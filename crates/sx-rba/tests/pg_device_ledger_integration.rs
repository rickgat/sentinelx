//! Postgres-backed `DeviceFingerprintLedger` integration tests
//! (LOW-004).
//!
//! These exercise the [`PgDeviceFingerprintLedger`] against a live
//! Postgres instance with the `rba_known_devices` migration applied.
//! They are gated by `#[ignore]` so the default `cargo test -p sx-rba`
//! suite stays hermetic; run them with:
//!
//! ```text
//! TEST_DATABASE_URL=postgres://... \
//!   cargo test -p sx-rba --test pg_device_ledger_integration -- --ignored
//! ```
//!
//! ## What this asserts
//!
//! 1. **Cross-restart persistence** — write through one
//!    `PgDeviceFingerprintLedger`, drop it, recreate from the same pool,
//!    and the row is still there. Mirrors what happens on a
//!    `sx-monolith` redeploy (the in-memory ledger lost every row on
//!    restart — the whole reason LOW-004 exists).
//! 2. **Revoke-survival invariant** — after `revoke`, a subsequent
//!    `record` MUST NOT clear the revoked flag. A recovered stolen
//!    laptop must not silently re-arm itself by hitting the login page.
//!    The `WHERE rba_known_devices.revoked_at IS NULL` predicate on the
//!    upsert is the linchpin; this test pins it.
//! 3. **Across-reconnect survival of revoke** — the revoke status
//!    survives a full pool disconnect + reconnect (modelled by
//!    constructing a fresh pool against the same URL).
//! 4. **Inventory listing** — `list_for_user` surfaces every enrolled
//!    fingerprint (revoked rows included) for `(tenant, user)`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use sx_rba::signals::device_fp::{DeviceFingerprintStatus, DeviceFingerprintStore};
use sx_rba::signals::device_fp_pg::PgDeviceFingerprintLedger;
use time::OffsetDateTime;
use uuid::Uuid;

/// Connect to `TEST_DATABASE_URL`. Returns `None` when the env var is
/// unset so the runner logs a skip instead of panicking. Same shape
/// every other live-DB test in the project uses.
async fn maybe_pool() -> Option<PgPool> {
    #[allow(clippy::disallowed_methods)] // live-DB test-only env lookup
    let raw = std::env::var("TEST_DATABASE_URL").ok()?;
    PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(2))
        .connect(&raw)
        .await
        .ok()
}

/// Pin a tenant + user fixture into the database. Returns the IDs so
/// the device-ledger row can FK-reference them. Cleans up at the end
/// of every test via [`teardown_fixture`].
async fn seed_fixture(pool: &PgPool) -> (Uuid, Uuid) {
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    // `tenants` is the root of multi-tenancy and is intentionally not
    // under RLS — see migration 02. We can insert directly.
    sqlx::query(
        "INSERT INTO tenants (id, name, slug, tier) \
         VALUES ($1, $2, $3, 'starter')",
    )
    .bind(tenant)
    .bind(format!("low-004-test-{tenant}"))
    .bind(format!("low004-{}", tenant.simple()))
    .execute(pool)
    .await
    .expect("seed tenant");

    // `users` IS under RLS — set the tenant context first.
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await
        .expect("set tenant ctx");
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, password_hash, display_name) \
         VALUES ($1, $2, $3, 'x', 'low-004 test user')",
    )
    .bind(user)
    .bind(tenant)
    .bind(format!("low004-{user}@test.local"))
    .execute(&mut *tx)
    .await
    .expect("seed user");
    tx.commit().await.expect("commit user");

    (tenant, user)
}

async fn teardown_fixture(pool: &PgPool, tenant: Uuid) {
    // Tenant CASCADE removes users + rba_known_devices in one shot.
    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant)
        .execute(pool)
        .await;
}

fn unique_fp() -> String {
    // 64-char hex satisfies the `length(fp_hash) BETWEEN 16 AND 128`
    // CHECK on the table.
    let raw = Uuid::new_v4().to_string().replace('-', "");
    format!("{raw}{raw}").chars().take(64).collect()
}

/// LOW-004 §1: writes survive a "restart" (new pool / new ledger
/// instance against the same database).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Requires live Postgres on TEST_DATABASE_URL with the project migrations applied"]
async fn record_survives_restart() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let (tenant, user) = seed_fixture(&pool).await;
    let fp = unique_fp();
    let at = OffsetDateTime::now_utc();

    // First "process" — write through ledger 1.
    let l1 = PgDeviceFingerprintLedger::new(pool.clone());
    {
        let l = l1.clone();
        let fp = fp.clone();
        tokio::task::spawn_blocking(move || l.record(tenant, user, &fp, at))
            .await
            .expect("record");
    }
    // Drop the original ledger handle — simulates `sx-monolith`
    // shutdown.
    drop(l1);

    // Second "process" — open a brand-new pool against the same DB
    // and instantiate a fresh ledger. Postgres connection state is
    // gone; the database row must remain.
    let Some(pool2) = maybe_pool().await else {
        return;
    };
    let l2 = PgDeviceFingerprintLedger::new(pool2);
    let signal = {
        let l = l2.clone();
        let fp = fp.clone();
        tokio::task::spawn_blocking(move || l.lookup(tenant, user, &fp))
            .await
            .expect("lookup")
    };
    assert_eq!(
        signal.status,
        DeviceFingerprintStatus::Known,
        "device must remain known after restart",
    );
    assert!(signal.last_seen_at.is_some());

    teardown_fixture(&pool, tenant).await;
}

/// LOW-004 §2 (the critical invariant): `record` AFTER `revoke` MUST
/// NOT clear the revoked flag. Pins the `WHERE rba_known_devices.revoked_at
/// IS NULL` predicate on the upsert.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Requires live Postgres on TEST_DATABASE_URL with the project migrations applied"]
async fn record_after_revoke_does_not_re_arm() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let (tenant, user) = seed_fixture(&pool).await;
    let fp = unique_fp();
    let at = OffsetDateTime::now_utc();
    let l = PgDeviceFingerprintLedger::new(pool.clone());

    // Enrol, then revoke.
    let l_c = l.clone();
    let fp_c = fp.clone();
    tokio::task::spawn_blocking(move || l_c.record(tenant, user, &fp_c, at))
        .await
        .expect("record");
    let l_c = l.clone();
    let fp_c = fp.clone();
    tokio::task::spawn_blocking(move || l_c.revoke(tenant, user, &fp_c))
        .await
        .expect("revoke");
    let l_c = l.clone();
    let fp_c = fp.clone();
    let revoked_signal = tokio::task::spawn_blocking(move || l_c.lookup(tenant, user, &fp_c))
        .await
        .expect("lookup-revoked");
    assert_eq!(revoked_signal.status, DeviceFingerprintStatus::Revoked);

    // Replay record — the attacker scenario.
    let l_c = l.clone();
    let fp_c = fp.clone();
    let later = at + time::Duration::hours(1);
    tokio::task::spawn_blocking(move || l_c.record(tenant, user, &fp_c, later))
        .await
        .expect("record-after-revoke");

    let l_c = l.clone();
    let fp_c = fp.clone();
    let after = tokio::task::spawn_blocking(move || l_c.lookup(tenant, user, &fp_c))
        .await
        .expect("lookup-after-replay");
    assert_eq!(
        after.status,
        DeviceFingerprintStatus::Revoked,
        "record() after revoke MUST NOT silently re-arm the device",
    );

    teardown_fixture(&pool, tenant).await;
}

/// LOW-004 §3: revoke survives a full reconnect (new pool against the
/// same database) — equivalent to a `sx-monolith` restart with revoked
/// devices still in the table.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Requires live Postgres on TEST_DATABASE_URL with the project migrations applied"]
async fn revoke_survives_reconnect() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let (tenant, user) = seed_fixture(&pool).await;
    let fp = unique_fp();
    let at = OffsetDateTime::now_utc();
    let l1 = PgDeviceFingerprintLedger::new(pool.clone());

    {
        let l = l1.clone();
        let fp = fp.clone();
        tokio::task::spawn_blocking(move || l.record(tenant, user, &fp, at))
            .await
            .expect("record");
    }
    {
        let l = l1.clone();
        let fp = fp.clone();
        tokio::task::spawn_blocking(move || l.revoke(tenant, user, &fp))
            .await
            .expect("revoke");
    }
    drop(l1);

    let Some(pool2) = maybe_pool().await else {
        return;
    };
    let l2 = PgDeviceFingerprintLedger::new(pool2);
    let signal = {
        let l = l2.clone();
        let fp = fp.clone();
        tokio::task::spawn_blocking(move || l.lookup(tenant, user, &fp))
            .await
            .expect("lookup")
    };
    assert_eq!(
        signal.status,
        DeviceFingerprintStatus::Revoked,
        "revoke must survive reconnect",
    );

    teardown_fixture(&pool, tenant).await;
}

/// LOW-004 §4 + inventory: `list_for_user` surfaces every enrolled
/// fingerprint (revoked rows included) for `(tenant, user)`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Requires live Postgres on TEST_DATABASE_URL with the project migrations applied"]
async fn list_for_user_includes_revoked_rows() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let (tenant, user) = seed_fixture(&pool).await;
    let l = PgDeviceFingerprintLedger::new(pool.clone());
    let fp_a = unique_fp();
    let fp_b = unique_fp();
    let at = OffsetDateTime::now_utc();

    for fp in [&fp_a, &fp_b] {
        let l_c = l.clone();
        let fp_c = fp.clone();
        tokio::task::spawn_blocking(move || l_c.record(tenant, user, &fp_c, at))
            .await
            .expect("record");
    }
    let l_c = l.clone();
    let fp_c = fp_b.clone();
    tokio::task::spawn_blocking(move || l_c.revoke(tenant, user, &fp_c))
        .await
        .expect("revoke");

    let l_c = l.clone();
    let rows = tokio::task::spawn_blocking(move || l_c.list_for_user(tenant, user))
        .await
        .expect("list");
    assert_eq!(rows.len(), 2);
    let revoked = rows
        .iter()
        .find(|r| r.fp_hash == fp_b)
        .expect("revoked row present");
    assert_eq!(revoked.status, DeviceFingerprintStatus::Revoked);

    teardown_fixture(&pool, tenant).await;
}
