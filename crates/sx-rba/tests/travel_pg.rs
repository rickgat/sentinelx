//! Integration tests for [`sx_rba::signals::travel_pg::PgTravelStore`]
//! (LOW-005).
//!
//! These tests exercise the real `rba_last_sightings` table against a
//! live Postgres database. They are gated by `#[ignore]` so the default
//! `cargo test -p sx-rba` suite stays hermetic; run them with:
//!
//! ```text
//! TEST_DATABASE_URL=postgres://... \
//!   cargo test -p sx-rba --test travel_pg -- --ignored
//! ```
//!
//! ## What this asserts
//!
//! 1. **Cross-restart persistence** — write through one
//!    `PgTravelStore`, drop it, recreate from the same pool, and the
//!    sighting is still there. Mirrors what happens on a `sx-monolith`
//!    redeploy (the in-memory ledger lost every row on restart — the
//!    whole reason LOW-005 exists).
//! 2. **Upsert semantics** — a second `record` for the same
//!    `(tenant, user)` overwrites `(lat, lon, at)`; it does NOT
//!    duplicate the row (PK is `(tenant_id, user_id)`).
//! 3. **First-sighting outcome** — `last_sighting` returns `None` when
//!    no row exists, identical to the in-memory contract.
//! 4. **RLS isolation** — FORCE-RLS on `rba_last_sightings` keyed off
//!    `app_current_tenant()` hides tenant B's row from tenant A's GUC
//!    context.
//!
//! ## Pattern note
//!
//! Same shape as the LOW-004 sibling tests in
//! `tests/pg_device_ledger_integration.rs` (build a pool from
//! `TEST_DATABASE_URL`, seed `tenants` + `users` with the FORCE-RLS
//! discipline, run the assertions, then tear down via the
//! `ON DELETE CASCADE` on the tenant row). The handoff doc names
//! `sqlx::test` explicitly but the project's policy is hermetic
//! defaults — we honour that by gating these on `#[ignore]` exactly
//! like LOW-004.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use sx_rba::signals::impossible_travel::TravelStore;
use sx_rba::signals::travel_pg::PgTravelStore;
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
/// the `rba_last_sightings` row can FK-reference them. The
/// `ON DELETE CASCADE` on the tenant row tears every dependent row
/// down at the end of each test via [`teardown_fixture`].
///
/// `tenants` is intentionally NOT under RLS (see migration 02), so the
/// row goes in via a plain `INSERT`. `users` IS under FORCE-RLS, so the
/// insert is wrapped in a transaction that first sets
/// `app.current_tenant_id` via `set_config(...)` — same shim
/// `PgTravelStore` uses for `rba_last_sightings` itself.
async fn seed_fixture(pool: &PgPool) -> (Uuid, Uuid) {
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO tenants (id, name, slug, tier) \
         VALUES ($1, $2, $3, 'starter')",
    )
    .bind(tenant)
    .bind(format!("low-005-test-{tenant}"))
    .bind(format!("low005-{}", tenant.simple()))
    .execute(pool)
    .await
    .expect("seed tenant");

    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await
        .expect("set tenant ctx");
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, password_hash, display_name) \
         VALUES ($1, $2, $3, 'x', 'low-005 test user')",
    )
    .bind(user)
    .bind(tenant)
    .bind(format!("low005-{user}@test.local"))
    .execute(&mut *tx)
    .await
    .expect("seed user");
    tx.commit().await.expect("commit user");

    (tenant, user)
}

async fn teardown_fixture(pool: &PgPool, tenant: Uuid) {
    // Tenant CASCADE removes users + rba_last_sightings in one shot.
    let _ = sqlx::query("DELETE FROM tenants WHERE id = $1")
        .bind(tenant)
        .execute(pool)
        .await;
}

/// LOW-005 §1: write + read back round-trip through one store.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Requires live Postgres on TEST_DATABASE_URL with the project migrations applied"]
async fn record_and_read_back_round_trip() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let (tenant, user) = seed_fixture(&pool).await;
    let store = PgTravelStore::new(pool.clone());

    let at = OffsetDateTime::now_utc();
    {
        let store = store.clone();
        tokio::task::spawn_blocking(move || store.record(tenant, user, 51.5074, -0.1278, at))
            .await
            .expect("record");
    }

    let got = {
        let store = store.clone();
        tokio::task::spawn_blocking(move || store.last_sighting(tenant, user))
            .await
            .expect("lookup")
    }
    .expect("last_sighting must read back what we wrote");
    assert!((got.lat - 51.5074).abs() < 1e-9);
    assert!((got.lon - (-0.1278)).abs() < 1e-9);
    // Postgres rounds TIMESTAMPTZ to microseconds; allow that tiny delta.
    assert!((got.at - at).whole_seconds().abs() <= 1);

    teardown_fixture(&pool, tenant).await;
}

/// LOW-005 first-sighting outcome: `None`, identical to the in-memory contract.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Requires live Postgres on TEST_DATABASE_URL with the project migrations applied"]
async fn first_sighting_returns_none() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let (tenant, user) = seed_fixture(&pool).await;
    let store = PgTravelStore::new(pool.clone());

    let got = tokio::task::spawn_blocking(move || store.last_sighting(tenant, user))
        .await
        .expect("lookup");
    assert!(got.is_none());

    teardown_fixture(&pool, tenant).await;
}

/// LOW-005 §2: upsert semantics — second `record` overwrites, not
/// duplicates. The PK `(tenant_id, user_id)` would reject a duplicate
/// outright; we also assert the read-back picks up the new values.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Requires live Postgres on TEST_DATABASE_URL with the project migrations applied"]
async fn record_is_upsert() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let (tenant, user) = seed_fixture(&pool).await;
    let store = PgTravelStore::new(pool.clone());

    let t0 = OffsetDateTime::now_utc() - time::Duration::hours(1);
    {
        let store = store.clone();
        tokio::task::spawn_blocking(move || store.record(tenant, user, 37.0902, -95.7129, t0))
            .await
            .expect("record 1");
    }
    let t1 = OffsetDateTime::now_utc();
    {
        let store = store.clone();
        tokio::task::spawn_blocking(move || store.record(tenant, user, 48.8566, 2.3522, t1))
            .await
            .expect("record 2");
    }

    let last = {
        let store = store.clone();
        tokio::task::spawn_blocking(move || store.last_sighting(tenant, user))
            .await
            .expect("lookup")
    }
    .expect("upsert must have produced a row");
    assert!((last.lat - 48.8566).abs() < 1e-9);
    assert!((last.lon - 2.3522).abs() < 1e-9);
    assert!((last.at - t1).whole_seconds().abs() <= 1);

    teardown_fixture(&pool, tenant).await;
}

/// LOW-005 §1 (the headline acceptance criterion): write through one
/// `PgTravelStore`, drop it (analogous to `sx-monolith` restarting),
/// open a brand-new pool against the same DB and read back through a
/// fresh store. The read must observe the written sighting — that is
/// the property `MemTravelStore` loses on restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Requires live Postgres on TEST_DATABASE_URL with the project migrations applied"]
async fn cross_restart_persistence() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let (tenant, user) = seed_fixture(&pool).await;
    let written_at = OffsetDateTime::now_utc();

    // First "process" — write through store 1, drop it.
    {
        let store_before = PgTravelStore::new(pool.clone());
        let s = store_before.clone();
        tokio::task::spawn_blocking(move || s.record(tenant, user, 35.6762, 139.6503, written_at))
            .await
            .expect("record before restart");
        drop(store_before);
    }

    // Second "process" — open a brand-new pool against the same DB
    // and instantiate a fresh store. Postgres connection state is
    // gone; the row must remain.
    let Some(pool2) = maybe_pool().await else {
        return;
    };
    let store_after = PgTravelStore::new(pool2);
    let read_back = {
        let store = store_after.clone();
        tokio::task::spawn_blocking(move || store.last_sighting(tenant, user))
            .await
            .expect("lookup after restart")
    }
    .expect("post-restart read must still see the written sighting");

    assert!((read_back.lat - 35.6762).abs() < 1e-9);
    assert!((read_back.lon - 139.6503).abs() < 1e-9);
    assert!((read_back.at - written_at).whole_seconds().abs() <= 1);

    teardown_fixture(&pool, tenant).await;
}

/// FORCE-RLS on `rba_last_sightings` keyed off `app_current_tenant()`
/// must hide tenant B's row from tenant A's GUC context. Pins the
/// migration's row-level-security policy.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "Requires live Postgres on TEST_DATABASE_URL with the project migrations applied"]
async fn rls_isolates_per_tenant() {
    let Some(pool) = maybe_pool().await else {
        return;
    };
    let (tenant_a, user_a) = seed_fixture(&pool).await;
    let (tenant_b, user_b) = seed_fixture(&pool).await;

    let store = PgTravelStore::new(pool.clone());
    let now = OffsetDateTime::now_utc();
    {
        let s = store.clone();
        tokio::task::spawn_blocking(move || s.record(tenant_a, user_a, 12.34, 56.78, now))
            .await
            .expect("record A");
    }
    {
        let s = store.clone();
        tokio::task::spawn_blocking(move || s.record(tenant_b, user_b, 90.0, -90.0, now))
            .await
            .expect("record B");
    }

    // Cross-tenant probe: ask for tenant A's user_b row — must be
    // empty. The row exists under `tenant_id = tenant_b`, so RLS
    // hides it from tenant A's GUC context.
    let probe = {
        let s = store.clone();
        tokio::task::spawn_blocking(move || s.last_sighting(tenant_a, user_b))
            .await
            .expect("cross-tenant probe")
    };
    assert!(
        probe.is_none(),
        "RLS must hide tenant B's sighting from tenant A's GUC context"
    );

    // Sanity check: each tenant sees its own.
    let a = {
        let s = store.clone();
        tokio::task::spawn_blocking(move || s.last_sighting(tenant_a, user_a))
            .await
            .expect("lookup A")
    }
    .expect("A sees A");
    assert!((a.lat - 12.34).abs() < 1e-9);

    let b = {
        let s = store.clone();
        tokio::task::spawn_blocking(move || s.last_sighting(tenant_b, user_b))
            .await
            .expect("lookup B")
    }
    .expect("B sees B");
    assert!((b.lat - 90.0).abs() < 1e-9);

    teardown_fixture(&pool, tenant_a).await;
    teardown_fixture(&pool, tenant_b).await;
}
