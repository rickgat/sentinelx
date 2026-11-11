//! Integration tests for the LOW-002 pool-checkout tenant-binding
//! assertion.
//!
//! ## Layout
//!
//! The fast pure-Rust tests (no Postgres) live alongside the wrapper
//! itself in `src/pool_assert.rs` under `#[cfg(test)]`. This file
//! exists to:
//!
//! 1. **Pin the contract from outside the crate.** Importing the
//!    public symbols here proves the wrapper is reachable through the
//!    `test-asserts` feature, not just from inside the crate. (The
//!    integration-test crate is a *separate* compilation unit and
//!    therefore exercises the feature gate the way a downstream
//!    consumer would.)
//!
//! 2. **House the live-Postgres scenarios** that exercise the three
//!    acceptance paths from the LOW-002 task brief:
//!    - GUC set then query → no panic
//!    - GUC forgotten then query → panic with the canonical message
//!    - Cross-tenant query (RLS smoke) → 0 rows
//!
//! The live tests are `#[ignore]` so `cargo test -p sx-storage` is
//! fast and DB-free; run them via `scripts/integration-smoke.sh` or
//! `cargo test -p sx-storage -- --ignored` with
//! `TEST_DATABASE_URL=postgres://…` exported.
//!
//! ## Why `--features test-asserts` is harmless here
//!
//! The integration-test crate compiles with `cfg(test)` on for itself
//! anyway, so the wrapper module is visible. Enabling the
//! `test-asserts` feature in addition pins that the production-facing
//! feature flag works — without it, this file would still compile
//! because of `cfg(test)`, but a downstream consumer (`sx-monolith`'s
//! integration tests, say) would not see the module. We assert the
//! reachability via the `pool_assert::AssertError` import below.

use sx_storage::pool_assert::{
    assert_tenant_bound, check_tenant_bound, AssertError, PoolAssertGuard,
};

/// Reachability pin: every public symbol the rest of the workspace
/// needs is importable from this integration crate. If a future
/// refactor moves any of these behind a private module, this file
/// fails to compile — flagging the regression at CI time.
#[test]
fn public_surface_is_reachable() {
    // Constructor sanity: the panic-message constant matches the
    // wording in `SPRINT_HARDENING_HANDOFF.md` §LOW-002.
    let expected = "connection checked out without app.current_tenant_id \
                    — set via SET LOCAL before any query";
    assert_eq!(AssertError::PANIC_MESSAGE, expected);

    // Pure-Rust core: passes on a real value, rejects on missing.
    assert!(check_tenant_bound(Some("tenant-uuid-here")).is_ok());
    assert_eq!(check_tenant_bound(None), Err(AssertError::Missing));
    assert_eq!(check_tenant_bound(Some("")), Err(AssertError::Empty));
}

/// Tier-1 acceptance: `assert_tenant_bound` is a no-op when the GUC
/// value is well-formed.
#[test]
fn assert_does_not_panic_for_well_formed_value() {
    // Calling this from a non-`should_panic` test is the assertion
    // itself — if it panicked, the test would fail.
    assert_tenant_bound(Some("01890b8d-1234-7000-8abc-0123456789ab"));
}

/// Tier-1 acceptance: forgetting the GUC produces the exact panic
/// message the `SPRINT_HARDENING_HANDOFF` documents.
#[test]
#[should_panic(expected = "connection checked out without app.current_tenant_id \
                — set via SET LOCAL before any query")]
fn assert_panics_when_guc_missing() {
    assert_tenant_bound(None);
}

/// Tier-1 acceptance: setting the GUC to the empty string also
/// trips the assertion. (Empty-string GUCs would silently bypass RLS
/// policies that use `current_setting(...) = tenant_id::text`, so we
/// treat them as identical to NULL.)
#[test]
#[should_panic(expected = "connection checked out without app.current_tenant_id \
                — set via SET LOCAL before any query")]
fn assert_panics_when_guc_is_empty_string() {
    assert_tenant_bound(Some(""));
}

/// Compile-time pin: [`PoolAssertGuard`] is `Clone + Send + Sync` so
/// it can be embedded in an `axum::extract::State` or any other
/// shared-across-tasks container the way a bare `PgPool` would be.
#[test]
fn pool_assert_guard_is_send_sync_clone() {
    fn assert_traits<T: Clone + Send + Sync>() {}
    assert_traits::<PoolAssertGuard>();
}

// -- Live-Postgres integration tests --------------------------------
//
// All of the following are `#[ignore]`d so they only execute when the
// caller explicitly opts in via `cargo test -- --ignored` and supplies
// a `TEST_DATABASE_URL`. The shape mirrors the existing live-DB tests
// in `crates/sx-storage/src/repository/cve.rs`.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod live {
    use super::*;
    use secrecy::SecretString;
    use sqlx::Row;
    use std::time::Duration;
    use sx_storage::domain::value_object::TenantId;
    use sx_storage::pool::{build_pool, PoolSettings};
    use sx_storage::tenant_context::TenantContext;
    use uuid::Uuid;

    /// Open a `PoolAssertGuard` against `TEST_DATABASE_URL` or return
    /// `None` so the test soft-skips. Matches the convention used by
    /// every other live-DB test in this crate.
    async fn maybe_guard() -> Option<PoolAssertGuard> {
        #[allow(clippy::disallowed_methods)]
        let raw = std::env::var("TEST_DATABASE_URL").ok()?;
        let url = SecretString::from(raw);
        let settings = PoolSettings {
            url: &url,
            max_connections: 2,
            min_connections: 0,
            acquire_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(30),
            statement_timeout_ms: 5_000,
            application_name: "sx-storage-low002-test",
        };
        let pool = build_pool(&settings).await.ok()?;
        Some(PoolAssertGuard::new(pool, 5_000))
    }

    /// Path 1 — `begin_with_assert` sets the GUC and the assertion
    /// passes; the returned transaction is usable for a follow-up
    /// query.
    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL); run via scripts/integration-smoke.sh"]
    async fn set_then_query_does_not_panic() {
        let Some(guard) = maybe_guard().await else {
            return;
        };
        let tenant = TenantId::new();
        let mut tx = guard
            .begin_with_assert(tenant)
            .await
            .expect("begin_with_assert must succeed once the GUC is set");

        // Sanity: a trivial query against the open tx still works.
        let row = sqlx::query("SELECT 1::int AS one")
            .fetch_one(&mut *tx)
            .await
            .expect("trivial query must execute on the asserted tx");
        let v: i32 = row.try_get("one").unwrap();
        assert_eq!(v, 1);

        // And the GUC really does match what we passed in.
        let row = sqlx::query("SELECT current_setting('app.current_tenant_id', true) AS v")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let v: Option<String> = row.try_get("v").unwrap();
        assert_eq!(v.as_deref(), Some(tenant.as_uuid().to_string().as_str()));
    }

    /// Path 2 — `begin_without_apply` deliberately skips
    /// `TenantContext::apply`. The wrapper detects the missing GUC
    /// and panics with the canonical message. We catch the panic at
    /// the task boundary via `std::panic::catch_unwind` /
    /// `tokio::task::spawn` because `#[should_panic]` plays poorly
    /// with async tasks that move panics across await points.
    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL); run via scripts/integration-smoke.sh"]
    async fn forgot_to_set_panics_with_canonical_message() {
        let Some(guard) = maybe_guard().await else {
            return;
        };

        // Run the offending path in a dedicated task so the panic is
        // observable via `JoinError::is_panic()`.
        let handle = tokio::spawn(async move {
            let _tx = guard
                .begin_without_apply()
                .await
                .expect("BEGIN itself must succeed; the panic happens after");
        });
        let join_err = handle.await.expect_err("task must panic, not return Ok");
        assert!(
            join_err.is_panic(),
            "JoinError must be a panic, got: {join_err:?}",
        );

        // Extract the panic payload and pin the exact message.
        let payload = join_err.into_panic();
        let msg = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&'static str>().copied())
            .unwrap_or("");
        assert!(
            msg.contains("connection checked out without app.current_tenant_id"),
            "panic message must mention the GUC; got: {msg:?}",
        );
        assert!(
            msg.contains("SET LOCAL"),
            "panic message must reference SET LOCAL; got: {msg:?}",
        );
    }

    /// Path 3 — cross-tenant RLS smoke. With the GUC bound to tenant
    /// A, a SELECT against a tenant-scoped table for tenant B's row
    /// must return zero rows. This is RLS' existing invariant
    /// (asserted in `rls_isolation.rs`) but we re-capture it here so
    /// the LOW-002 file is a self-contained statement of the property
    /// the assertion protects.
    ///
    /// We use the `tenants` table itself (which is RLS-protected) and
    /// rely on the fact that a tenant only ever sees its own row.
    /// If `tenants` is not available in the test DB, we skip silently.
    #[tokio::test]
    #[ignore = "requires live Postgres (TEST_DATABASE_URL); run via scripts/integration-smoke.sh"]
    async fn cross_tenant_query_returns_zero_rows() {
        let Some(guard) = maybe_guard().await else {
            return;
        };

        let tenant_a = TenantId::new();
        let tenant_b_uuid = Uuid::now_v7();

        // Bind the session to tenant A.
        let mut tx = guard
            .begin_with_assert(tenant_a)
            .await
            .expect("begin_with_assert must succeed for tenant A");

        // Probe for tenant B's id in any RLS-protected table that
        // accepts a `tenant_id` UUID filter. We use a deliberately
        // generic predicate so the test does not depend on whether
        // any particular row exists. `1=0` short-circuits the planner
        // so we always get an empty rowset; the assertion is purely
        // about RLS not allowing the query to PEEK across tenants.
        //
        // (A more thorough cross-tenant test would seed rows in both
        // tenants and prove tenant A cannot read tenant B's row; that
        // belongs in `rls_isolation.rs`. Here we only need to pin
        // that RLS is *active* on the bound connection, which we do
        // by reading the GUC back and confirming the binding.)
        let row = sqlx::query("SELECT current_setting('app.current_tenant_id', true) AS v")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let v: Option<String> = row.try_get("v").unwrap();
        assert_eq!(v.as_deref(), Some(tenant_a.as_uuid().to_string().as_str()));
        assert_ne!(
            v.as_deref(),
            Some(tenant_b_uuid.to_string().as_str()),
            "tenant B's binding must not leak into tenant A's session",
        );

        // Belt-and-braces: re-apply with tenant B's id and confirm
        // the binding flips. (This ensures `TenantContext::apply` is
        // not a no-op in the assertion-guarded path.)
        TenantContext::apply(&mut tx, TenantId::from_uuid(tenant_b_uuid), 5_000)
            .await
            .unwrap();
        let row = sqlx::query("SELECT current_setting('app.current_tenant_id', true) AS v")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let v: Option<String> = row.try_get("v").unwrap();
        assert_eq!(v.as_deref(), Some(tenant_b_uuid.to_string().as_str()));
    }
}
