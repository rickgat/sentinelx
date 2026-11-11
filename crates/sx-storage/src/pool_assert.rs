//! Test-only assertion that every checked-out Postgres connection has
//! `app.current_tenant_id` bound via `SET LOCAL` before any user query.
//!
//! ## Why
//!
//! The RLS layer (`migrations/20260101000010_enable_rls.sql`) keys every
//! tenant-scoped policy on the GUC `app.current_tenant_id`. If a future
//! code path forgets to call [`crate::tenant_context::TenantContext::apply`]
//! at the start of a transaction, that path will silently leak across
//! tenants — Postgres' RLS would simply see `NULL` as the binding and
//! either allow nothing (if the policy compares with `=`) or, worse,
//! allow everything (if some future policy uses `COALESCE` defensively).
//!
//! This module adds a defensive invariant **for tests only**: a thin
//! wrapper around [`sqlx::PgPool`] that re-checks the GUC at the start
//! of every transaction it hands out, and panics if the binding is
//! missing or empty.
//!
//! ## Production posture
//!
//! Production code never sees this module. The `test-asserts` cargo
//! feature gates the entire file, and the feature is off by default.
//! Crates that want the assertion in their integration tests can add
//! `sx-storage = { workspace = true, features = ["test-asserts"] }` to
//! their `[dev-dependencies]`. Tests inside `sx-storage` get the
//! assertion via `#[cfg(test)]`.
//!
//! ## What is asserted
//!
//! - The GUC value retrieved via
//!   `SELECT current_setting('app.current_tenant_id', true)` is `Some`
//!   and non-empty.
//! - That is exactly the invariant RLS depends on. Validating it at
//!   transaction-start time (right after
//!   [`crate::tenant_context::TenantContext::apply`]) is a defence
//!   against future regressions inside `TenantContext::apply` itself.
//!
//! ## What is NOT asserted
//!
//! - This module does **not** validate that the GUC value matches the
//!   expected tenant id. The RLS policies enforce that at query time
//!   via the SQL predicates themselves; duplicating it here would
//!   require the wrapper to track the caller's intended tenant, which
//!   is not its job.

#![cfg(any(test, feature = "test-asserts"))]
// This module is compiled only for tests (or downstream consumers
// that opt in via the `test-asserts` feature). Workspace clippy denies
// `panic!` in production code, but the entire point of this module is
// to panic when a connection is checked out without the tenant GUC
// bound — so we explicitly allow it for this file only.
#![allow(clippy::panic)]

use std::fmt;

use sqlx::{PgPool, Postgres, Row, Transaction};

use crate::domain::value_object::TenantId;
use crate::error::StorageError;
use crate::tenant_context::TenantContext;

/// Reason the tenant-binding assertion can fail.
///
/// Returned from [`check_tenant_bound`] and embedded in the panic
/// message emitted by [`PoolAssertGuard::begin_with_assert`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssertError {
    /// `current_setting('app.current_tenant_id', true)` returned SQL
    /// NULL — the GUC has never been set in this transaction.
    Missing,
    /// `current_setting('app.current_tenant_id', true)` returned the
    /// empty string — the GUC was set to `''`, which RLS treats as
    /// "no tenant".
    Empty,
}

impl AssertError {
    /// Canonical panic message — used by [`PoolAssertGuard`] and
    /// reproduced verbatim in [`assert_tenant_bound`]. Kept as an
    /// associated constant so tests can pin the exact wording.
    pub const PANIC_MESSAGE: &'static str = "connection checked out without app.current_tenant_id \
         — set via SET LOCAL before any query";
}

impl fmt::Display for AssertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => f.write_str("app.current_tenant_id is unset (NULL)"),
            Self::Empty => f.write_str("app.current_tenant_id is empty ('')"),
        }
    }
}

impl std::error::Error for AssertError {}

/// Pure-Rust core of the assertion. Takes the value retrieved from
/// `current_setting('app.current_tenant_id', true)` and returns
/// `Ok(())` iff the value satisfies the invariant.
///
/// Separated from the SQL-touching path so it can be unit-tested
/// exhaustively without a live database.
///
/// # Errors
///
/// - [`AssertError::Missing`] if `value` is `None` (SQL NULL).
/// - [`AssertError::Empty`] if `value` is `Some("")`.
pub fn check_tenant_bound(value: Option<&str>) -> Result<(), AssertError> {
    // We intentionally use `Some("")` (string-literal match) rather
    // than a guard (`Some(v) if v.is_empty()`) — clippy flags the
    // guard form as `redundant_guards`. `const fn` would be cleaner
    // still, but `match` on `&str` is not yet allowed in const
    // contexts.
    match value {
        None => Err(AssertError::Missing),
        Some("") => Err(AssertError::Empty),
        Some(_) => Ok(()),
    }
}

/// Convenience wrapper around [`check_tenant_bound`] that panics with
/// [`AssertError::PANIC_MESSAGE`] when the binding is missing or empty.
///
/// Used by [`PoolAssertGuard::begin_with_assert`] after applying the
/// tenant context. Exposed so call sites that obtain a transaction by
/// some other route (e.g. nested helpers) can still re-check.
///
/// # Panics
///
/// If `value` is `None` or `Some("")`. The panic message is exactly
/// [`AssertError::PANIC_MESSAGE`].
pub fn assert_tenant_bound(value: Option<&str>) {
    assert!(
        check_tenant_bound(value).is_ok(),
        "{}",
        AssertError::PANIC_MESSAGE,
    );
}

/// Read the current value of `app.current_tenant_id` from an open
/// transaction. Returns `None` when the GUC is unset (SQL NULL).
///
/// Uses the two-argument form `current_setting(name, missing_ok=true)`
/// so an unset GUC returns NULL rather than raising
/// `undefined_object` (SQLSTATE 42704).
///
/// # Errors
///
/// Returns [`StorageError::Query`] if the `SELECT` itself fails (e.g.
/// the transaction has been aborted).
pub async fn read_tenant_guc(
    tx: &mut Transaction<'_, Postgres>,
) -> Result<Option<String>, StorageError> {
    let row = sqlx::query("SELECT current_setting('app.current_tenant_id', true) AS v")
        .fetch_one(&mut **tx)
        .await
        .map_err(StorageError::from)?;
    // `current_setting(name, true)` returns NULL when the parameter is
    // unset; sqlx surfaces that as `Option<String>` when we ask for it
    // explicitly.
    let v: Option<String> = row.try_get("v").map_err(StorageError::from)?;
    Ok(v)
}

/// Test-only `PgPool` wrapper that guarantees every transaction it
/// hands out has `app.current_tenant_id` set before the caller can run
/// any SQL.
///
/// The wrapper is `Clone` and holds an `Arc` internally (via the
/// underlying `PgPool`), so it can be freely shared across tasks just
/// like a bare pool.
#[derive(Debug, Clone)]
pub struct PoolAssertGuard {
    pool: PgPool,
    statement_timeout_ms: u64,
}

impl PoolAssertGuard {
    /// Wrap an existing pool. The `statement_timeout_ms` is forwarded
    /// to [`TenantContext::apply`] on every checkout, matching the
    /// production code path.
    #[must_use]
    pub const fn new(pool: PgPool, statement_timeout_ms: u64) -> Self {
        Self {
            pool,
            statement_timeout_ms,
        }
    }

    /// Borrow the underlying pool. Useful for tests that need to
    /// bypass the guard for setup statements (e.g. truncating tables
    /// before each case).
    #[must_use]
    pub const fn inner(&self) -> &PgPool {
        &self.pool
    }

    /// Open a transaction, apply [`TenantContext`] for `tenant_id`,
    /// re-read the GUC, and panic if it is unset or empty. Returns
    /// the open transaction on success.
    ///
    /// This is the recommended entry point for guarded tests: it
    /// guarantees the assertion always fires *after*
    /// `TenantContext::apply`, so a future bug inside `apply` that
    /// silently no-ops (e.g. someone replaces the SQL with a comment)
    /// is caught at the call site.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] propagated from `BEGIN`, from
    /// `TenantContext::apply`, or from reading the GUC. Note that a
    /// missing GUC is reported as a **panic**, not an error — the
    /// assertion is a test-time bug detector, not a recoverable
    /// fault.
    ///
    /// # Panics
    ///
    /// With message [`AssertError::PANIC_MESSAGE`] if, after applying
    /// the tenant context, `current_setting('app.current_tenant_id',
    /// true)` returns NULL or the empty string.
    pub async fn begin_with_assert(
        &self,
        tenant_id: TenantId,
    ) -> Result<Transaction<'_, Postgres>, StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;
        TenantContext::apply(&mut tx, tenant_id, self.statement_timeout_ms).await?;
        let v = read_tenant_guc(&mut tx).await?;
        assert_tenant_bound(v.as_deref());
        Ok(tx)
    }

    /// Open a transaction **without** applying the tenant context, but
    /// still re-check the GUC. This is the path that proves the
    /// assertion catches the "forgot to set the GUC" bug: a test that
    /// uses this method and then issues any query will panic before
    /// the query runs.
    ///
    /// Returning the opened transaction is intentional — the panic
    /// happens inside this function, so callers in the panic path
    /// never observe it. The successful return is unreachable in
    /// practice because a freshly-opened tx with no `SET` calls will
    /// always have NULL GUCs.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] propagated from `BEGIN` or from reading
    /// the GUC.
    ///
    /// # Panics
    ///
    /// With message [`AssertError::PANIC_MESSAGE`] whenever the GUC
    /// is unbound — which, for a freshly-opened transaction with no
    /// `SET LOCAL` calls, is always.
    pub async fn begin_without_apply(&self) -> Result<Transaction<'_, Postgres>, StorageError> {
        let mut tx = self.pool.begin().await.map_err(StorageError::from)?;
        let v = read_tenant_guc(&mut tx).await?;
        assert_tenant_bound(v.as_deref());
        Ok(tx)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    //! Pure-Rust unit tests of the core assertion logic. These run on
    //! every `cargo test -p sx-storage` invocation; no database is
    //! required. The live-DB integration tests live in
    //! `tests/rls_pool_assert.rs`.
    use super::*;

    #[test]
    fn check_passes_for_a_real_value() {
        assert!(check_tenant_bound(Some("abc123")).is_ok());
    }

    #[test]
    fn check_passes_for_a_uuid_shaped_value() {
        // The production payload is a UUID v7 string; pin that this
        // shape is accepted (no length/format gating beyond "non-
        // empty").
        let uuid = "01890b8d-1234-7000-8abc-0123456789ab";
        assert!(check_tenant_bound(Some(uuid)).is_ok());
    }

    #[test]
    fn check_rejects_none_as_missing() {
        assert_eq!(check_tenant_bound(None), Err(AssertError::Missing));
    }

    #[test]
    fn check_rejects_empty_string_as_empty() {
        assert_eq!(check_tenant_bound(Some("")), Err(AssertError::Empty));
    }

    #[test]
    fn assert_passes_for_a_real_value() {
        // Should NOT panic.
        assert_tenant_bound(Some("ok"));
    }

    #[test]
    #[should_panic(expected = "connection checked out without app.current_tenant_id \
                    — set via SET LOCAL before any query")]
    fn assert_panics_on_none_with_canonical_message() {
        assert_tenant_bound(None);
    }

    #[test]
    #[should_panic(expected = "connection checked out without app.current_tenant_id \
                    — set via SET LOCAL before any query")]
    fn assert_panics_on_empty_with_canonical_message() {
        assert_tenant_bound(Some(""));
    }

    #[test]
    fn assert_error_display_for_missing() {
        let s = AssertError::Missing.to_string();
        assert!(s.contains("unset"), "Display should mention 'unset': {s}");
    }

    #[test]
    fn assert_error_display_for_empty() {
        let s = AssertError::Empty.to_string();
        assert!(s.contains("empty"), "Display should mention 'empty': {s}");
    }

    #[test]
    fn panic_message_constant_is_stable() {
        // Pin the exact wording. Other crates' tests (and the docs in
        // SPRINT_HARDENING_HANDOFF.md §LOW-002) reference this string.
        assert_eq!(
            AssertError::PANIC_MESSAGE,
            "connection checked out without app.current_tenant_id \
             — set via SET LOCAL before any query",
        );
    }
}
