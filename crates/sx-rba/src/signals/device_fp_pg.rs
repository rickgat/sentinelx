//! Postgres-backed [`DeviceFingerprintStore`] (LOW-004).
//!
//! The HIGH-001 device-fingerprint ledger originally shipped as an
//! in-memory `DashMap` ([`crate::signals::device_fp::MemDeviceFingerprintLedger`]).
//! Every restart of `sx-monolith` dropped the entire enrolled-device
//! corpus → every subsequent login from a known device scored as
//! `Unknown`, dragging composite risk scores upward and stepping users
//! up to MFA spuriously for hours/days post-deploy.
//!
//! [`PgDeviceFingerprintLedger`] backs the same surface
//! ([`DeviceFingerprintStore`]) with the `rba_known_devices` table
//! (migration `20270615000000__create_rba_known_devices.sql`), so the
//! ledger survives restarts and rolls forward across pods.
//!
//! ## Revoke-survival invariant
//!
//! `record` MUST NOT clear the revoked flag. The upsert is
//!
//! ```sql
//! INSERT INTO rba_known_devices (tenant_id, user_id, fp_hash, first_seen, last_seen)
//! VALUES ($1, $2, $3, $4, $4)
//! ON CONFLICT (tenant_id, user_id, fp_hash) DO UPDATE
//!     SET last_seen = GREATEST(rba_known_devices.last_seen, EXCLUDED.last_seen)
//!     WHERE rba_known_devices.revoked_at IS NULL
//! ```
//!
//! The trailing `WHERE rba_known_devices.revoked_at IS NULL` is the
//! linchpin: a row that was revoked stays revoked even if the same
//! fingerprint is replayed by an attacker who recovered the laptop.
//! `GREATEST` defends against NTP-skewed / queue-reordered replays
//! dragging `last_seen` backwards.
//!
//! ## Tenant-context (RLS)
//!
//! Every public method opens its own transaction, applies the
//! `app.current_tenant_id` GUC via `set_config(..., true)`, then runs
//! the actual SQL. The `rba_known_devices` table has
//! `FORCE ROW LEVEL SECURITY` per migration, so any forgotten `SET LOCAL`
//! would yield zero rows on read + zero rows affected on write. We
//! never query without the GUC set.
//!
//! ## Sync trait, async I/O bridge
//!
//! [`DeviceFingerprintStore`] is intentionally synchronous so it can be
//! called from the sync hot path inside [`crate::service::RbaService::evaluate`]
//! without rippling `async fn` through the whole engine. The Postgres
//! implementor bridges via `tokio::task::block_in_place(|| Handle::current().block_on(...))`,
//! which requires a multi-threaded tokio runtime — the `sx-monolith`
//! main `#[tokio::main]` is multi-threaded by default. Tests must use
//! `#[tokio::test(flavor = "multi_thread")]` if they exercise this impl
//! from a sync context.

use std::sync::Arc;

use sqlx::PgPool;
use time::OffsetDateTime;
use tokio::runtime::Handle;
use uuid::Uuid;

use super::device_fp::{
    DeviceFingerprintRow, DeviceFingerprintSignal, DeviceFingerprintStatus, DeviceFingerprintStore,
};

/// Postgres-backed implementor of [`DeviceFingerprintStore`].
///
/// Cheap to clone (`Arc<PgPool>` internally). The pool itself is
/// expected to be the shared `sx-storage` pool — no new connections are
/// established per call.
#[derive(Clone)]
pub struct PgDeviceFingerprintLedger {
    inner: Arc<Inner>,
}

struct Inner {
    pool: PgPool,
    /// Bound used in `SET LOCAL statement_timeout = N`. Mirrors the
    /// `sx-storage` repositories' default — short enough to avoid
    /// queue starvation, long enough for the index-only path on a
    /// large `rba_known_devices`.
    statement_timeout_ms: u64,
}

impl std::fmt::Debug for PgDeviceFingerprintLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgDeviceFingerprintLedger")
            .field("statement_timeout_ms", &self.inner.statement_timeout_ms)
            .finish_non_exhaustive()
    }
}

impl PgDeviceFingerprintLedger {
    /// Default statement timeout — 5 s is generous for an index lookup
    /// on `(tenant_id, user_id, fp_hash)` PK and bounded enough that a
    /// runaway lock waiter cannot starve the engine.
    pub const DEFAULT_STATEMENT_TIMEOUT_MS: u64 = 5_000;

    /// Build a Postgres-backed ledger wrapping a shared [`PgPool`].
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self::with_statement_timeout(pool, Self::DEFAULT_STATEMENT_TIMEOUT_MS)
    }

    /// Same as [`Self::new`] but lets callers override the per-query
    /// statement timeout (in milliseconds).
    #[must_use]
    pub fn with_statement_timeout(pool: PgPool, statement_timeout_ms: u64) -> Self {
        Self {
            inner: Arc::new(Inner {
                pool,
                statement_timeout_ms,
            }),
        }
    }

    /// Borrow the underlying pool — used by integration tests to drive
    /// the ledger across simulated reconnects (LOW-004 acceptance test).
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.inner.pool
    }

    /// Apply the `app.current_tenant_id` + `statement_timeout` GUCs to
    /// the open transaction. Mirrors `sx-storage::tenant_context::TenantContext`
    /// without taking a hard dependency on the storage crate (sx-rba
    /// currently sits below sx-storage in the dep graph).
    async fn apply_tenant_context(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant_id: Uuid,
        statement_timeout_ms: u64,
    ) -> sqlx::Result<()> {
        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(tenant_id.to_string())
            .execute(&mut **tx)
            .await?;
        let bounded = statement_timeout_ms.min(u64::from(u32::MAX));
        let stmt = format!("SET LOCAL statement_timeout = {bounded}");
        sqlx::query(&stmt).execute(&mut **tx).await?;
        Ok(())
    }

    async fn record_async(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        fp_hash: &str,
        at: OffsetDateTime,
    ) -> sqlx::Result<()> {
        let mut tx = self.inner.pool.begin().await?;
        Self::apply_tenant_context(&mut tx, tenant_id, self.inner.statement_timeout_ms).await?;
        // Revoke-survival invariant: the `WHERE rba_known_devices.revoked_at IS NULL`
        // predicate on the ON CONFLICT branch means a revoked row will
        // NOT have last_seen rolled forward. The row itself remains
        // revoked. Honest replay from a recovered laptop cannot silently
        // re-arm the device.
        sqlx::query(
            "INSERT INTO rba_known_devices (tenant_id, user_id, fp_hash, first_seen, last_seen) \
             VALUES ($1, $2, $3, $4, $4) \
             ON CONFLICT (tenant_id, user_id, fp_hash) DO UPDATE \
                 SET last_seen = GREATEST(rba_known_devices.last_seen, EXCLUDED.last_seen) \
                 WHERE rba_known_devices.revoked_at IS NULL",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(fp_hash)
        .bind(at)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn lookup_async(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        fp_hash: &str,
    ) -> sqlx::Result<Option<(OffsetDateTime, Option<OffsetDateTime>)>> {
        let mut tx = self.inner.pool.begin().await?;
        Self::apply_tenant_context(&mut tx, tenant_id, self.inner.statement_timeout_ms).await?;
        let row: Option<(OffsetDateTime, Option<OffsetDateTime>)> = sqlx::query_as(
            "SELECT last_seen, revoked_at \
             FROM rba_known_devices \
             WHERE tenant_id = $1 AND user_id = $2 AND fp_hash = $3",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(fp_hash)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row)
    }

    async fn revoke_async(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        fp_hash: &str,
    ) -> sqlx::Result<()> {
        let mut tx = self.inner.pool.begin().await?;
        Self::apply_tenant_context(&mut tx, tenant_id, self.inner.statement_timeout_ms).await?;
        // Idempotent: revoking an already-revoked row leaves `revoked_at`
        // at the original revocation timestamp. Revoking a never-seen
        // fingerprint inserts a row whose `last_seen` is pinned to the
        // revocation moment (the CHECK on `first_seen <= last_seen`
        // requires both to be present, and we want the inventory view
        // to surface a sensible "last_seen" rather than the UNIX epoch).
        let now = OffsetDateTime::now_utc();
        sqlx::query(
            "INSERT INTO rba_known_devices \
                 (tenant_id, user_id, fp_hash, first_seen, last_seen, revoked_at, revoke_reason) \
             VALUES ($1, $2, $3, $4, $4, $4, 'operator') \
             ON CONFLICT (tenant_id, user_id, fp_hash) DO UPDATE \
                 SET revoked_at    = COALESCE(rba_known_devices.revoked_at, EXCLUDED.revoked_at), \
                     revoke_reason = COALESCE(rba_known_devices.revoke_reason, EXCLUDED.revoke_reason)",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(fp_hash)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn list_async(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> sqlx::Result<Vec<DeviceFingerprintRow>> {
        let mut tx = self.inner.pool.begin().await?;
        Self::apply_tenant_context(&mut tx, tenant_id, self.inner.statement_timeout_ms).await?;
        let rows: Vec<(String, OffsetDateTime, Option<OffsetDateTime>)> = sqlx::query_as(
            "SELECT fp_hash, last_seen, revoked_at \
             FROM rba_known_devices \
             WHERE tenant_id = $1 AND user_id = $2 \
             ORDER BY last_seen DESC",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows
            .into_iter()
            .map(|(fp_hash, last_seen, revoked_at)| DeviceFingerprintRow {
                fp_hash,
                last_seen_at: last_seen,
                status: if revoked_at.is_some() {
                    DeviceFingerprintStatus::Revoked
                } else {
                    DeviceFingerprintStatus::Known
                },
            })
            .collect())
    }
}

/// Bridge from the sync trait surface into the async sqlx calls.
///
/// Requires the caller's tokio runtime to be multi-threaded so
/// `block_in_place` can park the current worker without deadlocking the
/// scheduler. `#[tokio::main]` is multi-threaded by default; tests
/// driving the trait sync must opt in with
/// `#[tokio::test(flavor = "multi_thread")]`.
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    match Handle::try_current() {
        // Inside a tokio runtime → use block_in_place + block_on.
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(fut)),
        // No tokio runtime — the trait method was called from a pure
        // sync context with no ambient runtime. The production callers
        // never hit this branch (`#[tokio::main]` is multi-threaded);
        // it exists only so a non-tokio test driver doesn't immediately
        // null-deref. We allow `expect_used` on the runtime-build path
        // because the alternative (silently swallowing every ledger
        // operation) is strictly worse for an in-band attack-path
        // signal — a missing record would silently misclassify a
        // logged-in device as `Unknown`.
        #[allow(clippy::expect_used)]
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build single-thread tokio runtime for sync sqlx bridge")
            .block_on(fut),
    }
}

impl DeviceFingerprintStore for PgDeviceFingerprintLedger {
    fn record(&self, tenant_id: Uuid, user_id: Uuid, fp_hash: &str, at: OffsetDateTime) {
        if let Err(err) = block_on(self.record_async(tenant_id, user_id, fp_hash, at)) {
            tracing::error!(
                target: "sx_rba.device_fp.pg",
                tenant_id = %tenant_id,
                user_id   = %user_id,
                error     = %err,
                "pg device-fingerprint record failed (fail-open: the engine still scores the login but the ledger row was NOT written)",
            );
        }
    }

    fn lookup(&self, tenant_id: Uuid, user_id: Uuid, fp_hash: &str) -> DeviceFingerprintSignal {
        match block_on(self.lookup_async(tenant_id, user_id, fp_hash)) {
            Ok(Some((last_seen, revoked_at))) => DeviceFingerprintSignal {
                fp_hash: fp_hash.to_owned(),
                last_seen_at: Some(last_seen),
                status: if revoked_at.is_some() {
                    DeviceFingerprintStatus::Revoked
                } else {
                    DeviceFingerprintStatus::Known
                },
            },
            Ok(None) => DeviceFingerprintSignal::unknown(fp_hash),
            Err(err) => {
                tracing::error!(
                    target: "sx_rba.device_fp.pg",
                    tenant_id = %tenant_id,
                    user_id   = %user_id,
                    error     = %err,
                    "pg device-fingerprint lookup failed (fail-closed: returning Unknown so the engine scores conservatively)",
                );
                DeviceFingerprintSignal::unknown(fp_hash)
            }
        }
    }

    fn revoke(&self, tenant_id: Uuid, user_id: Uuid, fp_hash: &str) {
        if let Err(err) = block_on(self.revoke_async(tenant_id, user_id, fp_hash)) {
            tracing::error!(
                target: "sx_rba.device_fp.pg",
                tenant_id = %tenant_id,
                user_id   = %user_id,
                error     = %err,
                "pg device-fingerprint revoke failed",
            );
        }
    }

    fn list_for_user(&self, tenant_id: Uuid, user_id: Uuid) -> Vec<DeviceFingerprintRow> {
        match block_on(self.list_async(tenant_id, user_id)) {
            Ok(rows) => rows,
            Err(err) => {
                tracing::error!(
                    target: "sx_rba.device_fp.pg",
                    tenant_id = %tenant_id,
                    user_id   = %user_id,
                    error     = %err,
                    "pg device-fingerprint list_for_user failed (returning empty list)",
                );
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    //! Compile-time sanity checks. The behavioural integration tests
    //! that exercise the live Postgres path live in
    //! `tests/pg_device_ledger_integration.rs` and are gated by the
    //! `sqlx::test` macro (auto-skips when no `DATABASE_URL` is set).

    use super::*;

    // Object-safety check: a `dyn DeviceFingerprintStore` must work so
    // the composition root can hold either implementor behind an
    // `Arc<dyn ...>`.
    #[allow(dead_code)]
    fn assert_object_safe(_: &dyn DeviceFingerprintStore) {}

    fn ledger_is_send_sync<T: Send + Sync + 'static>() {}

    #[test]
    fn pg_ledger_is_send_sync() {
        ledger_is_send_sync::<PgDeviceFingerprintLedger>();
    }
}
