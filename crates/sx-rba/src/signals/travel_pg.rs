//! Postgres-backed [`TravelStore`] implementation (LOW-005).
//!
//! [`PgTravelStore`] persists the impossible-travel last-sighting ledger
//! in the `rba_last_sightings` table created by migration
//! `20271117000000__create_rba_last_sightings.sql`. The table carries
//! exactly one row per `(tenant_id, user_id)` pair and is guarded by
//! `FORCE ROW LEVEL SECURITY` keyed off the `app_current_tenant()`
//! GUC. The Pg impl applies that GUC inside a short transaction before
//! every read/write — mirroring the pattern used by `PgDekStore` in
//! `sx-secrets`.
//!
//! ## Sync surface over async I/O
//!
//! The [`TravelStore`] trait is intentionally synchronous: the RBA
//! engine's `evaluate()` hot path is sync and is called from the IAM
//! login flow without an `await`. The Pg impl bridges to async sqlx by
//! borrowing the *current* Tokio runtime handle via
//! `tokio::runtime::Handle::current()` + `block_in_place`. Production
//! `sx-monolith` always runs on the multi-threaded runtime — the only
//! place where `block_in_place` is sound. Calling `PgTravelStore` from
//! a current-thread runtime is a programming error and is documented
//! on each method.
//!
//! ## Errors
//!
//! The trait surface returns `()` from `record` and `Option<...>` from
//! `last_sighting`. Database errors at this layer are non-fatal — a
//! transient outage of the rba_last_sightings table must not lock
//! every user out of authentication. We therefore log + drop errors at
//! this layer and the surrounding service falls through to the
//! conservative "no opinion" outcome (sub-score 0). The behaviour
//! matches `MemTravelStore` on a first-sighting cache miss.

use std::time::Duration;

use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use tokio::runtime::Handle;
use uuid::Uuid;

use crate::signals::impossible_travel::{LastSighting, TravelStore};

/// Default `statement_timeout` (ms) for `rba_last_sightings`
/// transactions when callers do not override at construction time.
pub const DEFAULT_STMT_TIMEOUT_MS: u64 = 2_000;

/// Postgres-backed [`TravelStore`].
///
/// Wraps a [`PgPool`] handle and a per-statement timeout. Cheap to
/// clone — the underlying pool is reference-counted.
#[derive(Debug, Clone)]
pub struct PgTravelStore {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl PgTravelStore {
    /// Construct from a pre-built pool using the default statement
    /// timeout. No I/O is performed.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self {
            pool,
            stmt_timeout_ms: DEFAULT_STMT_TIMEOUT_MS,
        }
    }

    /// Construct with an explicit statement timeout (ms).
    #[must_use]
    pub const fn with_statement_timeout(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
        }
    }

    /// Borrow the underlying pool. Exposed for tests and for callers
    /// that want to share the connection budget with other adapters.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Apply the tenant-scoped GUC and statement timeout to an open
    /// transaction. Must be the first statement of every transaction
    /// so the FORCE-RLS policy on `rba_last_sightings` admits us.
    async fn apply_tenant_context(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        tenant_id: Uuid,
        stmt_timeout_ms: u64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT set_config('app.current_tenant_id', $1, true)")
            .bind(tenant_id.to_string())
            .execute(&mut **tx)
            .await?;

        // `SET LOCAL statement_timeout` does not accept `$1`; it
        // requires a literal. We bound to `u32::MAX` to rule out
        // overflow and bind the value as a plain integer (the type
        // is `u64`, so there is no injection vector).
        let bounded = stmt_timeout_ms.min(u64::from(u32::MAX));
        let stmt = format!("SET LOCAL statement_timeout = {bounded}");
        sqlx::query(&stmt).execute(&mut **tx).await?;

        Ok(())
    }

    async fn record_async(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        lat: f64,
        lon: f64,
        at: OffsetDateTime,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        Self::apply_tenant_context(&mut tx, tenant_id, self.stmt_timeout_ms).await?;

        sqlx::query(
            "INSERT INTO rba_last_sightings (tenant_id, user_id, lat, lon, at) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (tenant_id, user_id) DO UPDATE SET \
                lat = EXCLUDED.lat, \
                lon = EXCLUDED.lon, \
                at  = EXCLUDED.at",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(lat)
        .bind(lon)
        .bind(at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn last_sighting_async(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<LastSighting>, sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        Self::apply_tenant_context(&mut tx, tenant_id, self.stmt_timeout_ms).await?;

        let row = sqlx::query(
            "SELECT lat, lon, at FROM rba_last_sightings \
             WHERE tenant_id = $1 AND user_id = $2",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;

        tx.commit().await?;

        let Some(row) = row else { return Ok(None) };
        let lat: f64 = row.try_get("lat")?;
        let lon: f64 = row.try_get("lon")?;
        let at: OffsetDateTime = row.try_get("at")?;
        Ok(Some(LastSighting { lat, lon, at }))
    }
}

/// Pick the multi-thread Tokio handle to drive a sync→async bridge.
/// Returns `None` when no runtime is in scope or the runtime is the
/// current-thread flavor (which cannot host `block_in_place`).
fn pick_multi_thread_handle(op: &'static str) -> Option<Handle> {
    let Ok(handle) = Handle::try_current() else {
        tracing::warn!(
            target: "sx_rba.travel_pg",
            op,
            "no tokio runtime in scope; falling back to in-memory behaviour"
        );
        return None;
    };
    if handle.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
        tracing::warn!(
            target: "sx_rba.travel_pg",
            op,
            "current-thread tokio runtime is unsupported (block_in_place requires multi-thread); falling back to in-memory behaviour"
        );
        return None;
    }
    Some(handle)
}

/// Bridge an async future onto a sync call site by reusing the current
/// Tokio runtime. Returns `None` (treated as "no opinion") when the
/// future fails, no current runtime is in scope, or the runtime is the
/// current-thread flavor. Never panics on the caller — authentication
/// degrades gracefully on any wiring mistake instead of failing closed.
fn block_on_async<F, T>(fut: F, op: &'static str) -> Option<T>
where
    F: std::future::Future<Output = Result<T, sqlx::Error>>,
{
    let handle = pick_multi_thread_handle(op)?;
    match tokio::task::block_in_place(|| handle.block_on(fut)) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(
                target: "sx_rba.travel_pg",
                op,
                error = %e,
                "rba_last_sightings query failed; falling back to in-memory behaviour"
            );
            None
        }
    }
}

impl TravelStore for PgTravelStore {
    /// Record a sighting via INSERT … ON CONFLICT … DO UPDATE.
    ///
    /// **Runtime requirement:** must be called from inside a
    /// multi-threaded Tokio runtime. Outside one, the call is logged
    /// and dropped so authentication does not fail closed on a
    /// wiring mistake.
    fn record(&self, tenant_id: Uuid, user_id: Uuid, lat: f64, lon: f64, at: OffsetDateTime) {
        let _ = block_on_async(
            self.record_async(tenant_id, user_id, lat, lon, at),
            "record",
        );
    }

    /// Look up the last sighting for `(tenant, user)`.
    ///
    /// **Runtime requirement:** must be called from inside a
    /// multi-threaded Tokio runtime. Outside one, the call returns
    /// `None` (matches the `MemTravelStore` first-sighting outcome).
    fn last_sighting(&self, tenant_id: Uuid, user_id: Uuid) -> Option<LastSighting> {
        block_on_async(
            self.last_sighting_async(tenant_id, user_id),
            "last_sighting",
        )
        .flatten()
    }
}

/// Build a [`PgTravelStore`] suitable for installing in the
/// composition root. Holds a reference to the shared `PgPool`.
#[must_use]
pub const fn build(pool: PgPool) -> PgTravelStore {
    PgTravelStore::new(pool)
}

/// Build a [`PgTravelStore`] with a custom statement timeout.
#[must_use]
pub const fn build_with_timeout(pool: PgPool, stmt_timeout_ms: u64) -> PgTravelStore {
    PgTravelStore::with_statement_timeout(pool, stmt_timeout_ms)
}

/// Convenience for `acquire_timeout` defaults wired by the composition
/// root — the value mirrors the other Pg-backed adapters in the
/// monolith.
pub const DEFAULT_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(2);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn block_on_async_returns_none_outside_runtime() {
        // No Tokio runtime is in scope here — we must NOT panic; we
        // must return `None` so authentication degrades gracefully.
        let out = block_on_async::<_, i32>(async { Ok(42) }, "test");
        assert!(out.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn block_on_async_returns_none_on_current_thread_runtime() {
        // current_thread runtime cannot host `block_in_place`. The
        // helper must detect this and return None rather than panic.
        let out = block_on_async::<_, i32>(async { Ok(42) }, "test");
        assert!(out.is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn block_on_async_runs_on_multi_thread_runtime() {
        let out = block_on_async::<_, i32>(async { Ok(7) }, "test");
        assert_eq!(out, Some(7));
    }
}
