//! Durable Postgres-backed [`TenantIocRepository`] (PRG-03).
//!
//! The TAXII feed orchestrator ([`sx_intel_feeds::FeedOrchestrator`])
//! persists ingested indicators and per-feed poll status through the narrow
//! [`TenantIocRepository`] trait. In zero-config dev the composition root
//! wires the in-crate [`sx_intel_feeds::InMemoryRepository`]; when
//! `database.enabled` is true it wires this adapter instead, so ingested
//! IOCs and feed health survive a monolith restart and are readable by the
//! `/v1/intel/check` hot path across restarts.
//!
//! The backing tables (`tenant_iocs`, `intel_feed_status`) already exist in
//! `crates/sx-storage/migrations/20270101001200__create_tenant_iocs.sql`;
//! this adapter supplies the production binding the migration's header note
//! anticipated.
//!
//! ## Tenant isolation
//!
//! Every statement runs inside a transaction that first calls
//! [`TenantContext::apply`], so Postgres RLS confines each query to the
//! calling tenant. The `tenant_id` filters in the SQL are defence in depth.

use async_trait::async_trait;
use sqlx::types::Json;
use sqlx::{PgPool, Row as _};
use sx_intel_feeds::{
    FeedError, FeedId, FeedStatus, StoredIndicator, TenantId, TenantIocRepository,
};
use sx_storage::prelude::TenantId as StorageTenantId;
use sx_storage::tenant_context::TenantContext;
use time::OffsetDateTime;
use uuid::Uuid;

/// Postgres-backed per-tenant IOC + feed-status repository.
pub(crate) struct PgTenantIocRepository {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl std::fmt::Debug for PgTenantIocRepository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgTenantIocRepository")
            .finish_non_exhaustive()
    }
}

impl PgTenantIocRepository {
    /// Build a repository over the shared pool.
    pub(crate) fn new(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
        }
    }

    /// Parse the orchestrator's textual tenant id into the storage uuid,
    /// mapping a malformed id to a repository error (never a panic).
    fn parse_tenant(tenant: &TenantId) -> Result<StorageTenantId, FeedError> {
        Uuid::parse_str(tenant.as_str().trim())
            .map(StorageTenantId::from_uuid)
            .map_err(|e| FeedError::Repo(format!("invalid tenant id '{}': {e}", tenant.as_str())))
    }
}

fn repo_err(e: impl std::fmt::Display) -> FeedError {
    FeedError::Repo(e.to_string())
}

/// Clamp a `u64` count into the `i64` Postgres bind domain.
fn to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Read a non-negative `BIGINT` back as a `u64` (defends against a stray
/// negative value from a manual edit rather than panicking).
fn from_i64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

#[async_trait]
impl TenantIocRepository for PgTenantIocRepository {
    async fn upsert_batch(
        &self,
        tenant: &TenantId,
        rows: &[StoredIndicator],
    ) -> Result<u64, FeedError> {
        if rows.is_empty() {
            return Ok(0);
        }
        let tid = Self::parse_tenant(tenant)?;
        let mut tx = self.pool.begin().await.map_err(repo_err)?;
        TenantContext::apply(&mut tx, tid, self.stmt_timeout_ms)
            .await
            .map_err(repo_err)?;

        let mut added: u64 = 0;
        for row in rows {
            // `xmax = 0` is true only for a freshly-inserted row; an updated
            // row carries a non-zero xmax. This mirrors the in-memory repo's
            // "count only new `(tenant, kind, value)` keys" semantics.
            let inserted: bool = sqlx::query(
                "INSERT INTO tenant_iocs \
                     (id, tenant_id, feed_id, kind, value, severity, score, \
                      valid_from, valid_until, labels, first_seen_at, last_seen_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
                 ON CONFLICT (tenant_id, kind, value) DO UPDATE SET \
                     severity     = EXCLUDED.severity, \
                     score        = EXCLUDED.score, \
                     labels       = EXCLUDED.labels, \
                     valid_until  = EXCLUDED.valid_until, \
                     last_seen_at = EXCLUDED.last_seen_at \
                 RETURNING (xmax = 0) AS inserted",
            )
            .bind(Uuid::now_v7())
            .bind(tid.as_uuid())
            .bind(row.feed_id.as_str())
            .bind(row.kind.as_db_str())
            .bind(&row.value)
            .bind(i16::from(row.severity))
            .bind(row.score)
            .bind(row.valid_from)
            .bind(row.valid_until)
            .bind(Json(&row.labels))
            .bind(row.first_seen_at)
            .bind(row.last_seen_at)
            .fetch_one(&mut *tx)
            .await
            .map_err(repo_err)?
            .try_get("inserted")
            .map_err(repo_err)?;
            if inserted {
                added += 1;
            }
        }
        tx.commit().await.map_err(repo_err)?;
        Ok(added)
    }

    async fn count_for_tenant(&self, tenant: &TenantId) -> Result<u64, FeedError> {
        let tid = Self::parse_tenant(tenant)?;
        let mut tx = self.pool.begin().await.map_err(repo_err)?;
        TenantContext::apply(&mut tx, tid, self.stmt_timeout_ms)
            .await
            .map_err(repo_err)?;
        let count: i64 = sqlx::query("SELECT count(*) AS n FROM tenant_iocs WHERE tenant_id = $1")
            .bind(tid.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .map_err(repo_err)?
            .try_get("n")
            .map_err(repo_err)?;
        tx.commit().await.map_err(repo_err)?;
        Ok(from_i64(count))
    }

    async fn evict_lru(&self, tenant: &TenantId, overflow: u64) -> Result<u64, FeedError> {
        if overflow == 0 {
            return Ok(0);
        }
        let tid = Self::parse_tenant(tenant)?;
        let mut tx = self.pool.begin().await.map_err(repo_err)?;
        TenantContext::apply(&mut tx, tid, self.stmt_timeout_ms)
            .await
            .map_err(repo_err)?;
        // Drop the lowest-scoring rows first — the denormalised `score`
        // column exists precisely so this prune never recomputes.
        let result = sqlx::query(
            "DELETE FROM tenant_iocs \
             WHERE id IN ( \
                 SELECT id FROM tenant_iocs \
                 WHERE tenant_id = $1 \
                 ORDER BY score ASC, last_seen_at ASC \
                 LIMIT $2 \
             )",
        )
        .bind(tid.as_uuid())
        .bind(to_i64(overflow))
        .execute(&mut *tx)
        .await
        .map_err(repo_err)?;
        tx.commit().await.map_err(repo_err)?;
        Ok(result.rows_affected())
    }

    async fn get_status(&self, tenant: &TenantId, feed: &FeedId) -> Result<FeedStatus, FeedError> {
        let tid = Self::parse_tenant(tenant)?;
        let mut tx = self.pool.begin().await.map_err(repo_err)?;
        TenantContext::apply(&mut tx, tid, self.stmt_timeout_ms)
            .await
            .map_err(repo_err)?;
        let row = sqlx::query(
            "SELECT last_poll_at, last_success_at, last_error, error_count_24h, \
                    indicators_total, indicators_added, indicators_evicted, cursor_added_after \
             FROM intel_feed_status WHERE tenant_id = $1 AND feed_id = $2",
        )
        .bind(tid.as_uuid())
        .bind(feed.as_str())
        .fetch_optional(&mut *tx)
        .await
        .map_err(repo_err)?;
        tx.commit().await.map_err(repo_err)?;

        let Some(row) = row else {
            return Ok(FeedStatus::default());
        };
        Ok(FeedStatus {
            last_poll_at: row
                .try_get::<Option<OffsetDateTime>, _>("last_poll_at")
                .map_err(repo_err)?,
            last_success_at: row
                .try_get::<Option<OffsetDateTime>, _>("last_success_at")
                .map_err(repo_err)?,
            last_error: row
                .try_get::<Option<String>, _>("last_error")
                .map_err(repo_err)?,
            error_count_24h: u32::try_from(
                row.try_get::<i32, _>("error_count_24h").map_err(repo_err)?,
            )
            .unwrap_or(0),
            indicators_total: from_i64(
                row.try_get::<i64, _>("indicators_total")
                    .map_err(repo_err)?,
            ),
            indicators_added: from_i64(
                row.try_get::<i64, _>("indicators_added")
                    .map_err(repo_err)?,
            ),
            indicators_evicted: from_i64(
                row.try_get::<i64, _>("indicators_evicted")
                    .map_err(repo_err)?,
            ),
            cursor_added_after: row
                .try_get::<Option<String>, _>("cursor_added_after")
                .map_err(repo_err)?,
        })
    }

    async fn put_status(
        &self,
        tenant: &TenantId,
        feed: &FeedId,
        status: &FeedStatus,
    ) -> Result<(), FeedError> {
        let tid = Self::parse_tenant(tenant)?;
        let mut tx = self.pool.begin().await.map_err(repo_err)?;
        TenantContext::apply(&mut tx, tid, self.stmt_timeout_ms)
            .await
            .map_err(repo_err)?;
        sqlx::query(
            "INSERT INTO intel_feed_status \
                 (tenant_id, feed_id, last_poll_at, last_success_at, last_error, \
                  error_count_24h, indicators_total, indicators_added, \
                  indicators_evicted, cursor_added_after, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now()) \
             ON CONFLICT (tenant_id, feed_id) DO UPDATE SET \
                 last_poll_at       = EXCLUDED.last_poll_at, \
                 last_success_at    = EXCLUDED.last_success_at, \
                 last_error         = EXCLUDED.last_error, \
                 error_count_24h    = EXCLUDED.error_count_24h, \
                 indicators_total   = EXCLUDED.indicators_total, \
                 indicators_added   = EXCLUDED.indicators_added, \
                 indicators_evicted = EXCLUDED.indicators_evicted, \
                 cursor_added_after = EXCLUDED.cursor_added_after, \
                 updated_at         = now()",
        )
        .bind(tid.as_uuid())
        .bind(feed.as_str())
        .bind(status.last_poll_at)
        .bind(status.last_success_at)
        .bind(status.last_error.as_deref())
        .bind(i32::try_from(status.error_count_24h).unwrap_or(i32::MAX))
        .bind(to_i64(status.indicators_total))
        .bind(to_i64(status.indicators_added))
        .bind(to_i64(status.indicators_evicted))
        .bind(status.cursor_added_after.as_deref())
        .execute(&mut *tx)
        .await
        .map_err(repo_err)?;
        tx.commit().await.map_err(repo_err)?;
        Ok(())
    }
}
