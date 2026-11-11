//! Durable Postgres-backed [`EngagementRepository`] (engagement aggregate).
//!
//! The composition root previously bound the engagement authorization
//! aggregate to an in-memory repository, so every engagement — and thus the
//! active Rules-of-Engagement authorization the scan/pentest gate reads —
//! was lost on restart and invisible across instances. When
//! `database.enabled` this adapter persists the aggregate instead.
//!
//! The full `sx_engagement::model::Engagement` (status, scope, RoE window,
//! intensity ceiling, approvals) is stored losslessly as JSONB in
//! `engagement_aggregates`, keyed by `(tenant_id, engagement_id)`, with
//! scalar projections for listing. Every statement runs in a transaction
//! that applies [`TenantContext`] first, so Postgres RLS confines each query
//! to the calling tenant.

use async_trait::async_trait;
use sqlx::types::Json;
use sqlx::{PgPool, Row as _};
use sx_core::value_object::ids::{EngagementId, TenantId};
use sx_engagement::model::engagement::Engagement;
use sx_engagement::port::EngagementRepository;
use sx_engagement::EngagementError;
use sx_storage::prelude::TenantId as StorageTenantId;
use sx_storage::tenant_context::TenantContext;

/// Postgres-backed engagement aggregate repository.
pub(crate) struct PgEngagementRepository {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl std::fmt::Debug for PgEngagementRepository {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgEngagementRepository")
            .finish_non_exhaustive()
    }
}

impl PgEngagementRepository {
    pub(crate) fn new(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
        }
    }

    fn storage_tenant(tenant: TenantId) -> StorageTenantId {
        StorageTenantId::from_uuid(*tenant.as_uuid())
    }
}

fn repo_err(e: impl std::fmt::Display) -> EngagementError {
    EngagementError::Repository(e.to_string())
}

#[async_trait]
impl EngagementRepository for PgEngagementRepository {
    async fn create(&self, engagement: &Engagement) -> Result<(), EngagementError> {
        let tid = Self::storage_tenant(engagement.tenant_id);
        let mut tx = self.pool.begin().await.map_err(repo_err)?;
        TenantContext::apply(&mut tx, tid, self.stmt_timeout_ms)
            .await
            .map_err(repo_err)?;
        sqlx::query(
            "INSERT INTO engagement_aggregates \
                 (tenant_id, engagement_id, name, status, aggregate, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, now(), now())",
        )
        .bind(*engagement.tenant_id.as_uuid())
        .bind(*engagement.id.as_uuid())
        .bind(&engagement.name)
        .bind(engagement.status.to_string())
        .bind(Json(engagement))
        .execute(&mut *tx)
        .await
        .map_err(repo_err)?;
        tx.commit().await.map_err(repo_err)?;
        Ok(())
    }

    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: EngagementId,
    ) -> Result<Option<Engagement>, EngagementError> {
        let tid = Self::storage_tenant(tenant_id);
        let mut tx = self.pool.begin().await.map_err(repo_err)?;
        TenantContext::apply(&mut tx, tid, self.stmt_timeout_ms)
            .await
            .map_err(repo_err)?;
        let row = sqlx::query(
            "SELECT aggregate FROM engagement_aggregates \
             WHERE tenant_id = $1 AND engagement_id = $2",
        )
        .bind(*tenant_id.as_uuid())
        .bind(*id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(repo_err)?;
        tx.commit().await.map_err(repo_err)?;
        row.map(|r| {
            r.try_get::<Json<Engagement>, _>("aggregate")
                .map(|j| j.0)
                .map_err(repo_err)
        })
        .transpose()
    }

    async fn list(
        &self,
        tenant_id: TenantId,
        offset: u64,
        limit: u32,
    ) -> Result<Vec<Engagement>, EngagementError> {
        let tid = Self::storage_tenant(tenant_id);
        let mut tx = self.pool.begin().await.map_err(repo_err)?;
        TenantContext::apply(&mut tx, tid, self.stmt_timeout_ms)
            .await
            .map_err(repo_err)?;
        let rows = sqlx::query(
            "SELECT aggregate FROM engagement_aggregates \
             WHERE tenant_id = $1 \
             ORDER BY created_at DESC \
             LIMIT $2 OFFSET $3",
        )
        .bind(*tenant_id.as_uuid())
        .bind(i64::from(limit))
        .bind(i64::try_from(offset).unwrap_or(i64::MAX))
        .fetch_all(&mut *tx)
        .await
        .map_err(repo_err)?;
        tx.commit().await.map_err(repo_err)?;
        rows.into_iter()
            .map(|r| {
                r.try_get::<Json<Engagement>, _>("aggregate")
                    .map(|j| j.0)
                    .map_err(repo_err)
            })
            .collect()
    }

    async fn update(&self, engagement: &Engagement) -> Result<(), EngagementError> {
        let tid = Self::storage_tenant(engagement.tenant_id);
        let mut tx = self.pool.begin().await.map_err(repo_err)?;
        TenantContext::apply(&mut tx, tid, self.stmt_timeout_ms)
            .await
            .map_err(repo_err)?;
        // Upsert so a transition (activate/pause/…) persists whether or not
        // the row already exists; `created_at` is preserved on update.
        sqlx::query(
            "INSERT INTO engagement_aggregates \
                 (tenant_id, engagement_id, name, status, aggregate, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, now(), now()) \
             ON CONFLICT (tenant_id, engagement_id) DO UPDATE SET \
                 name       = EXCLUDED.name, \
                 status     = EXCLUDED.status, \
                 aggregate  = EXCLUDED.aggregate, \
                 updated_at = now()",
        )
        .bind(*engagement.tenant_id.as_uuid())
        .bind(*engagement.id.as_uuid())
        .bind(&engagement.name)
        .bind(engagement.status.to_string())
        .bind(Json(engagement))
        .execute(&mut *tx)
        .await
        .map_err(repo_err)?;
        tx.commit().await.map_err(repo_err)?;
        Ok(())
    }
}
