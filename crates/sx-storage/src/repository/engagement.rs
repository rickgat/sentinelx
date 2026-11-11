//! Postgres-backed [`EngagementRepository`] adapter.

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use sqlx::types::Json;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::entity::Engagement;
use crate::domain::error::DomainError;
use crate::domain::port::EngagementRepository;
use crate::domain::value_object::{EngagementId, Page, PagedResult, TenantId};
use crate::error::StorageError;
use crate::pagination::SqlBounds;
use crate::tenant_context::TenantContext;

/// `PgEngagementRepository` — `engagements` table adapter (RLS).
#[derive(Debug, Clone)]
pub struct PgEngagementRepository {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl PgEngagementRepository {
    /// Construct from a pre-built pool.
    #[must_use]
    pub const fn new(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
        }
    }
}

fn row_to_engagement(row: &sqlx::postgres::PgRow) -> Result<Engagement, StorageError> {
    let id: Uuid = row.try_get("id").map_err(StorageError::from)?;
    let tenant_id: Uuid = row.try_get("tenant_id").map_err(StorageError::from)?;
    let name: String = row.try_get("name").map_err(StorageError::from)?;
    let scope: Json<JsonValue> = row.try_get("scope").map_err(StorageError::from)?;
    let window_start: OffsetDateTime = row.try_get("window_start").map_err(StorageError::from)?;
    let window_end: OffsetDateTime = row.try_get("window_end").map_err(StorageError::from)?;
    let status: String = row.try_get("status").map_err(StorageError::from)?;
    let requires_dual_approval: bool = row
        .try_get("requires_dual_approval")
        .map_err(StorageError::from)?;
    let intensity: String = row.try_get("intensity").map_err(StorageError::from)?;
    let created_at: OffsetDateTime = row.try_get("created_at").map_err(StorageError::from)?;
    let updated_at: OffsetDateTime = row.try_get("updated_at").map_err(StorageError::from)?;
    Ok(Engagement {
        id: EngagementId::from_uuid(id),
        tenant_id: TenantId::from_uuid(tenant_id),
        name,
        scope: scope.0,
        window_start,
        window_end,
        status,
        requires_dual_approval,
        intensity,
        created_at,
        updated_at,
    })
}

#[async_trait]
impl EngagementRepository for PgEngagementRepository {
    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: EngagementId,
    ) -> Result<Option<Engagement>, DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        TenantContext::apply(&mut tx, tenant_id, self.stmt_timeout_ms).await?;

        let row = sqlx::query(
            "SELECT id, tenant_id, name, scope, window_start, window_end, status, \
                    requires_dual_approval, intensity, created_at, updated_at \
             FROM engagements WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id.as_uuid())
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        match row {
            Some(r) => Ok(Some(row_to_engagement(&r)?)),
            None => Ok(None),
        }
    }

    async fn save(&self, engagement: &Engagement) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        TenantContext::apply(&mut tx, engagement.tenant_id, self.stmt_timeout_ms).await?;

        sqlx::query(
            "INSERT INTO engagements (id, tenant_id, name, scope, window_start, window_end, \
                                       status, requires_dual_approval, intensity, \
                                       created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             ON CONFLICT (id) DO UPDATE SET \
                name = EXCLUDED.name, \
                scope = EXCLUDED.scope, \
                window_start = EXCLUDED.window_start, \
                window_end = EXCLUDED.window_end, \
                status = EXCLUDED.status, \
                requires_dual_approval = EXCLUDED.requires_dual_approval, \
                intensity = EXCLUDED.intensity, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind(engagement.id.as_uuid())
        .bind(engagement.tenant_id.as_uuid())
        .bind(&engagement.name)
        .bind(Json(&engagement.scope))
        .bind(engagement.window_start)
        .bind(engagement.window_end)
        .bind(&engagement.status)
        .bind(engagement.requires_dual_approval)
        .bind(&engagement.intensity)
        .bind(engagement.created_at)
        .bind(engagement.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;
        Ok(())
    }

    async fn list(
        &self,
        tenant_id: TenantId,
        page: Page,
    ) -> Result<PagedResult<Engagement>, DomainError> {
        let bounds: SqlBounds = page.into();

        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        TenantContext::apply(&mut tx, tenant_id, self.stmt_timeout_ms).await?;

        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*)::BIGINT FROM engagements WHERE tenant_id = $1")
                .bind(tenant_id.as_uuid())
                .fetch_one(&mut *tx)
                .await
                .map_err(StorageError::from)?;

        let rows = sqlx::query(
            "SELECT id, tenant_id, name, scope, window_start, window_end, status, \
                    requires_dual_approval, intensity, created_at, updated_at \
             FROM engagements WHERE tenant_id = $1 \
             ORDER BY created_at, id LIMIT $2 OFFSET $3",
        )
        .bind(tenant_id.as_uuid())
        .bind(bounds.limit)
        .bind(bounds.offset)
        .fetch_all(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        let mut items = Vec::with_capacity(rows.len());
        for r in &rows {
            items.push(row_to_engagement(r)?);
        }

        let total_u: u64 = total.try_into().unwrap_or(0);
        Ok(PagedResult::new(items, total_u, page))
    }
}

fn map_sqlx(e: sqlx::Error) -> DomainError {
    StorageError::from(e).into()
}
