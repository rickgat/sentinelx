//! Postgres-backed [`AssetRepository`] adapter.

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use sqlx::types::Json;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::entity::Asset;
use crate::domain::error::DomainError;
use crate::domain::port::AssetRepository;
use crate::domain::value_object::{AssetId, EngagementId, Page, PagedResult, TenantId};
use crate::error::StorageError;
use crate::pagination::SqlBounds;
use crate::tenant_context::TenantContext;

/// `PgAssetRepository` — `assets` table adapter (RLS).
#[derive(Debug, Clone)]
pub struct PgAssetRepository {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl PgAssetRepository {
    /// Construct from a pre-built pool.
    #[must_use]
    pub const fn new(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
        }
    }
}

fn row_to_asset(row: &sqlx::postgres::PgRow) -> Result<Asset, StorageError> {
    let id: Uuid = row.try_get("id").map_err(StorageError::from)?;
    let tenant_id: Uuid = row.try_get("tenant_id").map_err(StorageError::from)?;
    let engagement_id: Uuid = row.try_get("engagement_id").map_err(StorageError::from)?;
    let kind: String = row.try_get("kind").map_err(StorageError::from)?;
    let fingerprint: String = row.try_get("fingerprint").map_err(StorageError::from)?;
    let exposure: String = row.try_get("exposure").map_err(StorageError::from)?;
    let criticality: String = row.try_get("criticality").map_err(StorageError::from)?;
    let tags: Json<JsonValue> = row.try_get("tags").map_err(StorageError::from)?;
    let created_at: OffsetDateTime = row.try_get("created_at").map_err(StorageError::from)?;
    let updated_at: OffsetDateTime = row.try_get("updated_at").map_err(StorageError::from)?;
    Ok(Asset {
        id: AssetId::from_uuid(id),
        tenant_id: TenantId::from_uuid(tenant_id),
        engagement_id: EngagementId::from_uuid(engagement_id),
        kind,
        fingerprint,
        exposure,
        criticality,
        tags: tags.0,
        created_at,
        updated_at,
    })
}

#[async_trait]
impl AssetRepository for PgAssetRepository {
    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: AssetId,
    ) -> Result<Option<Asset>, DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        TenantContext::apply(&mut tx, tenant_id, self.stmt_timeout_ms).await?;

        let row = sqlx::query(
            "SELECT id, tenant_id, engagement_id, kind, fingerprint, exposure, \
                    criticality, tags, created_at, updated_at \
             FROM assets WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id.as_uuid())
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        match row {
            Some(r) => Ok(Some(row_to_asset(&r)?)),
            None => Ok(None),
        }
    }

    async fn find_by_fingerprint(
        &self,
        tenant_id: TenantId,
        fingerprint: &str,
    ) -> Result<Option<Asset>, DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        TenantContext::apply(&mut tx, tenant_id, self.stmt_timeout_ms).await?;

        let row = sqlx::query(
            "SELECT id, tenant_id, engagement_id, kind, fingerprint, exposure, \
                    criticality, tags, created_at, updated_at \
             FROM assets WHERE fingerprint = $1 AND tenant_id = $2",
        )
        .bind(fingerprint)
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        match row {
            Some(r) => Ok(Some(row_to_asset(&r)?)),
            None => Ok(None),
        }
    }

    async fn save(&self, asset: &Asset) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        TenantContext::apply(&mut tx, asset.tenant_id, self.stmt_timeout_ms).await?;

        sqlx::query(
            "INSERT INTO assets (id, tenant_id, engagement_id, kind, fingerprint, \
                                 exposure, criticality, tags, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (id) DO UPDATE SET \
                kind = EXCLUDED.kind, \
                fingerprint = EXCLUDED.fingerprint, \
                exposure = EXCLUDED.exposure, \
                criticality = EXCLUDED.criticality, \
                tags = EXCLUDED.tags, \
                updated_at = EXCLUDED.updated_at",
        )
        .bind(asset.id.as_uuid())
        .bind(asset.tenant_id.as_uuid())
        .bind(asset.engagement_id.as_uuid())
        .bind(&asset.kind)
        .bind(&asset.fingerprint)
        .bind(&asset.exposure)
        .bind(&asset.criticality)
        .bind(Json(&asset.tags))
        .bind(asset.created_at)
        .bind(asset.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;
        Ok(())
    }

    async fn list_by_engagement(
        &self,
        tenant_id: TenantId,
        engagement_id: EngagementId,
        page: Page,
    ) -> Result<PagedResult<Asset>, DomainError> {
        let bounds: SqlBounds = page.into();

        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        TenantContext::apply(&mut tx, tenant_id, self.stmt_timeout_ms).await?;

        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::BIGINT FROM assets WHERE tenant_id = $1 AND engagement_id = $2",
        )
        .bind(tenant_id.as_uuid())
        .bind(engagement_id.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        let rows = sqlx::query(
            "SELECT id, tenant_id, engagement_id, kind, fingerprint, exposure, \
                    criticality, tags, created_at, updated_at \
             FROM assets WHERE tenant_id = $1 AND engagement_id = $2 \
             ORDER BY created_at, id LIMIT $3 OFFSET $4",
        )
        .bind(tenant_id.as_uuid())
        .bind(engagement_id.as_uuid())
        .bind(bounds.limit)
        .bind(bounds.offset)
        .fetch_all(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        let mut items = Vec::with_capacity(rows.len());
        for r in &rows {
            items.push(row_to_asset(r)?);
        }

        let total_u: u64 = total.try_into().unwrap_or(0);
        Ok(PagedResult::new(items, total_u, page))
    }
}

fn map_sqlx(e: sqlx::Error) -> DomainError {
    StorageError::from(e).into()
}
