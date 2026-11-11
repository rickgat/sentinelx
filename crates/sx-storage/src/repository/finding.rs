//! Postgres-backed [`FindingRepository`] adapter.

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use sqlx::types::Json;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::entity::Finding;
use crate::domain::error::DomainError;
use crate::domain::port::FindingRepository;
use crate::domain::value_object::{AssetId, EngagementId, FindingId, Page, PagedResult, TenantId};
use crate::error::StorageError;
use crate::pagination::SqlBounds;
use crate::tenant_context::TenantContext;

/// `PgFindingRepository` — `findings` table adapter (RLS).
#[derive(Debug, Clone)]
pub struct PgFindingRepository {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl PgFindingRepository {
    /// Construct from a pre-built pool.
    #[must_use]
    pub const fn new(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
        }
    }
}

fn row_to_finding(row: &sqlx::postgres::PgRow) -> Result<Finding, StorageError> {
    let id: Uuid = row.try_get("id").map_err(StorageError::from)?;
    let tenant_id: Uuid = row.try_get("tenant_id").map_err(StorageError::from)?;
    let engagement_id: Uuid = row.try_get("engagement_id").map_err(StorageError::from)?;
    let asset_id: Uuid = row.try_get("asset_id").map_err(StorageError::from)?;
    let rule_id: String = row.try_get("rule_id").map_err(StorageError::from)?;
    let severity: String = row.try_get("severity").map_err(StorageError::from)?;
    let status: String = row.try_get("status").map_err(StorageError::from)?;
    let title: String = row.try_get("title").map_err(StorageError::from)?;
    let description: String = row.try_get("description").map_err(StorageError::from)?;
    let evidence_refs: Json<JsonValue> =
        row.try_get("evidence_refs").map_err(StorageError::from)?;
    let detected_at: OffsetDateTime = row.try_get("detected_at").map_err(StorageError::from)?;
    let triaged_at: Option<OffsetDateTime> =
        row.try_get("triaged_at").map_err(StorageError::from)?;
    let resolved_at: Option<OffsetDateTime> =
        row.try_get("resolved_at").map_err(StorageError::from)?;
    Ok(Finding {
        id: FindingId::from_uuid(id),
        tenant_id: TenantId::from_uuid(tenant_id),
        engagement_id: EngagementId::from_uuid(engagement_id),
        asset_id: AssetId::from_uuid(asset_id),
        rule_id,
        severity,
        status,
        title,
        description,
        evidence_refs: evidence_refs.0,
        detected_at,
        triaged_at,
        resolved_at,
    })
}

#[async_trait]
impl FindingRepository for PgFindingRepository {
    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: FindingId,
    ) -> Result<Option<Finding>, DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        TenantContext::apply(&mut tx, tenant_id, self.stmt_timeout_ms).await?;

        let row = sqlx::query(
            "SELECT id, tenant_id, engagement_id, asset_id, rule_id, severity, status, \
                    title, description, evidence_refs, detected_at, triaged_at, resolved_at \
             FROM findings WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id.as_uuid())
        .bind(tenant_id.as_uuid())
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        match row {
            Some(r) => Ok(Some(row_to_finding(&r)?)),
            None => Ok(None),
        }
    }

    async fn save(&self, finding: &Finding) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        TenantContext::apply(&mut tx, finding.tenant_id, self.stmt_timeout_ms).await?;

        sqlx::query(
            "INSERT INTO findings (id, tenant_id, engagement_id, asset_id, rule_id, severity, \
                                    status, title, description, evidence_refs, detected_at, \
                                    triaged_at, resolved_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
             ON CONFLICT (id) DO UPDATE SET \
                rule_id = EXCLUDED.rule_id, \
                severity = EXCLUDED.severity, \
                status = EXCLUDED.status, \
                title = EXCLUDED.title, \
                description = EXCLUDED.description, \
                evidence_refs = EXCLUDED.evidence_refs, \
                triaged_at = EXCLUDED.triaged_at, \
                resolved_at = EXCLUDED.resolved_at",
        )
        .bind(finding.id.as_uuid())
        .bind(finding.tenant_id.as_uuid())
        .bind(finding.engagement_id.as_uuid())
        .bind(finding.asset_id.as_uuid())
        .bind(&finding.rule_id)
        .bind(&finding.severity)
        .bind(&finding.status)
        .bind(&finding.title)
        .bind(&finding.description)
        .bind(Json(&finding.evidence_refs))
        .bind(finding.detected_at)
        .bind(finding.triaged_at)
        .bind(finding.resolved_at)
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
    ) -> Result<PagedResult<Finding>, DomainError> {
        let bounds: SqlBounds = page.into();

        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        TenantContext::apply(&mut tx, tenant_id, self.stmt_timeout_ms).await?;

        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*)::BIGINT FROM findings WHERE tenant_id = $1 AND engagement_id = $2",
        )
        .bind(tenant_id.as_uuid())
        .bind(engagement_id.as_uuid())
        .fetch_one(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        let rows = sqlx::query(
            "SELECT id, tenant_id, engagement_id, asset_id, rule_id, severity, status, \
                    title, description, evidence_refs, detected_at, triaged_at, resolved_at \
             FROM findings WHERE tenant_id = $1 AND engagement_id = $2 \
             ORDER BY detected_at DESC, id LIMIT $3 OFFSET $4",
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
            items.push(row_to_finding(r)?);
        }

        let total_u: u64 = total.try_into().unwrap_or(0);
        Ok(PagedResult::new(items, total_u, page))
    }
}

fn map_sqlx(e: sqlx::Error) -> DomainError {
    StorageError::from(e).into()
}
