//! Postgres-backed BAS approval repository.
//!
//! `bas_approvals` rows back the two-person rule enforced at the HTTP
//! boundary by `sx-api`. The repository is intentionally minimal: it
//! exposes `record`, `list_by_engagement`, and `count_distinct_approvers`
//! and nothing else. Tenant isolation is enforced via Row-Level Security
//! (see the migration), so every operation begins by setting
//! `app.current_tenant_id` on the transaction context.
//!
//! Idempotency on the `(engagement_id, technique_id, approver_email)`
//! tuple is enforced at the database level via a `UNIQUE` constraint and
//! mapped onto [`DomainError::Conflict`] by the standard
//! [`StorageError::Conflict`] translation.

use async_trait::async_trait;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::error::DomainError;
use crate::domain::value_object::{EngagementId, TenantId};
use crate::error::StorageError;
use crate::tenant_context::TenantContext;

/// Row persisted in `bas_approvals`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRow {
    /// Surrogate primary key (uuid v7).
    pub id: Uuid,
    /// Tenant the engagement belongs to. RLS-checked.
    pub tenant_id: TenantId,
    /// Engagement the approval covers.
    pub engagement_id: EngagementId,
    /// MITRE ATT&CK technique id.
    pub technique_id: String,
    /// Approver's normalised email.
    pub approver_email: String,
    /// Free-form rationale.
    pub reason: String,
    /// Insertion timestamp (server clock).
    pub recorded_at: OffsetDateTime,
}

/// Approval-repository port.
///
/// Declared at the storage layer rather than as a `trait` re-export of the
/// HTTP-facing `ApprovalPort` so the storage crate stays free of any
/// dependency on `sx-api`.
#[async_trait]
pub trait ApprovalRepository: Send + Sync {
    /// Insert a new row. Returns the persisted projection (with server
    /// timestamp) on success, [`DomainError::Conflict`] when the
    /// uniqueness constraint fires.
    async fn record(&self, row: NewApproval) -> Result<ApprovalRow, DomainError>;

    /// List every approval bound to `engagement_id`, oldest-first.
    async fn list_by_engagement(
        &self,
        tenant_id: TenantId,
        engagement_id: EngagementId,
    ) -> Result<Vec<ApprovalRow>, DomainError>;

    /// Count distinct approver emails recorded against
    /// `(engagement_id, technique_id)`.
    async fn count_distinct_approvers(
        &self,
        tenant_id: TenantId,
        engagement_id: EngagementId,
        technique_id: &str,
    ) -> Result<u32, DomainError>;
}

/// New-approval input passed to [`ApprovalRepository::record`]. The
/// repository allocates the surrogate id and stamps `recorded_at`.
#[derive(Debug, Clone)]
pub struct NewApproval {
    /// Tenant the engagement belongs to.
    pub tenant_id: TenantId,
    /// Engagement the approval covers.
    pub engagement_id: EngagementId,
    /// MITRE ATT&CK technique id.
    pub technique_id: String,
    /// Approver's normalised email.
    pub approver_email: String,
    /// Free-form rationale.
    pub reason: String,
}

/// `PgApprovalRepository` — `bas_approvals` table adapter (RLS).
#[derive(Debug, Clone)]
pub struct PgApprovalRepository {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl PgApprovalRepository {
    /// Construct from a pre-built pool.
    #[must_use]
    pub const fn new(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
        }
    }
}

fn row_to_approval(row: &sqlx::postgres::PgRow) -> Result<ApprovalRow, StorageError> {
    let id: Uuid = row.try_get("id").map_err(StorageError::from)?;
    let tenant_id: Uuid = row.try_get("tenant_id").map_err(StorageError::from)?;
    let engagement_id: Uuid = row.try_get("engagement_id").map_err(StorageError::from)?;
    let technique_id: String = row.try_get("technique_id").map_err(StorageError::from)?;
    let approver_email: String = row.try_get("approver_email").map_err(StorageError::from)?;
    let reason: String = row.try_get("reason").map_err(StorageError::from)?;
    let recorded_at: OffsetDateTime = row.try_get("recorded_at").map_err(StorageError::from)?;
    Ok(ApprovalRow {
        id,
        tenant_id: TenantId::from_uuid(tenant_id),
        engagement_id: EngagementId::from_uuid(engagement_id),
        technique_id,
        approver_email,
        reason,
        recorded_at,
    })
}

#[async_trait]
impl ApprovalRepository for PgApprovalRepository {
    async fn record(&self, row: NewApproval) -> Result<ApprovalRow, DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        TenantContext::apply(&mut tx, row.tenant_id, self.stmt_timeout_ms).await?;

        let id = Uuid::now_v7();
        let recorded_at = OffsetDateTime::now_utc();
        let approver_email = row.approver_email.trim().to_ascii_lowercase();

        let inserted = sqlx::query(
            "INSERT INTO bas_approvals \
                (id, tenant_id, engagement_id, technique_id, approver_email, reason, recorded_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             RETURNING id, tenant_id, engagement_id, technique_id, approver_email, reason, \
                       recorded_at",
        )
        .bind(id)
        .bind(row.tenant_id.as_uuid())
        .bind(row.engagement_id.as_uuid())
        .bind(&row.technique_id)
        .bind(&approver_email)
        .bind(&row.reason)
        .bind(recorded_at)
        .fetch_one(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;
        Ok(row_to_approval(&inserted)?)
    }

    async fn list_by_engagement(
        &self,
        tenant_id: TenantId,
        engagement_id: EngagementId,
    ) -> Result<Vec<ApprovalRow>, DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        TenantContext::apply(&mut tx, tenant_id, self.stmt_timeout_ms).await?;

        let rows = sqlx::query(
            "SELECT id, tenant_id, engagement_id, technique_id, approver_email, reason, \
                    recorded_at \
             FROM bas_approvals \
             WHERE tenant_id = $1 AND engagement_id = $2 \
             ORDER BY recorded_at ASC, id ASC",
        )
        .bind(tenant_id.as_uuid())
        .bind(engagement_id.as_uuid())
        .fetch_all(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push(row_to_approval(r)?);
        }
        Ok(out)
    }

    async fn count_distinct_approvers(
        &self,
        tenant_id: TenantId,
        engagement_id: EngagementId,
        technique_id: &str,
    ) -> Result<u32, DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
        TenantContext::apply(&mut tx, tenant_id, self.stmt_timeout_ms).await?;

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(DISTINCT approver_email)::BIGINT \
             FROM bas_approvals \
             WHERE tenant_id = $1 AND engagement_id = $2 AND technique_id = $3",
        )
        .bind(tenant_id.as_uuid())
        .bind(engagement_id.as_uuid())
        .bind(technique_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(StorageError::from)?;

        tx.commit().await.map_err(StorageError::from)?;

        u32::try_from(count.max(0))
            .map_err(|_| DomainError::Repository("distinct approver count overflow".to_owned()))
    }
}

fn map_sqlx(e: sqlx::Error) -> DomainError {
    StorageError::from(e).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_row_structural_equality_round_trips() {
        let now = OffsetDateTime::now_utc();
        let id = Uuid::now_v7();
        let tenant = TenantId::new();
        let engagement = EngagementId::new();
        let a = ApprovalRow {
            id,
            tenant_id: tenant,
            engagement_id: engagement,
            technique_id: "T1003".into(),
            approver_email: "alice@example.com".into(),
            reason: "ok".into(),
            recorded_at: now,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn new_approval_preserves_inputs() {
        let na = NewApproval {
            tenant_id: TenantId::new(),
            engagement_id: EngagementId::new(),
            technique_id: "T1003".into(),
            approver_email: "Alice@Example.com".into(),
            reason: "approved".into(),
        };
        assert_eq!(na.technique_id, "T1003");
        assert_eq!(na.approver_email, "Alice@Example.com");
        assert_eq!(na.reason, "approved");
    }
}
