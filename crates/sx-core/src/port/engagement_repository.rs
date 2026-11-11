//! [`EngagementRepository`] port.

use async_trait::async_trait;

use crate::entity::engagement::{Engagement, EngagementApproval, EngagementStatus};
use crate::error::DomainError;
use crate::value_object::ids::{EngagementId, TenantId};
use crate::value_object::page::{Page, PagedResult};

/// Persistence port for [`Engagement`]. All operations are tenant-scoped.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait EngagementRepository: Send + Sync {
    /// Look up by id, scoped to a tenant.
    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: EngagementId,
    ) -> Result<Option<Engagement>, DomainError>;

    /// List engagements for a tenant.
    async fn list_for_tenant(
        &self,
        tenant_id: TenantId,
        page: Page,
    ) -> Result<PagedResult<Engagement>, DomainError>;

    /// Persist a new engagement.
    async fn create(&self, engagement: &Engagement) -> Result<(), DomainError>;

    /// Persist the full state of an existing engagement.
    ///
    /// Default implementation delegates to [`update_status`] and
    /// [`add_approval`] so existing adapters do not have to be re-implemented;
    /// adapters that can write the whole aggregate atomically should
    /// override this.
    async fn update(&self, engagement: &Engagement) -> Result<(), DomainError> {
        self.update_status(engagement.tenant_id, engagement.id, engagement.status)
            .await?;
        // Approvals are written through `add_approval` so a partial update is
        // visible to readers. The default cannot reliably reconcile deletes
        // (approvals are append-only by domain rule), so this is consistent.
        for approval in &engagement.approvals {
            // Treat duplicate-approver errors as idempotent: the desired
            // post-state already holds.
            match self
                .add_approval(engagement.tenant_id, engagement.id, approval.clone())
                .await
            {
                Ok(()) | Err(DomainError::Conflict(_)) => {}
                Err(other) => return Err(other),
            }
        }
        Ok(())
    }

    /// Update an engagement's lifecycle status.
    async fn update_status(
        &self,
        tenant_id: TenantId,
        id: EngagementId,
        status: EngagementStatus,
    ) -> Result<(), DomainError>;

    /// Record a new approval against an engagement.
    async fn add_approval(
        &self,
        tenant_id: TenantId,
        id: EngagementId,
        approval: EngagementApproval,
    ) -> Result<(), DomainError>;
}
