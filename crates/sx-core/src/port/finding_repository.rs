//! [`FindingRepository`] port.

use async_trait::async_trait;

use crate::entity::finding::{Finding, FindingFilter};
use crate::error::DomainError;
use crate::value_object::ids::{AssetId, FindingId, TenantId};
use crate::value_object::page::{Page, PagedResult};

/// Persistence port for [`Finding`]. All operations are tenant-scoped.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait FindingRepository: Send + Sync {
    /// Look up by id, scoped to a tenant.
    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: FindingId,
    ) -> Result<Option<Finding>, DomainError>;

    /// Insert-or-update by id.
    async fn upsert(&self, finding: &Finding) -> Result<(), DomainError>;

    /// List all findings for an asset.
    async fn list_by_asset(
        &self,
        tenant_id: TenantId,
        asset_id: AssetId,
        page: Page,
    ) -> Result<PagedResult<Finding>, DomainError>;

    /// List findings for a tenant with arbitrary filter criteria.
    async fn list_by_tenant_filter(
        &self,
        tenant_id: TenantId,
        filter: FindingFilter,
        page: Page,
    ) -> Result<PagedResult<Finding>, DomainError>;
}
