//! [`AssetRepository`] port.

use async_trait::async_trait;

use crate::entity::asset::Asset;
use crate::error::DomainError;
use crate::value_object::ids::{AssetId, TenantId};
use crate::value_object::page::{Page, PagedResult};

/// Persistence port for [`Asset`]. All operations are tenant-scoped.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait AssetRepository: Send + Sync {
    /// Look up by id, scoped to a tenant.
    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: AssetId,
    ) -> Result<Option<Asset>, DomainError>;

    /// Look up by fingerprint within a tenant.
    async fn find_by_fingerprint(
        &self,
        tenant_id: TenantId,
        fingerprint: &str,
    ) -> Result<Option<Asset>, DomainError>;

    /// Upsert: create if absent, otherwise update mutable fields.
    async fn upsert(&self, asset: &Asset) -> Result<(), DomainError>;

    /// Page through all assets for a tenant.
    async fn list_for_tenant_paged(
        &self,
        tenant_id: TenantId,
        page: Page,
    ) -> Result<PagedResult<Asset>, DomainError>;
}
