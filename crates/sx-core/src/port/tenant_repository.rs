//! [`TenantRepository`] port.

use async_trait::async_trait;

use crate::entity::tenant::Tenant;
use crate::error::DomainError;
use crate::value_object::ids::TenantId;

/// Persistence port for [`Tenant`].
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait TenantRepository: Send + Sync {
    /// Look up a tenant by id.
    async fn find_by_id(&self, id: TenantId) -> Result<Option<Tenant>, DomainError>;

    /// Look up a tenant by globally-unique slug.
    async fn find_by_slug(&self, slug: &str) -> Result<Option<Tenant>, DomainError>;

    /// Persist a new tenant.
    async fn create(&self, tenant: &Tenant) -> Result<(), DomainError>;

    /// Soft-delete a tenant by id.
    async fn soft_delete(&self, id: TenantId) -> Result<(), DomainError>;
}
