//! [`UserRepository`] port.

use async_trait::async_trait;

use crate::entity::user::User;
use crate::error::DomainError;
use crate::value_object::ids::{TenantId, UserId};

/// Persistence port for [`User`]. All operations are tenant-scoped.
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Look up by id, scoped to a tenant.
    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: UserId,
    ) -> Result<Option<User>, DomainError>;

    /// Look up a user by email within a tenant.
    async fn find_by_email_in_tenant(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> Result<Option<User>, DomainError>;

    /// Persist a new user.
    async fn create(&self, user: &User) -> Result<(), DomainError>;

    /// Persist the full state of an existing user.
    async fn update(&self, user: &User) -> Result<(), DomainError>;
}
