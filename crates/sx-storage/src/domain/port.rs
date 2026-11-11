//! Repository port traits — mirror of `sx_core::port`.
//!
//! Each trait is the abstract interface that the application layer
//! consumes; the concrete implementations live in
//! [`crate::repository`].

use async_trait::async_trait;

use super::entity::{Asset, Cve, Engagement, Finding, Tenant, User};
use super::error::DomainError;
use super::value_object::{
    AssetId, CveId, EngagementId, FindingId, Page, PagedResult, TenantId, UserId,
};

/// Tenant aggregate persistence.
#[async_trait]
pub trait TenantRepository: Send + Sync {
    /// Lookup by primary key.
    async fn find_by_id(&self, id: TenantId) -> Result<Option<Tenant>, DomainError>;

    /// Lookup by URL-safe slug.
    async fn find_by_slug(&self, slug: &str) -> Result<Option<Tenant>, DomainError>;

    /// Insert or update.
    async fn save(&self, tenant: &Tenant) -> Result<(), DomainError>;

    /// Soft-delete (sets `deleted_at = now()`).
    async fn soft_delete(&self, id: TenantId) -> Result<(), DomainError>;
}

/// User aggregate persistence.
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Lookup by primary key, scoped to a tenant.
    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: UserId,
    ) -> Result<Option<User>, DomainError>;

    /// Lookup by email within a tenant. Email match is case-insensitive
    /// (column is `CITEXT`).
    async fn find_by_email(
        &self,
        tenant_id: TenantId,
        email: &str,
    ) -> Result<Option<User>, DomainError>;

    /// Insert or update.
    async fn save(&self, user: &User) -> Result<(), DomainError>;

    /// Paginated list within a tenant.
    async fn list(&self, tenant_id: TenantId, page: Page)
        -> Result<PagedResult<User>, DomainError>;
}

/// Engagement aggregate persistence.
#[async_trait]
pub trait EngagementRepository: Send + Sync {
    /// Lookup by primary key, scoped to a tenant.
    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: EngagementId,
    ) -> Result<Option<Engagement>, DomainError>;

    /// Insert or update.
    async fn save(&self, engagement: &Engagement) -> Result<(), DomainError>;

    /// Paginated list within a tenant.
    async fn list(
        &self,
        tenant_id: TenantId,
        page: Page,
    ) -> Result<PagedResult<Engagement>, DomainError>;
}

/// Asset aggregate persistence.
#[async_trait]
pub trait AssetRepository: Send + Sync {
    /// Lookup by primary key, scoped to a tenant.
    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: AssetId,
    ) -> Result<Option<Asset>, DomainError>;

    /// Lookup by fingerprint within a tenant (unique).
    async fn find_by_fingerprint(
        &self,
        tenant_id: TenantId,
        fingerprint: &str,
    ) -> Result<Option<Asset>, DomainError>;

    /// Insert or update.
    async fn save(&self, asset: &Asset) -> Result<(), DomainError>;

    /// Paginated list of all assets in an engagement.
    async fn list_by_engagement(
        &self,
        tenant_id: TenantId,
        engagement_id: EngagementId,
        page: Page,
    ) -> Result<PagedResult<Asset>, DomainError>;
}

/// Finding aggregate persistence.
#[async_trait]
pub trait FindingRepository: Send + Sync {
    /// Lookup by primary key, scoped to a tenant.
    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: FindingId,
    ) -> Result<Option<Finding>, DomainError>;

    /// Insert or update.
    async fn save(&self, finding: &Finding) -> Result<(), DomainError>;

    /// Paginated list of all findings against an engagement.
    async fn list_by_engagement(
        &self,
        tenant_id: TenantId,
        engagement_id: EngagementId,
        page: Page,
    ) -> Result<PagedResult<Finding>, DomainError>;
}

/// CVE catalogue (cross-tenant reference data, not tenant-scoped).
#[async_trait]
pub trait CveRepository: Send + Sync {
    /// Lookup by canonical CVE id.
    async fn find_by_id(&self, id: &CveId) -> Result<Option<Cve>, DomainError>;

    /// Insert or update.
    async fn upsert(&self, cve: &Cve) -> Result<(), DomainError>;

    /// Paginated catalogue listing.
    async fn list(&self, page: Page) -> Result<PagedResult<Cve>, DomainError>;
}
