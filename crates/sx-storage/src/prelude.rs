//! Re-exports the types most external callers need at the boundary.

pub use crate::domain::entity::{Asset, Cve, Engagement, Finding, Tenant, User};
pub use crate::domain::error::DomainError;
pub use crate::domain::port::{
    AssetRepository, CveRepository, EngagementRepository, FindingRepository, TenantRepository,
    UserRepository,
};
pub use crate::domain::value_object::{
    AssetId, CveId, EngagementId, FindingId, Page, PagedResult, TenantId, UserId,
};
pub use crate::error::StorageError;
pub use crate::pool::{build_pool, PoolSettings};
pub use crate::repository::{
    PgAssetRepository, PgCveRepository, PgEngagementRepository, PgFindingRepository,
    PgTenantRepository, PgUserRepository,
};
pub use crate::tenant_context::TenantContext;
