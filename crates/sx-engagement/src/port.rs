//! Repository port for the [`crate::model::engagement::Engagement`] aggregate.
//!
//! NOTE: this will ultimately be re-exported from
//! `sx_core::port::engagement_repository`. While the core crate is being
//! scaffolded, the canonical port lives here so that this crate is
//! self-contained and testable in isolation. The signature mirrors the spec.

use async_trait::async_trait;
use sx_core::value_object::ids::{EngagementId, TenantId};

use crate::error::EngagementError;
use crate::model::engagement::Engagement;

/// Persistence port for the engagement aggregate.
///
/// Adapter crates implement this trait against `PostgreSQL` / `SQLite` / a mock.
#[async_trait]
pub trait EngagementRepository: Send + Sync + std::fmt::Debug {
    /// Insert a new engagement.
    async fn create(&self, engagement: &Engagement) -> Result<(), EngagementError>;

    /// Load an engagement by id.
    async fn find_by_id(
        &self,
        tenant_id: TenantId,
        id: EngagementId,
    ) -> Result<Option<Engagement>, EngagementError>;

    /// Persist updates to an existing engagement.
    async fn update(&self, engagement: &Engagement) -> Result<(), EngagementError>;

    /// List a tenant's engagements, paginated. Defaults to empty so existing
    /// adapters / test doubles need no change; durable repositories
    /// (in-memory, Postgres) override it with a real listing.
    async fn list(
        &self,
        _tenant_id: TenantId,
        _offset: u64,
        _limit: u32,
    ) -> Result<Vec<Engagement>, EngagementError> {
        Ok(Vec::new())
    }
}
