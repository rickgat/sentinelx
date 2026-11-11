//! Request DTO for [`crate::controller::create_engagement::CreateEngagementUseCase`].

use serde::{Deserialize, Serialize};
use sx_core::value_object::ids::TenantId;
use time::OffsetDateTime;

use crate::model::intensity::ScanIntensity;
use crate::model::scope_target::ScopeTarget;

/// Input DTO for creating a new engagement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateEngagementRequest {
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Human-readable engagement name.
    pub name: String,
    /// Authorized scope — must be non-empty.
    pub scope: Vec<ScopeTarget>,
    /// Inclusive lower bound of the scan window.
    pub window_start: OffsetDateTime,
    /// Inclusive upper bound of the scan window.
    pub window_end: OffsetDateTime,
    /// Intensity ceiling.
    pub max_intensity: ScanIntensity,
}
