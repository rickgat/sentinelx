//! Response DTO for [`crate::controller::create_engagement::CreateEngagementUseCase`].

use serde::{Deserialize, Serialize};
use sx_core::value_object::ids::{EngagementId, TenantId};
use time::OffsetDateTime;

use crate::model::engagement::EngagementStatus;

/// Output DTO returned after a successful `CreateEngagement` call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateEngagementResponse {
    /// Identifier of the newly created engagement.
    pub engagement_id: EngagementId,
    /// Tenant the engagement belongs to.
    pub tenant_id: TenantId,
    /// Current FSM status (always `Draft` immediately after creation).
    pub status: EngagementStatus,
    /// When the record was created.
    pub created_at: OffsetDateTime,
}
