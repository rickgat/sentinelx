//! `ScanRequest` — the payload presented to the scope validator.

use serde::{Deserialize, Serialize};
use sx_core::value_object::ids::{EngagementId, TenantId, UserId};

use crate::model::intensity::ScanIntensity;
use crate::model::scope_target::ScopeTarget;

/// A request to scan a single target at a given intensity.
///
/// The validator decides whether to allow or deny — it never mutates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRequest {
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Engagement this request claims authorization from.
    pub engagement_id: EngagementId,
    /// The thing being scanned.
    pub target: ScopeTarget,
    /// Requested intensity.
    pub intensity: ScanIntensity,
    /// Identifier of the operator who initiated the request.
    pub requested_by: UserId,
}

impl ScanRequest {
    /// Construct a new `ScanRequest`.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        engagement_id: EngagementId,
        target: ScopeTarget,
        intensity: ScanIntensity,
        requested_by: UserId,
    ) -> Self {
        Self {
            tenant_id,
            engagement_id,
            target,
            intensity,
            requested_by,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_serde() {
        let req = ScanRequest::new(
            TenantId::new(),
            EngagementId::new(),
            ScopeTarget::Domain("example.com".into()),
            ScanIntensity::SafeInteractive,
            UserId::new(),
        );
        let json = serde_json::to_string(&req).unwrap();
        let back: ScanRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }
}
