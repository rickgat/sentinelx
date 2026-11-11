//! API-shaped view of a [`crate::model::decision::ScopeDecision`].

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::model::decision::ScopeDecision;
use crate::model::intensity::ScanIntensity;

/// Wire-friendly view of a scope decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeDecisionView {
    /// `true` when the request is fully authorized.
    pub allowed: bool,
    /// Human-readable reason.
    pub reason: String,
    /// Inclusive window start.
    pub window_start: OffsetDateTime,
    /// Inclusive window end.
    pub window_end: OffsetDateTime,
    /// Effective intensity ceiling.
    pub intensity_ceiling: ScanIntensity,
}

impl From<ScopeDecision> for ScopeDecisionView {
    fn from(d: ScopeDecision) -> Self {
        Self {
            allowed: d.allowed,
            reason: d.reason,
            window_start: d.engagement_window.start,
            window_end: d.engagement_window.end,
            intensity_ceiling: d.intensity_ceiling,
        }
    }
}
