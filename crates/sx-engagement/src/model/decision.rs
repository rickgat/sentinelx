//! `ScopeDecision` — the output of the scope validator.
//!
//! Always returned for every `evaluate` call; never panics, never throws.
//! Callers map `allowed = false` into `EngagementError` at the use-case
//! boundary if they need a typed error.

use serde::{Deserialize, Serialize};

use crate::model::intensity::ScanIntensity;
use crate::model::window::TimeWindow;

/// A structured allow/deny decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeDecision {
    /// `true` when the request is fully authorized.
    pub allowed: bool,
    /// Human-readable reason, suitable for audit logs.
    pub reason: String,
    /// The engagement window — surfaced even on denial for client UX.
    pub engagement_window: TimeWindow,
    /// The engagement intensity ceiling — surfaced for client UX.
    pub intensity_ceiling: ScanIntensity,
}

impl ScopeDecision {
    /// Build an `allow` decision with the canonical reason.
    #[must_use]
    pub fn allow(window: TimeWindow, ceiling: ScanIntensity) -> Self {
        Self {
            allowed: true,
            reason: "authorized".into(),
            engagement_window: window,
            intensity_ceiling: ceiling,
        }
    }

    /// Build a `deny` decision with a structured reason string.
    #[must_use]
    pub fn deny(reason: impl Into<String>, window: TimeWindow, ceiling: ScanIntensity) -> Self {
        Self {
            allowed: false,
            reason: reason.into(),
            engagement_window: window,
            intensity_ceiling: ceiling,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use time::{Duration, OffsetDateTime};

    fn window() -> TimeWindow {
        TimeWindow::new(
            OffsetDateTime::UNIX_EPOCH,
            OffsetDateTime::UNIX_EPOCH + Duration::hours(1),
        )
        .unwrap()
    }

    #[test]
    fn allow_has_authorized_reason() {
        let d = ScopeDecision::allow(window(), ScanIntensity::SafeInteractive);
        assert!(d.allowed);
        assert_eq!(d.reason, "authorized");
    }

    #[test]
    fn deny_preserves_reason() {
        let d = ScopeDecision::deny("denylisted: *.gov", window(), ScanIntensity::Theoretical);
        assert!(!d.allowed);
        assert_eq!(d.reason, "denylisted: *.gov");
    }
}
