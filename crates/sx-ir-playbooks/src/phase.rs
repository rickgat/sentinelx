//! NIST SP 800-61 Rev 2 lifecycle phases.

use serde::{Deserialize, Serialize};

/// The four canonical incident-response lifecycle phases. The order is
/// significant: phases progress strictly forward during an incident, but
/// state-machine rules in [`crate::state`] also permit re-entering
/// `containment_eradication_recovery` from `post_incident_activity` when
/// a follow-up containment action is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IrPhase {
    /// 1. Preparation — readiness, on-call setup, comms tree.
    Preparation,
    /// 2. Detection & analysis — triage, scoping, evidence pulls.
    DetectionAnalysis,
    /// 3. Containment, eradication & recovery — short / long-term
    ///    containment, root-cause removal, service restoration.
    ContainmentEradicationRecovery,
    /// 4. Post-incident activity — lessons learned, after-action review,
    ///    gap close-out.
    #[serde(rename = "post_incident_activity")]
    PostIncident,
}

impl IrPhase {
    /// Lowercase serialisation used in JSON wire shapes + DB columns.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Preparation => "preparation",
            Self::DetectionAnalysis => "detection_analysis",
            Self::ContainmentEradicationRecovery => "containment_eradication_recovery",
            Self::PostIncident => "post_incident_activity",
        }
    }

    /// Iterate the four phases in NIST order. Used by callers building
    /// per-phase checklists.
    #[must_use]
    pub const fn ordered() -> [Self; 4] {
        [
            Self::Preparation,
            Self::DetectionAnalysis,
            Self::ContainmentEradicationRecovery,
            Self::PostIncident,
        ]
    }
}

impl std::fmt::Display for IrPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_json() {
        for p in IrPhase::ordered() {
            let s = serde_json::to_string(&p).expect("ser");
            let back: IrPhase = serde_json::from_str(&s).expect("de");
            assert_eq!(p, back);
        }
    }

    #[test]
    fn as_str_is_stable() {
        assert_eq!(IrPhase::Preparation.as_str(), "preparation");
        assert_eq!(IrPhase::DetectionAnalysis.as_str(), "detection_analysis");
        assert_eq!(
            IrPhase::ContainmentEradicationRecovery.as_str(),
            "containment_eradication_recovery"
        );
        assert_eq!(IrPhase::PostIncident.as_str(), "post_incident_activity");
    }
}
