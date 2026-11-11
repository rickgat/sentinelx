//! SSVC v2.0 (CISA Stakeholder-Specific Vulnerability Categorization)
//! input types and the [`SsvcDecision`] output enum.
//!
//! The semantics of every variant are pinned to the published CISA SSVC
//! v2.0 specification — see <https://www.cisa.gov/ssvc>.

use std::fmt;

use serde::{Deserialize, Serialize};

/// State of public exploitation evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exploitation {
    /// No evidence of any exploit and no public `PoC`.
    None,
    /// Public proof-of-concept exists.
    Poc,
    /// Reliable evidence of active exploitation in the wild.
    Active,
}

impl fmt::Display for Exploitation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::None => "none",
            Self::Poc => "poc",
            Self::Active => "active",
        };
        f.write_str(s)
    }
}

/// SSVC exposure axis — distinct from
/// [`sx_core::value_object::exposure::ExposureLevel`] because SSVC uses a
/// three-bucket vocabulary aligned to the CISA decision tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SsvcExposure {
    /// Service is only reachable by a small, trusted population.
    Small,
    /// Service is reachable by a broader but controlled set of consumers.
    Controlled,
    /// Service is open to the public internet.
    Open,
}

impl fmt::Display for SsvcExposure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Small => "small",
            Self::Controlled => "controlled",
            Self::Open => "open",
        };
        f.write_str(s)
    }
}

/// Whether the vulnerability can be exploited in an automated, hands-off way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutomatableImpact {
    /// Exploitation requires manual steps.
    No,
    /// Exploitation can be scripted / wormed.
    Yes,
}

impl fmt::Display for AutomatableImpact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::No => "no",
            Self::Yes => "yes",
        };
        f.write_str(s)
    }
}

/// Mission impact: business / mission consequences of exploitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissionImpact {
    /// Minimal or degraded efficiency.
    Low,
    /// Significant but not crippling effects.
    Medium,
    /// Crippling, mission-essential consequences.
    High,
}

impl fmt::Display for MissionImpact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        };
        f.write_str(s)
    }
}

/// Human safety impact — the SSVC v2 well-being axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanImpact {
    /// No safety impact.
    Low,
    /// Modest safety impact (e.g. limited PII exposure).
    Medium,
    /// Safety or life impact, regulated data leakage, etc.
    High,
}

impl fmt::Display for HumanImpact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        };
        f.write_str(s)
    }
}

/// Input bundle for [`crate::service::SsvcMapper`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsvcInput {
    /// State of public exploitation evidence.
    pub exploitation: Exploitation,
    /// Where the vulnerable surface is exposed.
    pub exposure: SsvcExposure,
    /// Whether exploitation is automatable.
    pub automatable: AutomatableImpact,
    /// Mission / business impact.
    pub mission_impact: MissionImpact,
    /// Human safety impact.
    pub human_impact: HumanImpact,
}

/// SSVC decision label — the output of [`crate::service::SsvcMapper`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SsvcDecision {
    /// Routine handling.
    Track,
    /// Track with elevated urgency (the "Track*" label in CISA SSVC).
    #[serde(rename = "track_star")]
    TrackStar,
    /// Attend during the next maintenance window.
    Attend,
    /// Act now — patch / mitigate immediately.
    Act,
}

impl fmt::Display for SsvcDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Track => "Track",
            Self::TrackStar => "Track*",
            Self::Attend => "Attend",
            Self::Act => "Act",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ordering() {
        assert!(Exploitation::None < Exploitation::Poc);
        assert!(Exploitation::Poc < Exploitation::Active);
        assert!(SsvcExposure::Small < SsvcExposure::Controlled);
        assert!(SsvcExposure::Controlled < SsvcExposure::Open);
        assert!(MissionImpact::Low < MissionImpact::Medium);
        assert!(MissionImpact::Medium < MissionImpact::High);
        assert!(HumanImpact::Low < HumanImpact::Medium);
        assert!(SsvcDecision::Track < SsvcDecision::TrackStar);
        assert!(SsvcDecision::TrackStar < SsvcDecision::Attend);
        assert!(SsvcDecision::Attend < SsvcDecision::Act);
    }

    #[test]
    fn display_labels() {
        assert_eq!(SsvcDecision::Act.to_string(), "Act");
        assert_eq!(SsvcDecision::TrackStar.to_string(), "Track*");
        assert_eq!(SsvcExposure::Open.to_string(), "open");
        assert_eq!(Exploitation::Active.to_string(), "active");
    }

    #[test]
    fn json_round_trip() {
        let input = SsvcInput {
            exploitation: Exploitation::Active,
            exposure: SsvcExposure::Open,
            automatable: AutomatableImpact::Yes,
            mission_impact: MissionImpact::High,
            human_impact: HumanImpact::High,
        };
        let s = serde_json::to_string(&input).unwrap();
        let back: SsvcInput = serde_json::from_str(&s).unwrap();
        assert_eq!(input, back);
    }

    #[test]
    fn track_star_serializes_with_underscore() {
        let s = serde_json::to_string(&SsvcDecision::TrackStar).unwrap();
        assert_eq!(s, "\"track_star\"");
    }
}
