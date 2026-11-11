//! Scan intensity ladder.
//!
//! Intensities form a total order. A scan request is rejected if its
//! intensity exceeds the engagement's `max_intensity` ceiling.

use serde::{Deserialize, Serialize};

/// How aggressively a probe is allowed to behave.
///
/// Variants are ordered: `Theoretical < PassiveValidation < SafeInteractive
/// < ActiveExploit < RedTeam`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanIntensity {
    /// Reasoning over existing data; no network I/O at all.
    Theoretical,
    /// Passive validation: DNS / WHOIS / certificate transparency, no probing.
    PassiveValidation,
    /// Safe interactive: low-rate, non-mutating probes.
    SafeInteractive,
    /// Active exploit attempts (within scope, approved).
    ActiveExploit,
    /// Full red-team: chained exploitation, lateral movement.
    RedTeam,
}

impl ScanIntensity {
    /// Returns `true` when this intensity is at least as aggressive as `other`.
    #[must_use]
    pub fn at_least(self, other: Self) -> bool {
        self >= other
    }

    /// Whether this intensity requires the dual-approval gate.
    #[must_use]
    pub fn requires_dual_approval(self) -> bool {
        self >= Self::ActiveExploit
    }
}

impl std::fmt::Display for ScanIntensity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Theoretical => "theoretical",
            Self::PassiveValidation => "passive_validation",
            Self::SafeInteractive => "safe_interactive",
            Self::ActiveExploit => "active_exploit",
            Self::RedTeam => "red_team",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::ScanIntensity;

    #[test]
    fn order_is_total_and_monotonic() {
        assert!(ScanIntensity::Theoretical < ScanIntensity::PassiveValidation);
        assert!(ScanIntensity::PassiveValidation < ScanIntensity::SafeInteractive);
        assert!(ScanIntensity::SafeInteractive < ScanIntensity::ActiveExploit);
        assert!(ScanIntensity::ActiveExploit < ScanIntensity::RedTeam);
    }

    #[test]
    fn requires_dual_approval_threshold() {
        assert!(!ScanIntensity::Theoretical.requires_dual_approval());
        assert!(!ScanIntensity::PassiveValidation.requires_dual_approval());
        assert!(!ScanIntensity::SafeInteractive.requires_dual_approval());
        assert!(ScanIntensity::ActiveExploit.requires_dual_approval());
        assert!(ScanIntensity::RedTeam.requires_dual_approval());
    }

    #[test]
    fn at_least_is_inclusive() {
        assert!(ScanIntensity::ActiveExploit.at_least(ScanIntensity::ActiveExploit));
        assert!(ScanIntensity::RedTeam.at_least(ScanIntensity::SafeInteractive));
        assert!(!ScanIntensity::Theoretical.at_least(ScanIntensity::RedTeam));
    }

    #[test]
    fn display_is_snake_case() {
        assert_eq!(
            ScanIntensity::PassiveValidation.to_string(),
            "passive_validation"
        );
        assert_eq!(ScanIntensity::RedTeam.to_string(), "red_team");
    }
}
