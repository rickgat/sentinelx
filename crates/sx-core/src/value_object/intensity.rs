//! Scan intensity ladder.
//!
//! [`ScanIntensity`] is the canonical, totally-ordered enumeration of how
//! aggressively a probe / engagement may behave. Higher variants are
//! stronger: `Theoretical < PassiveValidation < SafeInteractive <
//! ActiveExploit < RedTeam`.
//!
//! A scan request is rejected if its requested intensity exceeds the
//! engagement's `max_intensity` ceiling. This type is co-located with the
//! engagement aggregate and is also re-used by the BAS / discovery crates.
//!
//! The older [`crate::entity::engagement::ProbeIntensity`] type predates this
//! module and is retained for backward compatibility; new code should prefer
//! [`ScanIntensity`].

use serde::{Deserialize, Serialize};

/// How aggressively a probe is allowed to behave.
///
/// Variants are ordered: `Theoretical < PassiveValidation < SafeInteractive
/// < ActiveExploit < RedTeam`. The `Ord` impl is derived from declaration
/// order — do not reorder variants.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum ScanIntensity {
    /// Reasoning over existing data; no network I/O at all.
    #[default]
    Theoretical,
    /// Passive validation: DNS / WHOIS / certificate transparency, no probing.
    PassiveValidation,
    /// Low-rate, non-mutating probes.
    SafeInteractive,
    /// Active exploit attempts (within scope, approved).
    ActiveExploit,
    /// Full red-team: chained exploitation, lateral movement.
    RedTeam,
}

impl ScanIntensity {
    /// `true` when `self` is at least as aggressive as `other`.
    #[must_use]
    pub fn at_least(self, other: Self) -> bool {
        self >= other
    }

    /// `true` when this intensity requires the dual-approval gate
    /// (i.e. `>= ActiveExploit`).
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
    fn scan_intensity_ord_is_total() {
        // Explicit pairwise ordering checks — avoids slice indexing and
        // keeps the assertion site readable.
        assert!(ScanIntensity::Theoretical < ScanIntensity::PassiveValidation);
        assert!(ScanIntensity::PassiveValidation < ScanIntensity::SafeInteractive);
        assert!(ScanIntensity::SafeInteractive < ScanIntensity::ActiveExploit);
        assert!(ScanIntensity::ActiveExploit < ScanIntensity::RedTeam);

        // Reflexivity and antisymmetry across every variant.
        let ladder = [
            ScanIntensity::Theoretical,
            ScanIntensity::PassiveValidation,
            ScanIntensity::SafeInteractive,
            ScanIntensity::ActiveExploit,
            ScanIntensity::RedTeam,
        ];
        for x in ladder {
            assert!(x <= x);
            assert!(x >= x);
        }
    }

    #[test]
    fn at_least_is_inclusive() {
        assert!(ScanIntensity::ActiveExploit.at_least(ScanIntensity::ActiveExploit));
        assert!(ScanIntensity::RedTeam.at_least(ScanIntensity::SafeInteractive));
        assert!(!ScanIntensity::Theoretical.at_least(ScanIntensity::RedTeam));
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
    fn display_is_snake_case() {
        assert_eq!(
            ScanIntensity::PassiveValidation.to_string(),
            "passive_validation"
        );
        assert_eq!(ScanIntensity::RedTeam.to_string(), "red_team");
    }

    #[test]
    fn default_is_theoretical() {
        assert_eq!(ScanIntensity::default(), ScanIntensity::Theoretical);
    }

    #[test]
    fn serde_round_trip() {
        let intensity = ScanIntensity::ActiveExploit;
        let json = serde_json::to_string(&intensity).unwrap();
        assert_eq!(json, "\"active_exploit\"");
        let back: ScanIntensity = serde_json::from_str(&json).unwrap();
        assert_eq!(back, intensity);
    }
}
