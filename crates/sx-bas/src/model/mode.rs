//! Operating mode ladder for BAS.
//!
//! Variants are ordered: `Theoretical < PassiveValidation < SafeInteractive
//! < ActiveExploit < RedTeam`. The default mode for any new platform run is
//! [`AttackMode::Theoretical`]. Promotion to a higher mode requires an
//! explicit `ModeBump` audit event recorded by the orchestrator (out of
//! scope for this crate — handled at the API boundary).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::BasError;

/// How aggressively a BAS run is allowed to behave.
///
/// Each [`crate::model::technique::AttackTechnique`] declares its own
/// `max_mode`. The orchestrator refuses to execute a technique whose
/// declared `max_mode` exceeds the active engagement's mode ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackMode {
    /// Reasoning over existing data; no packets emitted.
    Theoretical,
    /// Cached intel and signature match only.
    PassiveValidation,
    /// Non-destructive probes (e.g. SSRF callback to OOB server).
    SafeInteractive,
    /// Exploit verification with a limited PoC. Requires dual approval and a
    /// valid Rules-of-Engagement artifact.
    ActiveExploit,
    /// Full chain (lateral movement, persistence). Requires signed RoE and
    /// an active change window.
    RedTeam,
}

impl AttackMode {
    /// The default mode for any new platform run.
    pub const DEFAULT: Self = Self::Theoretical;

    /// Returns a small monotonically-increasing rank suitable for ordering or
    /// metrics labels.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Theoretical => 0,
            Self::PassiveValidation => 1,
            Self::SafeInteractive => 2,
            Self::ActiveExploit => 3,
            Self::RedTeam => 4,
        }
    }

    /// Returns `true` when this mode requires the dual-approval gate.
    ///
    /// `ActiveExploit` requires ≥2 approvers; `RedTeam` requires ≥3.
    #[must_use]
    pub const fn requires_dual_approval(self) -> bool {
        matches!(self, Self::ActiveExploit | Self::RedTeam)
    }

    /// Approver count required for this mode under the conservative default
    /// policy.
    ///
    /// - `Theoretical`, `PassiveValidation`, `SafeInteractive` → 0
    /// - `ActiveExploit` → 2
    /// - `RedTeam` → 3
    #[must_use]
    pub const fn required_approvals(self) -> u32 {
        match self {
            Self::Theoretical | Self::PassiveValidation | Self::SafeInteractive => 0,
            Self::ActiveExploit => 2,
            Self::RedTeam => 3,
        }
    }

    /// Returns `true` when this mode requires a signed Rules of Engagement
    /// artifact AND an active change window.
    #[must_use]
    pub const fn requires_roe_and_change_window(self) -> bool {
        matches!(self, Self::ActiveExploit | Self::RedTeam)
    }

    /// Returns the canonical snake_case form of this mode.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Theoretical => "theoretical",
            Self::PassiveValidation => "passive_validation",
            Self::SafeInteractive => "safe_interactive",
            Self::ActiveExploit => "active_exploit",
            Self::RedTeam => "red_team",
        }
    }
}

impl fmt::Display for AttackMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AttackMode {
    type Err = BasError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "theoretical" => Ok(Self::Theoretical),
            "passive_validation" => Ok(Self::PassiveValidation),
            "safe_interactive" => Ok(Self::SafeInteractive),
            "active_exploit" => Ok(Self::ActiveExploit),
            "red_team" => Ok(Self::RedTeam),
            other => Err(BasError::invalid_input(format!(
                "unknown attack mode: {other}"
            ))),
        }
    }
}

impl Default for AttackMode {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::AttackMode;

    #[test]
    fn attack_mode_ordering_is_total() {
        assert!(AttackMode::Theoretical < AttackMode::PassiveValidation);
        assert!(AttackMode::PassiveValidation < AttackMode::SafeInteractive);
        assert!(AttackMode::SafeInteractive < AttackMode::ActiveExploit);
        assert!(AttackMode::ActiveExploit < AttackMode::RedTeam);
        // Reflexive.
        assert!(AttackMode::Theoretical <= AttackMode::Theoretical);
        assert!(AttackMode::RedTeam >= AttackMode::RedTeam);
        // Ranks line up.
        assert_eq!(AttackMode::Theoretical.rank(), 0);
        assert_eq!(AttackMode::RedTeam.rank(), 4);
    }

    #[test]
    fn attack_mode_from_str_round_trip() {
        for m in [
            AttackMode::Theoretical,
            AttackMode::PassiveValidation,
            AttackMode::SafeInteractive,
            AttackMode::ActiveExploit,
            AttackMode::RedTeam,
        ] {
            let s = m.to_string();
            let parsed: AttackMode = s.parse().unwrap();
            assert_eq!(parsed, m);
        }
    }

    #[test]
    fn default_mode_is_theoretical() {
        assert_eq!(AttackMode::default(), AttackMode::Theoretical);
        assert_eq!(AttackMode::DEFAULT, AttackMode::Theoretical);
    }

    #[test]
    fn from_str_rejects_unknown() {
        assert!("yolo".parse::<AttackMode>().is_err());
    }

    #[test]
    fn requires_dual_approval_threshold() {
        assert!(!AttackMode::Theoretical.requires_dual_approval());
        assert!(!AttackMode::SafeInteractive.requires_dual_approval());
        assert!(AttackMode::ActiveExploit.requires_dual_approval());
        assert!(AttackMode::RedTeam.requires_dual_approval());
    }

    #[test]
    fn required_approvals_are_conservative() {
        assert_eq!(AttackMode::Theoretical.required_approvals(), 0);
        assert_eq!(AttackMode::PassiveValidation.required_approvals(), 0);
        assert_eq!(AttackMode::SafeInteractive.required_approvals(), 0);
        assert_eq!(AttackMode::ActiveExploit.required_approvals(), 2);
        assert_eq!(AttackMode::RedTeam.required_approvals(), 3);
    }
}
