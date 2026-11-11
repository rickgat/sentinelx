//! Dual-approval policy.
//!
//! For high-intensity engagements (`ActiveExploit`, `RedTeam`) at least N
//! unique human approvers must sign off before the engagement may activate.
//!
//! Thresholds come from configuration, never from compiled-in constants.

use serde::{Deserialize, Serialize};
use sx_config::schema::engagement::EngagementConfig;

use crate::model::engagement::EngagementApproval;
use crate::model::intensity::ScanIntensity;

/// Tiered approval thresholds keyed by intensity ceiling.
///
/// Built either from operator config OR derived from an [`EngagementConfig`]
/// via [`ApprovalThresholds::from_engagement_config`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalThresholds {
    /// Approvals required for `Theoretical`.
    pub theoretical: u32,
    /// Approvals required for `PassiveValidation`.
    pub passive_validation: u32,
    /// Approvals required for `SafeInteractive`.
    pub safe_interactive: u32,
    /// Approvals required for `ActiveExploit`.
    pub active_exploit: u32,
    /// Approvals required for `RedTeam`.
    pub red_team: u32,
}

impl ApprovalThresholds {
    /// Look up the threshold for the given intensity.
    #[must_use]
    pub const fn for_intensity(&self, intensity: ScanIntensity) -> u32 {
        match intensity {
            ScanIntensity::Theoretical => self.theoretical,
            ScanIntensity::PassiveValidation => self.passive_validation,
            ScanIntensity::SafeInteractive => self.safe_interactive,
            ScanIntensity::ActiveExploit => self.active_exploit,
            ScanIntensity::RedTeam => self.red_team,
        }
    }

    /// Derive thresholds from an [`EngagementConfig`].
    ///
    /// The mapping follows a security-conservative default chain anchored at
    /// the operator-configured `default_intensity`:
    /// * intensities at or below `default_intensity` require **1** approval;
    /// * intensities above `default_intensity` require **2** approvals
    ///   (the dual-approval gate);
    /// * `RedTeam` requires **3** approvals regardless.
    ///
    /// Operators who need finer-grained control build [`ApprovalThresholds`]
    /// explicitly and pass it to [`ApprovalPolicy::from_thresholds`].
    #[must_use]
    pub fn from_engagement_config(cfg: &EngagementConfig) -> Self {
        let default = map_config_intensity(cfg.default_intensity);
        let baseline = 1_u32;
        let elevated = 2_u32;
        let critical = 3_u32;
        let pick = |i: ScanIntensity| -> u32 {
            if i == ScanIntensity::RedTeam {
                critical
            } else if i > default {
                elevated
            } else {
                baseline
            }
        };
        Self {
            theoretical: pick(ScanIntensity::Theoretical),
            passive_validation: pick(ScanIntensity::PassiveValidation),
            safe_interactive: pick(ScanIntensity::SafeInteractive),
            active_exploit: pick(ScanIntensity::ActiveExploit),
            red_team: pick(ScanIntensity::RedTeam),
        }
    }
}

/// Maps the config-layer `Intensity` enum onto the domain `ScanIntensity`.
const fn map_config_intensity(i: sx_config::schema::engagement::Intensity) -> ScanIntensity {
    match i {
        sx_config::schema::engagement::Intensity::Passive => ScanIntensity::PassiveValidation,
        sx_config::schema::engagement::Intensity::Light
        | sx_config::schema::engagement::Intensity::Normal => ScanIntensity::SafeInteractive,
        sx_config::schema::engagement::Intensity::Aggressive => ScanIntensity::ActiveExploit,
    }
}

/// Policy object built once per use-case invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalPolicy {
    /// Required number of unique approvers.
    pub required_count: u32,
}

impl ApprovalPolicy {
    /// Build from a known intensity + config.
    #[must_use]
    pub fn from_intensity(intensity: ScanIntensity, cfg: &EngagementConfig) -> Self {
        let thresholds = ApprovalThresholds::from_engagement_config(cfg);
        Self {
            required_count: thresholds.for_intensity(intensity),
        }
    }

    /// Build from an explicit `ApprovalThresholds` set.
    #[must_use]
    pub const fn from_thresholds(intensity: ScanIntensity, t: &ApprovalThresholds) -> Self {
        Self {
            required_count: t.for_intensity(intensity),
        }
    }

    /// Returns `true` iff the approval ledger contains at least
    /// `required_count` distinct approvers.
    #[must_use]
    pub fn met(self, approvals: &[EngagementApproval]) -> bool {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for a in approvals {
            seen.insert(a.approver);
            if u32::try_from(seen.len()).unwrap_or(u32::MAX) >= self.required_count {
                return true;
            }
        }
        self.required_count == 0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sx_config::schema::engagement::{DenylistEntry, EngagementConfig, Intensity};
    use sx_core::value_object::ids::UserId;
    use time::OffsetDateTime;

    fn cfg(default: Intensity) -> EngagementConfig {
        EngagementConfig {
            max_concurrent: 4,
            default_intensity: default,
            kill_switch_channel: "sx:kill".into(),
            killswitch_watchdog_interval: std::time::Duration::from_secs(5),
            global_denylist: Vec::<DenylistEntry>::new(),
        }
    }

    fn approval() -> EngagementApproval {
        EngagementApproval::new(UserId::new(), OffsetDateTime::UNIX_EPOCH)
    }

    #[test]
    fn red_team_requires_at_least_three() {
        let c = cfg(Intensity::Aggressive);
        let p = ApprovalPolicy::from_intensity(ScanIntensity::RedTeam, &c);
        assert_eq!(p.required_count, 3);
    }

    #[test]
    fn intensity_above_default_requires_two() {
        let c = cfg(Intensity::Passive);
        let p = ApprovalPolicy::from_intensity(ScanIntensity::SafeInteractive, &c);
        assert_eq!(p.required_count, 2);
    }

    #[test]
    fn intensity_at_or_below_default_requires_one() {
        let c = cfg(Intensity::Aggressive);
        let p = ApprovalPolicy::from_intensity(ScanIntensity::SafeInteractive, &c);
        assert_eq!(p.required_count, 1);
    }

    #[test]
    fn met_counts_unique_approvers() {
        let p = ApprovalPolicy { required_count: 2 };
        let a1 = approval();
        let a2 = approval();
        let dup = EngagementApproval::new(a1.approver, OffsetDateTime::UNIX_EPOCH);
        // a1 and a duplicate -> only one unique approver
        assert!(!p.met(&[a1.clone(), dup]));
        // a1 + a2 -> two unique
        assert!(p.met(&[a1, a2]));
    }

    #[test]
    fn zero_threshold_is_always_met() {
        let p = ApprovalPolicy { required_count: 0 };
        assert!(p.met(&[]));
    }
}
