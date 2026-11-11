//! Dual-approval gate.
//!
//! - `Theoretical`, `PassiveValidation`, `SafeInteractive` require **no**
//!   approvals.
//! - `ActiveExploit` requires **≥ 2** distinct approvers AND a non-expired
//!   Rules-of-Engagement artifact.
//! - `RedTeam` requires **≥ 3** distinct approvers AND a non-expired RoE.
//!
//! Counts come from [`crate::model::mode::AttackMode::required_approvals`];
//! callers needing tenant-specific tuning supply their own
//! [`crate::model::approval::ApprovalPolicy`] directly.

use time::OffsetDateTime;
use tracing::warn;

use crate::error::BasError;
use crate::model::approval::{Approval, ApprovalPolicy, RulesOfEngagement};
use crate::model::mode::AttackMode;

/// Stateless dual-approval gate.
#[derive(Debug, Default, Clone, Copy)]
pub struct DualApprovalGate;

impl DualApprovalGate {
    /// Construct the gate.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Evaluate the gate against the conservative defaults for `mode`.
    pub fn evaluate(
        self,
        engagement_id: &str,
        technique_id: &str,
        mode: AttackMode,
        approvals: &[Approval],
        roe: Option<&RulesOfEngagement>,
        now: OffsetDateTime,
    ) -> Result<(), BasError> {
        self.evaluate_with_policy(
            engagement_id,
            technique_id,
            mode,
            ApprovalPolicy::for_mode(mode),
            approvals,
            roe,
            now,
        )
    }

    /// Evaluate against an explicit policy. Useful when callers override the
    /// default threshold via configuration.
    // `self` is intentionally a stateless gate token so the call site reads
    // as `gate.evaluate_with_policy(...)`; cognitive complexity reflects the
    // number of distinct denial reasons, not real branching depth.
    #[allow(
        clippy::too_many_arguments,
        clippy::unused_self,
        clippy::cognitive_complexity
    )]
    pub fn evaluate_with_policy(
        self,
        engagement_id: &str,
        technique_id: &str,
        mode: AttackMode,
        policy: ApprovalPolicy,
        approvals: &[Approval],
        roe: Option<&RulesOfEngagement>,
        now: OffsetDateTime,
    ) -> Result<(), BasError> {
        // Distinct-approver count for telemetry / error rendering.
        let distinct = distinct_approver_count(approvals);

        if !policy.met(approvals) {
            warn!(
                target = "sx_bas::gate",
                gate = "approval",
                engagement_id = engagement_id,
                technique_id = technique_id,
                mode = %mode,
                have = distinct,
                need = policy.required_count,
                reason = "insufficient distinct approvers",
                "approval gate denied",
            );
            return Err(BasError::ApprovalsInsufficient {
                have: distinct,
                need: policy.required_count,
            });
        }

        if mode.requires_roe_and_change_window() {
            let Some(roe) = roe else {
                warn!(
                    target = "sx_bas::gate",
                    gate = "approval",
                    engagement_id = engagement_id,
                    technique_id = technique_id,
                    mode = %mode,
                    reason = "active mode requires RoE but none supplied",
                    "approval gate denied",
                );
                return Err(BasError::roe_invalid("missing RoE for active mode"));
            };
            if !roe.is_valid_at(now) {
                warn!(
                    target = "sx_bas::gate",
                    gate = "approval",
                    engagement_id = engagement_id,
                    technique_id = technique_id,
                    mode = %mode,
                    reason = "RoE expired or not yet active",
                    "approval gate denied",
                );
                return Err(BasError::roe_invalid("RoE expired or not yet active"));
            }
        }

        Ok(())
    }
}

fn distinct_approver_count(approvals: &[Approval]) -> u32 {
    use std::collections::HashSet;
    let mut seen = HashSet::with_capacity(approvals.len());
    for a in approvals {
        seen.insert(a.approver);
    }
    u32::try_from(seen.len()).unwrap_or(u32::MAX)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::DualApprovalGate;
    use crate::error::BasError;
    use crate::model::approval::{Approval, RulesOfEngagement};
    use crate::model::mode::AttackMode;
    use sx_core::value_object::ids::UserId;
    use time::{Duration, OffsetDateTime};

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::hours(1)
    }

    fn valid_roe() -> RulesOfEngagement {
        RulesOfEngagement::new(
            UserId::new(),
            OffsetDateTime::UNIX_EPOCH,
            now() + Duration::hours(1),
        )
        .unwrap()
    }

    fn approval() -> Approval {
        Approval::new(UserId::new(), OffsetDateTime::UNIX_EPOCH)
    }

    #[test]
    fn approval_gate_denies_active_exploit_with_single_approver() {
        let g = DualApprovalGate::new();
        let approvals = vec![approval()];
        let roe = valid_roe();
        let err = g
            .evaluate(
                "e1",
                "t1",
                AttackMode::ActiveExploit,
                &approvals,
                Some(&roe),
                now(),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            BasError::ApprovalsInsufficient { have: 1, need: 2 }
        ));
    }

    #[test]
    fn approval_gate_allows_active_exploit_with_two_approvers() {
        let g = DualApprovalGate::new();
        let approvals = vec![approval(), approval()];
        let roe = valid_roe();
        assert!(g
            .evaluate(
                "e1",
                "t1",
                AttackMode::ActiveExploit,
                &approvals,
                Some(&roe),
                now(),
            )
            .is_ok());
    }

    #[test]
    fn approval_gate_red_team_requires_three_approvers() {
        let g = DualApprovalGate::new();
        let two = vec![approval(), approval()];
        let three = vec![approval(), approval(), approval()];
        let roe = valid_roe();
        // Two approvers: rejected for RedTeam.
        let err = g
            .evaluate("e1", "t1", AttackMode::RedTeam, &two, Some(&roe), now())
            .unwrap_err();
        assert!(matches!(
            err,
            BasError::ApprovalsInsufficient { have: 2, need: 3 }
        ));
        // Three: accepted.
        assert!(g
            .evaluate("e1", "t1", AttackMode::RedTeam, &three, Some(&roe), now())
            .is_ok());
    }

    #[test]
    fn approval_gate_safe_modes_pass_without_approvals() {
        let g = DualApprovalGate::new();
        for m in [
            AttackMode::Theoretical,
            AttackMode::PassiveValidation,
            AttackMode::SafeInteractive,
        ] {
            assert!(g.evaluate("e1", "t1", m, &[], None, now()).is_ok());
        }
    }

    #[test]
    fn approval_gate_active_mode_requires_roe() {
        let g = DualApprovalGate::new();
        let approvals = vec![approval(), approval()];
        let err = g
            .evaluate(
                "e1",
                "t1",
                AttackMode::ActiveExploit,
                &approvals,
                None,
                now(),
            )
            .unwrap_err();
        assert!(matches!(err, BasError::RoeInvalid(_)));
    }

    #[test]
    fn approval_gate_rejects_expired_roe() {
        let g = DualApprovalGate::new();
        let approvals = vec![approval(), approval()];
        // RoE that expires at `now`.
        let signed = OffsetDateTime::UNIX_EPOCH;
        let expires = now();
        let roe = RulesOfEngagement::new(UserId::new(), signed, expires).unwrap();
        let err = g
            .evaluate(
                "e1",
                "t1",
                AttackMode::ActiveExploit,
                &approvals,
                Some(&roe),
                now(),
            )
            .unwrap_err();
        assert!(matches!(err, BasError::RoeInvalid(_)));
    }
}
