//! Synthetic-finding helpers (TOP5-#3-P2-005).
//!
//! Pure, IO-free helpers used by the monolith RBA adapter to project an
//! [`crate::service::RbaDecision`] onto the `description` body of the
//! synthetic Finding emitted when emission is enabled and the decision
//! breaches the operator-set threshold.
//!
//! Keeping the projection here (vs. the monolith adapter) means:
//!
//! * The signal-breakdown vocabulary (signal_kind names, ordering)
//!   stays under the same module that mints the decision.
//! * Unit-test coverage on the description body lives next to the
//!   scorer it observes.
//! * Downstream emitters that grow later (e.g. dashboard "explain this
//!   block" panel) can reuse the same formatter without re-implementing
//!   it.

use crate::scorer::SignalContribution;
use crate::service::RbaDecision;

/// The legacy colon-form `check_id` / `rule_id` for every high-risk RBA
/// Block decision. Mirrors
/// [`sx_core::reference::rba_block_enrichment::RBA_HIGH_RISK_BLOCK_CHECK_ID`]
/// — kept duplicated here on purpose so the engine crate stays free of
/// a circular dependency on `sx-core`'s reference tables. A unit test in
/// the monolith integration crate guards them against drift.
///
/// Retained for backward-compat receive-side lookups; emitters have
/// migrated to [`RBA_HIGH_RISK_BLOCK_DOTTED`] (TOP5-#3 Phase 3).
pub const RBA_HIGH_RISK_BLOCK_CHECK_ID: &str = "rba:high-risk-block";

/// Canonical dotted-form `check_id` / `rule_id` for every high-risk RBA
/// Block decision (TOP5-#3 Phase 3). Mirrors
/// [`sx_core::reference::rba_block_enrichment::RBA_HIGH_RISK_BLOCK_DOTTED`]
/// — duplicated locally so the engine crate stays free of a circular
/// dependency on `sx-core`'s reference tables. Guarded against drift by
/// [`check_id_dotted_constant_matches_reference_table`] in tests.
pub const RBA_HIGH_RISK_BLOCK_DOTTED: &str = "RBA.HIGH_RISK_BLOCK";

/// Build the human-readable Finding description for a Block decision.
///
/// Format (deterministic so SOC dashboards can pattern-match):
///
/// ```text
/// Risk-based authentication blocked sign-in for tenant <uuid> user <uuid|anon>
/// from IP <ipv4>. Composite score: 82/100 (threshold: 75). Reason: <reason>.
/// Signal breakdown: ip_geo=80 (weight 0.20), velocity=60 (weight 0.15), ...
/// ```
///
/// Any user-facing field that may be `None` (the `user_id` in particular —
/// failed credential lookups never resolve a user id) renders as
/// `"anonymous"`. The decision's `reason` is reproduced verbatim because
/// it is itself a curated, non-PII string emitted by the scorer.
#[must_use]
pub fn block_decision_description(decision: &RbaDecision, emission_threshold: u8) -> String {
    let user = decision
        .user_id
        .map_or_else(|| "anonymous".to_owned(), |u| u.to_string());
    let mut buf = format!(
        "Risk-based authentication blocked sign-in for tenant {tenant} user {user} \
         from IP {ip}. Composite score: {score}/100 (threshold: {threshold}). Reason: {reason}.",
        tenant = decision.tenant_id,
        user = user,
        ip = decision.ip,
        score = decision.score,
        threshold = emission_threshold,
        reason = decision.reason,
    );
    if !decision.signal_contributions.is_empty() {
        buf.push_str(" Signal breakdown: ");
        buf.push_str(&format_signal_breakdown(&decision.signal_contributions));
        buf.push('.');
    }
    buf
}

/// Format the per-signal contribution rows into a stable, comma-separated
/// string. Iteration order follows the scorer's emitted order so the
/// SOC can correlate the breakdown back to the audit row.
fn format_signal_breakdown(contributions: &[SignalContribution]) -> String {
    contributions
        .iter()
        .map(|c| {
            format!(
                "{name}={sub} (weight {weight:.2})",
                name = c.signal.as_str(),
                sub = c.sub_score,
                weight = c.weight,
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;

    use time::macros::datetime;
    use uuid::Uuid;

    use super::*;
    use crate::baseline::BaselinePhase;
    use crate::scorer::SignalContribution;
    use crate::service::{RbaAction, RbaDecision, SignalSnapshot};
    use crate::signals::SignalKind;

    fn decision_with(
        score: i32,
        user_id: Option<Uuid>,
        contributions: Vec<SignalContribution>,
    ) -> RbaDecision {
        RbaDecision {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            user_id,
            ip: Ipv4Addr::new(203, 0, 113, 7),
            score,
            action: RbaAction::Block,
            signals: HashMap::new(),
            snapshot: SignalSnapshot::default(),
            signal_contributions: contributions,
            reason: "burst from unknown country".to_owned(),
            baseline_phase: BaselinePhase::Active,
            decided_at: datetime!(2026-06-25 04:00:00 UTC),
        }
    }

    #[test]
    fn description_includes_score_threshold_and_reason() {
        let d = decision_with(82, Some(Uuid::nil()), vec![]);
        let s = block_decision_description(&d, 75);
        assert!(s.contains("Composite score: 82/100"));
        assert!(s.contains("threshold: 75"));
        assert!(s.contains("burst from unknown country"));
        assert!(s.contains("blocked sign-in"));
    }

    #[test]
    fn description_renders_anonymous_for_missing_user_id() {
        let d = decision_with(80, None, vec![]);
        let s = block_decision_description(&d, 75);
        assert!(s.contains("user anonymous"), "got: {s}");
    }

    #[test]
    fn description_includes_signal_breakdown_when_present() {
        let contributions = vec![
            SignalContribution {
                signal: SignalKind::IpGeo,
                sub_score: 80,
                weight: 0.20,
                weighted: 16.0,
            },
            SignalContribution {
                signal: SignalKind::Velocity,
                sub_score: 60,
                weight: 0.15,
                weighted: 9.0,
            },
        ];
        let d = decision_with(80, Some(Uuid::nil()), contributions);
        let s = block_decision_description(&d, 75);
        assert!(s.contains("Signal breakdown:"));
        assert!(s.contains("ip_geo=80"));
        assert!(s.contains("velocity=60"));
        assert!(s.contains("weight 0.20"));
    }

    #[test]
    fn description_omits_breakdown_section_when_no_contributions() {
        let d = decision_with(82, Some(Uuid::nil()), vec![]);
        let s = block_decision_description(&d, 75);
        assert!(!s.contains("Signal breakdown:"));
    }

    #[test]
    fn check_id_constant_is_canonical() {
        // Guard against an accidental rename — the string is the
        // metadata.rule_id contract value persisted to the findings
        // table.
        assert_eq!(RBA_HIGH_RISK_BLOCK_CHECK_ID, "rba:high-risk-block");
        // TOP5-#3 Phase 3 dotted form — the new canonical emit shape.
        assert_eq!(RBA_HIGH_RISK_BLOCK_DOTTED, "RBA.HIGH_RISK_BLOCK");
        // Every fresh emit must contain a `.` per the Phase 3 rule.
        assert!(RBA_HIGH_RISK_BLOCK_DOTTED.contains('.'));
    }
}
