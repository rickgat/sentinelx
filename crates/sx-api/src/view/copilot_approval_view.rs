//! Copilot human-in-loop approval DTOs (P1-012).
//!
//! Wire-shape request and response types for:
//!
//! - `GET  /v1/copilot/approvals`                — list pending approvals
//! - `POST /v1/copilot/approvals/{token}/decide` — approve or reject
//!
//! The view layer intentionally projects the domain types in
//! [`sx_collab::copilot_approval`] into JSON-friendly fields so the public
//! schema stays decoupled from the in-crate storage shape. The action
//! payload itself is forwarded verbatim as an opaque `serde_json::Value`
//! — the dashboard renders it as a labelled card, not by introspecting
//! variant kinds.

use serde::{Deserialize, Serialize};
use sx_collab::copilot_approval::{
    ApprovalSnapshot, ApprovalStatus, ApprovalToken, CopilotProposer, Decision, DecisionOutcome,
    PendingApproval, ProposedAction,
};
use validator::Validate;

/// Single pending approval entry returned by `GET /v1/copilot/approvals`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingApprovalView {
    /// Opaque approval token (UUID hyphenated). Quoted on the decide URL.
    pub token: String,
    /// Tenant the approval is scoped to. Echoed for symmetry with the
    /// audit chain — the dashboard already knows the value.
    pub tenant_id: String,
    /// Stable machine-readable code for the action variant — e.g.
    /// `run_bas_technique`, `apply_remediation`, `change_safety_policy`.
    pub action_kind: String,
    /// Full action body. Forwarded as raw JSON so the API stays
    /// resilient to future variants of the [`ProposedAction`] enum.
    pub action: serde_json::Value,
    /// Proposer code (e.g. `copilot:claude-3-5-sonnet-latest`, `autonomy`,
    /// or the custom code).
    pub proposer: String,
    /// Current status — always `"pending"` on this list.
    pub status: String,
    /// RFC 3339 timestamp the proposal was recorded.
    pub proposed_at: String,
    /// RFC 3339 timestamp the proposal will auto-expire.
    pub expires_at: String,
}

impl PendingApprovalView {
    /// Project a [`PendingApproval`] into the wire shape.
    #[must_use]
    pub fn from_domain(p: PendingApproval) -> Self {
        let action_kind = p.action.kind_code().to_owned();
        let action = serde_json::to_value(&p.action)
            .unwrap_or_else(|_| serde_json::json!({ "kind": action_kind }));
        Self {
            token: p.token.as_string(),
            tenant_id: p.tenant_id.0,
            action_kind,
            action,
            proposer: proposer_code(&p.proposer),
            status: p.status.as_str().to_owned(),
            proposed_at: p.proposed_at,
            expires_at: p.expires_at,
        }
    }
}

/// `GET /v1/copilot/approvals` response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingApprovalListView {
    /// Pending approvals scoped to the caller's tenant, oldest-first.
    pub items: Vec<PendingApprovalView>,
}

/// `POST /v1/copilot/approvals/{token}/decide` request body.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, PartialEq, Eq)]
pub struct DecideApprovalRequest {
    /// Reviewer decision — `"approve"` or `"reject"`.
    #[validate(length(min = 1, max = 16))]
    pub decision: String,
    /// Required when `decision == "reject"`; ignored on approve. The
    /// service refuses an empty reason on reject (see
    /// [`sx_collab::copilot_approval::CopilotApprovalError::ReasonRequired`]).
    #[validate(length(max = 1024))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl DecideApprovalRequest {
    /// Parse the decision string into the domain [`Decision`] enum.
    ///
    /// Returns [`None`] on a malformed value; the controller surfaces this
    /// as HTTP 422.
    #[must_use]
    pub fn parse_decision(&self) -> Option<Decision> {
        match self.decision.as_str() {
            "approve" => Some(Decision::Approve),
            "reject" => Some(Decision::Reject),
            _ => None,
        }
    }
}

/// `POST /v1/copilot/approvals/{token}/decide` response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionOutcomeView {
    /// The decided token.
    pub token: String,
    /// Terminal status — `"approved"` or `"rejected"`.
    pub status: String,
    /// Reviewer that decided (uuid-shaped string).
    pub reviewer: String,
    /// Reviewer rationale, when supplied (required for reject).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// RFC 3339 timestamp the decision was recorded.
    pub decided_at: String,
}

impl DecisionOutcomeView {
    /// Project the domain outcome into the wire shape.
    #[must_use]
    pub fn from_domain(o: DecisionOutcome) -> Self {
        Self {
            token: o.token.as_string(),
            status: o.status.as_str().to_owned(),
            reviewer: o.reviewer.0,
            reason: o.reason,
            decided_at: o.decided_at,
        }
    }
}

/// Full snapshot of an approval — pending or terminal. Used by the
/// pending-approval banner on the copilot chat page so the dashboard can
/// surface the proposed action without hitting `list_pending` again.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalSnapshotView {
    /// Token.
    pub token: String,
    /// Tenant.
    pub tenant_id: String,
    /// Action kind code.
    pub action_kind: String,
    /// Full action body.
    pub action: serde_json::Value,
    /// Proposer code.
    pub proposer: String,
    /// Current status.
    pub status: String,
    /// RFC 3339 timestamp the proposal was recorded.
    pub proposed_at: String,
    /// RFC 3339 timestamp the proposal will auto-expire.
    pub expires_at: String,
    /// RFC 3339 timestamp the reviewer decided; absent until then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<String>,
    /// Reviewer that decided; absent until then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    /// Reviewer reason; absent unless supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ApprovalSnapshotView {
    /// Project the domain snapshot into the wire shape.
    #[must_use]
    pub fn from_domain(s: ApprovalSnapshot) -> Self {
        let action_kind = s.action.kind_code().to_owned();
        let action = serde_json::to_value(&s.action)
            .unwrap_or_else(|_| serde_json::json!({ "kind": action_kind }));
        Self {
            token: s.token.as_string(),
            tenant_id: s.tenant_id.0,
            action_kind,
            action,
            proposer: proposer_code(&s.proposer),
            status: s.status.as_str().to_owned(),
            proposed_at: s.proposed_at,
            expires_at: s.expires_at,
            decided_at: s.decided_at,
            decided_by: s.decided_by.map(|u| u.0),
            reason: s.reason,
        }
    }
}

/// Stable wire form for a proposer. Mirrors the snake_case serde tag the
/// domain enum already uses. The enum is `#[non_exhaustive]`, so a
/// future variant degrades to a stable `"unknown"` code rather than
/// failing the projection.
fn proposer_code(p: &CopilotProposer) -> String {
    match p {
        CopilotProposer::Copilot { model } => format!("copilot:{model}"),
        CopilotProposer::Autonomy => "autonomy".to_owned(),
        CopilotProposer::Custom { code } => code.clone(),
        _ => "unknown".to_owned(),
    }
}

/// Chat response carrying an optional pending-approval token.
///
/// Returned by the copilot chat adapter whenever a state-changing action
/// is queued for approval instead of being executed inline. The shape
/// mirrors [`crate::view::copilot_view::CopilotChatResponse`] so the
/// dashboard's existing chat surface can re-use the same envelope, with
/// the extra `pending_approval` field carrying the token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CopilotChatWithApprovalResponse {
    /// Assistant reply text.
    pub reply: String,
    /// Model identifier that produced the reply.
    pub model: String,
    /// Token the reviewer must approve / reject before the action runs.
    /// Absent when the reply did not propose a state-changing action.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_approval: Option<PendingApprovalView>,
}

/// Convenience: borrow-checker friendly accessor for the [`ApprovalToken`]
/// path parameter parser. Returns [`None`] on a malformed token.
#[must_use]
pub fn parse_token(s: &str) -> Option<ApprovalToken> {
    ApprovalToken::parse(s)
}

/// Wire string for the [`ApprovalStatus`] enum — kept as a free helper so
/// the dashboard test harness can stitch up minimal fixtures without
/// depending on `sx-collab`.
#[must_use]
pub const fn status_str(s: ApprovalStatus) -> &'static str {
    s.as_str()
}

/// Wire string used for the action `kind` discriminator. Re-exported so
/// dashboard fixtures can keep parity with the service's wire schema.
#[must_use]
pub const fn action_kind_code(a: &ProposedAction) -> &'static str {
    a.kind_code()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sx_collab::copilot_approval::{
        ApprovalToken, CopilotProposer, ProposedAction, TenantScope, UserId,
    };

    fn sample_pending() -> PendingApproval {
        PendingApproval {
            token: ApprovalToken::new_random(),
            tenant_id: TenantScope("00000000-0000-0000-0000-000000000001".to_owned()),
            proposer: CopilotProposer::Copilot {
                model: "claude-3-5-sonnet-latest".to_owned(),
            },
            action: ProposedAction::ApplyRemediation {
                finding_id: "f-1".to_owned(),
                vendor: "redhat".to_owned(),
                change_payload: serde_json::json!({ "rhsa": "RHSA-2024-0001" }),
            },
            status: ApprovalStatus::Pending,
            proposed_at: "2026-06-12T00:00:00Z".to_owned(),
            expires_at: "2026-06-12T01:00:00Z".to_owned(),
        }
    }

    #[test]
    fn pending_view_projects_action_kind_code() {
        let view = PendingApprovalView::from_domain(sample_pending());
        assert_eq!(view.action_kind, "apply_remediation");
        assert_eq!(view.status, "pending");
        assert!(view.proposer.starts_with("copilot:"));
    }

    #[test]
    fn decision_parsing_round_trips() {
        let approve = DecideApprovalRequest {
            decision: "approve".into(),
            reason: None,
        };
        assert!(matches!(approve.parse_decision(), Some(Decision::Approve)));
        let reject = DecideApprovalRequest {
            decision: "reject".into(),
            reason: Some("noise".into()),
        };
        assert!(matches!(reject.parse_decision(), Some(Decision::Reject)));
        let bogus = DecideApprovalRequest {
            decision: "shrug".into(),
            reason: None,
        };
        assert!(bogus.parse_decision().is_none());
    }

    #[test]
    fn decision_outcome_view_projects_status() {
        let outcome = DecisionOutcome {
            token: ApprovalToken::new_random(),
            status: ApprovalStatus::Rejected,
            reviewer: UserId("reviewer-1".to_owned()),
            reason: Some("noise".to_owned()),
            decided_at: "2026-06-12T00:30:00Z".to_owned(),
        };
        let view = DecisionOutcomeView::from_domain(outcome);
        assert_eq!(view.status, "rejected");
        assert_eq!(view.reason.as_deref(), Some("noise"));
    }

    #[test]
    fn parse_token_rejects_garbage() {
        assert!(parse_token("not-a-uuid").is_none());
        let t = ApprovalToken::new_random();
        assert_eq!(parse_token(&t.as_string()).unwrap(), t);
    }

    #[test]
    fn snapshot_view_round_trips() {
        let snap = ApprovalSnapshot {
            token: ApprovalToken::new_random(),
            tenant_id: TenantScope("t".into()),
            proposer: CopilotProposer::Autonomy,
            action: ProposedAction::ChangeSafetyPolicy {
                policy_diff: serde_json::json!({ "patch": [] }),
            },
            status: ApprovalStatus::Approved,
            proposed_at: "2026-06-12T00:00:00Z".into(),
            expires_at: "2026-06-12T01:00:00Z".into(),
            decided_at: Some("2026-06-12T00:30:00Z".into()),
            decided_by: Some(UserId("u-1".into())),
            reason: None,
            audit_trail: vec![],
        };
        let view = ApprovalSnapshotView::from_domain(snap);
        assert_eq!(view.action_kind, "change_safety_policy");
        assert_eq!(view.proposer, "autonomy");
        assert_eq!(view.decided_by.as_deref(), Some("u-1"));
    }

    #[test]
    fn validates_oversized_reason() {
        let req = DecideApprovalRequest {
            decision: "reject".into(),
            reason: Some("a".repeat(1025)),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn validates_well_formed_request() {
        let req = DecideApprovalRequest {
            decision: "approve".into(),
            reason: None,
        };
        assert!(req.validate().is_ok());
    }
}
