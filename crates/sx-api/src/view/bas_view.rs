//! Breach-and-Attack-Simulation (BAS) DTOs.
//!
//! These are wire-shape types only — they hold strings on purpose so the
//! API crate never has to depend on the concrete enums in `sx-bas`. The
//! string-shaped `mode` field is validated against the three modes the
//! HTTP surface understands (`theoretical`, `safe_interactive`,
//! `active_exploit`). The boundary gate in `controller::bas` decides which
//! of those modes actually reach the orchestrator.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /v1/bas/run` request body.
///
/// At the HTTP layer the orchestrator accepts `theoretical` and
/// `safe_interactive`; `active_exploit` is reserved for a separate
/// approval flow and is rejected by the boundary gate (see
/// `controller::bas::validate_http_mode`). The DTO validator only
/// confirms the string is one of the three known mode names — semantic
/// gating happens in the controller.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct BasRunRequestView {
    /// MITRE ATT&CK technique identifier, e.g. `T1003`.
    #[validate(length(min = 1))]
    pub technique_id: String,
    /// Free-form target reference (engagement scope, asset uuid, FQDN, …).
    #[validate(length(min = 1))]
    pub target: String,
    /// Attack mode. Must parse to one of the three known snake-case modes
    /// (`theoretical`, `safe_interactive`, `active_exploit`).
    #[validate(custom(function = "validate_bas_mode"))]
    pub mode: String,
    /// When `true` the run is a no-op simulation. Defaults to `false` when
    /// absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
    /// Engagement uuid the run is bound to. Optional on the wire because the
    /// existing `theoretical` workflow does not require it, but the
    /// two-person rule for `safe_interactive` MUST resolve approvals against
    /// a known engagement. The controller rejects requests that omit it for
    /// `safe_interactive`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(custom(function = "validate_optional_uuid"))]
    pub engagement_id: Option<String>,
}

/// `POST /v1/bas/run` response body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BasRunResponseView {
    /// Simulation uuid the caller can use to poll for evidence.
    pub simulation_id: String,
    /// Coarse outcome: `simulated`, `blocked`, or `killed`.
    pub outcome: String,
    /// Number of evidence artifacts emitted by the run.
    pub evidence_count: u32,
}

/// `POST /v1/bas/approvals` request body.
///
/// Operators record their approval against a specific
/// `(engagement_id, technique_id, approver_email)` tuple. The adapter is
/// idempotent on this tuple — re-submitting the same approval returns a
/// conflict so the caller knows nothing changed.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct RecordApprovalRequest {
    /// Engagement uuid the approval covers.
    #[validate(custom(function = "validate_uuid"))]
    pub engagement_id: String,
    /// MITRE ATT&CK technique id the approval targets.
    #[validate(length(min = 1, max = 64))]
    pub technique_id: String,
    /// Approver's email — used as the distinct-count key in the two-person
    /// rule. Normalised lowercase by the adapter.
    #[validate(email)]
    pub approver_email: String,
    /// Free-form rationale recorded for the audit log.
    #[validate(length(min = 1, max = 1024))]
    pub reason: String,
}

/// One approval row on the wire.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ApprovalView {
    /// Engagement uuid the approval covers.
    pub engagement_id: String,
    /// Technique id the approval targets.
    pub technique_id: String,
    /// Approver's normalised email.
    pub approver_email: String,
    /// Free-form rationale recorded by the approver.
    pub reason: String,
    /// RFC 3339 timestamp the adapter stamped at record time.
    pub recorded_at: String,
}

/// One persisted BAS run history entry.
///
/// Records every `POST /v1/bas/run` outcome so operators can audit what
/// was executed against which target across reloads. Stored newest-first
/// by the in-memory adapter.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct BasRunHistoryView {
    /// Simulation uuid returned by the orchestrator.
    pub simulation_id: String,
    /// Tenant the run belongs to.
    pub tenant_id: String,
    /// Optional engagement context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engagement_id: Option<String>,
    /// MITRE ATT&CK technique id the run targeted.
    pub technique_id: String,
    /// Free-form target string supplied by the caller.
    pub target: String,
    /// Attack mode used (`theoretical`, `safe_interactive`, …).
    pub mode: String,
    /// `true` when the run was a no-op simulation.
    pub dry_run: bool,
    /// Coarse outcome (`simulated`, `denied`, `blocked`, …).
    pub outcome: String,
    /// Number of evidence artifacts emitted by the run.
    pub evidence_count: u32,
    /// RFC 3339 timestamp the run was recorded.
    pub created_at: String,
}

/// `GET /v1/bas/runs` response body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListBasRunsResponse {
    /// Runs matching the query, ordered newest-first.
    pub items: Vec<BasRunHistoryView>,
}

/// `GET /v1/bas/approvals` response body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListApprovalsResponse {
    /// Approvals matching the query, ordered oldest-first.
    pub items: Vec<ApprovalView>,
}

// ---------------------------------------------------------------------------
// P2-015 — Lateral-movement chain replay views.
// ---------------------------------------------------------------------------

/// One step in a [`LateralChainView`].
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ChainStepView {
    /// Registry id of the technique (e.g. `"t1021_remote_services_v1"`).
    pub technique_id: String,
    /// MITRE ATT&CK technique id for display (e.g. `"T1021"`).
    pub mitre_id: String,
    /// Human-readable step label.
    pub display_name: String,
    /// `true` when failing this step terminates the chain.
    pub kill_on_failure: bool,
}

/// Pre-canned lateral-movement chain catalogue entry.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct LateralChainView {
    /// Stable chain id (e.g. `"ransomware_style_v1"`).
    pub id: String,
    /// Display name.
    pub name: String,
    /// One-sentence intent description.
    pub description: String,
    /// Ordered steps.
    pub steps: Vec<ChainStepView>,
}

/// `GET /v1/bas/chains` response body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListChainsResponse {
    /// Pre-canned chains available to this tenant.
    pub items: Vec<LateralChainView>,
}

/// `POST /v1/bas/chains/{id}/run` request body.
///
/// `engagement_id` is mandatory: chain runs always inherit the engagement's
/// safety stance (two-person approvals, RoE, change window) just like
/// single-technique runs.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct StartChainRunRequest {
    /// Engagement uuid the chain is bound to.
    #[validate(custom(function = "validate_uuid"))]
    pub engagement_id: String,
    /// Attack mode the chain runs at. Validated against the same set as
    /// [`BasRunRequestView::mode`].
    #[validate(custom(function = "validate_bas_mode"))]
    pub mode: String,
    /// Optional free-form note recorded in the audit log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 1024))]
    pub note: Option<String>,
}

/// One step record returned in [`ChainRunView`].
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ChainStepRecordView {
    /// Zero-based step index in the originating chain.
    pub step_index: u32,
    /// Registry id of the technique that ran.
    pub technique_id: String,
    /// MITRE ATT&CK id for display.
    pub mitre_id: String,
    /// `"success"`, `"failure"`, or `"skipped"`.
    pub status: String,
    /// Free-text evidence summary.
    pub evidence: String,
}

/// `POST /v1/bas/chains/{id}/run` and `GET /v1/bas/chains/runs/{id}`
/// response body.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ChainRunView {
    /// Unique run id (UUID v4 as string).
    pub run_id: String,
    /// Tenant the run belongs to.
    pub tenant_id: String,
    /// Engagement uuid the run is bound to.
    pub engagement_id: String,
    /// Chain id that produced this run.
    pub chain_id: String,
    /// Top-level status: `"running"`, `"completed"`, `"failed"`,
    /// `"aborted"`.
    pub status: String,
    /// Per-step records in the order steps were attempted.
    pub steps: Vec<ChainStepRecordView>,
    /// RFC 3339 start timestamp.
    pub started_at: String,
    /// RFC 3339 finish timestamp (only set when `status != "running"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,
}

/// Validate that `value` is one of the three known BAS mode strings.
///
/// We re-implement the string match inline rather than depend on
/// [`sx_bas::AttackMode::FromStr`] so this validator does not pull
/// `sx-bas` into every compilation unit that touches the view.
fn validate_bas_mode(v: &str) -> Result<(), validator::ValidationError> {
    match v {
        "theoretical" | "safe_interactive" | "active_exploit" => Ok(()),
        _ => Err(validator::ValidationError::new("invalid_mode")),
    }
}

/// Validate that `value` is a canonical UUID string.
fn validate_uuid(value: &str) -> Result<(), validator::ValidationError> {
    uuid::Uuid::parse_str(value).map_err(|_| validator::ValidationError::new("invalid_uuid"))?;
    Ok(())
}

/// Validate that `value`, when present, is a canonical UUID string. The
/// validator runs against the inner `&str` because `validator` derives
/// already skip `None`.
fn validate_optional_uuid(value: &str) -> Result<(), validator::ValidationError> {
    validate_uuid(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_bas_mode_accepts_three_known_values() {
        for m in ["theoretical", "safe_interactive", "active_exploit"] {
            assert!(validate_bas_mode(m).is_ok(), "should accept {m}");
        }
    }

    #[test]
    fn validate_bas_mode_rejects_garbage() {
        assert!(validate_bas_mode("yolo").is_err());
        assert!(validate_bas_mode("").is_err());
        // Modes that used to be accepted by the wider ladder are now
        // rejected because the HTTP surface only knows three names.
        assert!(validate_bas_mode("passive_validation").is_err());
        assert!(validate_bas_mode("red_team").is_err());
    }

    #[test]
    fn accepts_three_known_modes_through_dto() {
        for m in ["theoretical", "safe_interactive", "active_exploit"] {
            let r = BasRunRequestView {
                technique_id: "T1003".into(),
                target: "asset-1".into(),
                mode: m.into(),
                dry_run: None,
                engagement_id: None,
            };
            assert!(r.validate().is_ok(), "should accept {m}");
        }
    }

    #[test]
    fn rejects_unknown_mode() {
        let r = BasRunRequestView {
            technique_id: "T1003".into(),
            target: "asset-1".into(),
            mode: "yolo".into(),
            dry_run: None,
            engagement_id: None,
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn requires_non_empty_technique_and_target() {
        let r = BasRunRequestView {
            technique_id: String::new(),
            target: String::new(),
            mode: "theoretical".into(),
            dry_run: None,
            engagement_id: None,
        };
        assert!(r.validate().is_err());
    }

    fn valid_uuid() -> String {
        "11111111-2222-3333-4444-555555555555".to_string()
    }

    #[test]
    fn approval_request_validates_required_fields() {
        // Happy path.
        let ok = RecordApprovalRequest {
            engagement_id: valid_uuid(),
            technique_id: "T1003".into(),
            approver_email: "alice@example.com".into(),
            reason: "Reviewed in change-board".into(),
        };
        assert!(ok.validate().is_ok());

        // Bad uuid.
        let bad_uuid = RecordApprovalRequest {
            engagement_id: "not-a-uuid".into(),
            technique_id: "T1003".into(),
            approver_email: "alice@example.com".into(),
            reason: "ok".into(),
        };
        assert!(bad_uuid.validate().is_err());

        // Empty technique.
        let bad_tech = RecordApprovalRequest {
            engagement_id: valid_uuid(),
            technique_id: String::new(),
            approver_email: "alice@example.com".into(),
            reason: "ok".into(),
        };
        assert!(bad_tech.validate().is_err());

        // Invalid email.
        let bad_email = RecordApprovalRequest {
            engagement_id: valid_uuid(),
            technique_id: "T1003".into(),
            approver_email: "not-an-email".into(),
            reason: "ok".into(),
        };
        assert!(bad_email.validate().is_err());

        // Empty reason.
        let bad_reason = RecordApprovalRequest {
            engagement_id: valid_uuid(),
            technique_id: "T1003".into(),
            approver_email: "alice@example.com".into(),
            reason: String::new(),
        };
        assert!(bad_reason.validate().is_err());
    }

    #[test]
    fn run_request_engagement_id_when_present_is_validated() {
        let bad = BasRunRequestView {
            technique_id: "T1003".into(),
            target: "asset-1".into(),
            mode: "safe_interactive".into(),
            dry_run: None,
            engagement_id: Some("not-a-uuid".into()),
        };
        assert!(bad.validate().is_err());

        let good = BasRunRequestView {
            technique_id: "T1003".into(),
            target: "asset-1".into(),
            mode: "safe_interactive".into(),
            dry_run: None,
            engagement_id: Some(valid_uuid()),
        };
        assert!(good.validate().is_ok());
    }
}
