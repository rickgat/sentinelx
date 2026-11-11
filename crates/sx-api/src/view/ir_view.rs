//! IR playbooks DTOs (wire shape only) — P3-004.
//!
//! Wire types backing the four `/v1/ir/*` endpoints:
//!
//! - `GET   /v1/ir/playbooks`                   → [`ListPlaybooksResponse`]
//! - `POST  /v1/ir/incidents`                   → [`OpenIncidentRequest`] / [`IncidentView`]
//! - `GET   /v1/ir/incidents/{id}`              → [`IncidentView`]
//! - `PATCH /v1/ir/incidents/{id}/steps/{step}` → [`UpdateStepRequest`] / [`IncidentView`]
//!
//! All wire shapes are stable and intentionally decoupled from the
//! domain types in [`sx_ir_playbooks`] — projection happens in the
//! controller layer so the API contract is not married to the domain
//! struct field order.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// One template step inside a playbook (wire shape).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PlaybookStepView {
    /// Stable opaque id.
    pub id: String,
    /// NIST phase serialised as a lowercase string
    /// (`preparation` / `detection_analysis` /
    /// `containment_eradication_recovery` / `post_incident_activity`).
    pub phase: String,
    /// Short human-readable title.
    pub title: String,
    /// Long-form description.
    pub description: String,
    /// Suggested owner role.
    pub default_owner_role: String,
    /// Evidence hints.
    pub evidence_hints: Vec<String>,
}

/// One playbook template (wire shape).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PlaybookView {
    /// Stable opaque catalog id (`ransomware` / …).
    pub id: String,
    /// Display name.
    pub name: String,
    /// Two-to-three sentence scenario summary.
    pub summary: String,
    /// Ordered template steps.
    pub steps: Vec<PlaybookStepView>,
}

/// `GET /v1/ir/playbooks` response body.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ListPlaybooksResponse {
    /// All playbook templates available to the caller's tenant.
    pub items: Vec<PlaybookView>,
}

/// `POST /v1/ir/incidents` request body.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct OpenIncidentRequest {
    /// Catalog id of the playbook to clone (e.g. `"ransomware"`).
    #[validate(length(min = 1, max = 64))]
    pub playbook_id: String,
    /// Display title for the new incident.
    #[validate(length(min = 1, max = 256))]
    pub title: String,
    /// Optional severity label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
}

/// One step inside a live incident (wire shape).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct IncidentStepView {
    /// Stable opaque id (mirrors the template).
    pub step_id: String,
    /// NIST phase, lowercase string.
    pub phase: String,
    /// Title at incident-open time.
    pub title: String,
    /// Description at incident-open time.
    pub description: String,
    /// Concrete owner (user id / email / handle), `None` until claimed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// `todo` / `in_progress` / `done` / `skipped`.
    pub status: String,
    /// Optional reason (mandatory when `status == "skipped"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Free-form evidence URIs attached so far.
    pub evidence: Vec<String>,
    /// RFC 3339 timestamp of the last per-step mutation.
    pub updated_at: String,
}

/// One audit row in the trail.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct StepAuditView {
    /// Stable opaque id.
    pub id: String,
    /// `step_status_changed` / `step_owner_changed` / `evidence_attached`
    /// / `incident_state_changed`.
    pub kind: String,
    /// Affected step id (absent for incident-level rows).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step_id: Option<String>,
    /// Actor that drove the change.
    pub actor: String,
    /// Previous step status (when applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_status: Option<String>,
    /// New step status (when applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_status: Option<String>,
    /// Previous incident state (when applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_incident_state: Option<String>,
    /// New incident state (when applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_incident_state: Option<String>,
    /// Operator-supplied note / `skipped` reason / evidence URI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// RFC 3339 timestamp.
    pub at: String,
}

/// `POST /v1/ir/incidents` and `GET /v1/ir/incidents/{id}` response body.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct IncidentView {
    /// Incident uuid.
    pub id: String,
    /// Tenant uuid scoping the incident.
    pub tenant_id: String,
    /// Catalog id the incident was opened from.
    pub playbook_id: String,
    /// `open` / `in_progress` / `contained` / `closed`.
    pub state: String,
    /// Display title.
    pub title: String,
    /// Optional severity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Cloned mutable step list, in phase order.
    pub steps: Vec<IncidentStepView>,
    /// Append-only audit trail.
    pub audit: Vec<StepAuditView>,
    /// RFC 3339 open timestamp.
    pub opened_at: String,
    /// RFC 3339 timestamp of the most-recent mutation.
    pub updated_at: String,
}

/// `PATCH /v1/ir/incidents/{id}/steps/{step}` request body.
#[derive(Debug, Clone, Default, Deserialize, Serialize, Validate)]
pub struct UpdateStepRequest {
    /// Target status. Subject to the state-machine guard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// New owner (claim or reassign).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 256))]
    pub owner: Option<String>,
    /// Mandatory when `status == "skipped"`, optional note otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 1024))]
    pub reason: Option<String>,
    /// Evidence URI to append to the step.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 2048))]
    pub evidence: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_incident_request_validates() {
        let r = OpenIncidentRequest {
            playbook_id: "ransomware".into(),
            title: "encryption observed".into(),
            severity: Some("high".into()),
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn open_incident_request_rejects_empty_title() {
        let r = OpenIncidentRequest {
            playbook_id: "ransomware".into(),
            title: String::new(),
            severity: None,
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn update_step_request_round_trip_skips_none() {
        let r = UpdateStepRequest {
            status: Some("in_progress".into()),
            ..UpdateStepRequest::default()
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(!s.contains("owner"));
        assert!(s.contains("in_progress"));
    }

    #[test]
    fn incident_view_round_trip() {
        let iv = IncidentView {
            id: "00000000-0000-0000-0000-000000000001".into(),
            tenant_id: "00000000-0000-0000-0000-00000000000a".into(),
            playbook_id: "ransomware".into(),
            state: "open".into(),
            title: "demo".into(),
            severity: None,
            steps: vec![],
            audit: vec![],
            opened_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let s = serde_json::to_string(&iv).unwrap();
        let back: IncidentView = serde_json::from_str(&s).unwrap();
        assert_eq!(iv, back);
    }
}
