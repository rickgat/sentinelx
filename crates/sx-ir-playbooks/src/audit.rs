//! Per-step audit entries.
//!
//! Every legal mutation appends one [`StepAuditEntry`] onto
//! [`crate::Incident::audit`]. The trail is intentionally append-only —
//! the in-memory adapter never rewrites past entries, and the SQL
//! migration captures the same shape in the `ir_step_audit` table.

use serde::{Deserialize, Serialize};

use crate::incident::{IncidentState, StepStatus};

/// Discriminator for the audit row: what kind of transition produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepAuditKind {
    /// Step status changed (`todo` / `in_progress` / `done` / `skipped`).
    StepStatusChanged,
    /// Step owner was claimed or reassigned.
    StepOwnerChanged,
    /// Evidence was attached to the step.
    EvidenceAttached,
    /// Incident-level rollup state changed.
    IncidentStateChanged,
}

impl StepAuditKind {
    /// Lowercase serialisation used on wire + DB columns.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StepStatusChanged => "step_status_changed",
            Self::StepOwnerChanged => "step_owner_changed",
            Self::EvidenceAttached => "evidence_attached",
            Self::IncidentStateChanged => "incident_state_changed",
        }
    }
}

/// One append-only audit row.
///
/// Tenant id is also stored on the parent incident so this row stays a
/// thin payload — but the persistent table (see migration) duplicates it
/// for RLS scoping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepAuditEntry {
    /// Stable opaque id (uuid v7).
    pub id: String,
    /// Kind of mutation captured.
    pub kind: StepAuditKind,
    /// Affected step id when applicable (`None` for incident-level rows).
    pub step_id: Option<String>,
    /// Actor (user id / email / opaque service principal) that drove
    /// the change. Free-form so SAML / SCIM / API-token callers all fit.
    pub actor: String,
    /// Previous status snapshot when applicable.
    pub from_status: Option<StepStatus>,
    /// New status snapshot when applicable.
    pub to_status: Option<StepStatus>,
    /// Previous incident state snapshot when applicable.
    pub from_incident_state: Option<IncidentState>,
    /// New incident state snapshot when applicable.
    pub to_incident_state: Option<IncidentState>,
    /// Operator-supplied note / `skipped` reason / evidence URI.
    pub note: Option<String>,
    /// RFC 3339 timestamp.
    pub at: String,
}

impl StepAuditEntry {
    /// Helper to build a step-status row.
    #[must_use]
    pub fn step_status(
        id: String,
        step_id: String,
        actor: String,
        from: StepStatus,
        to: StepStatus,
        note: Option<String>,
        at: String,
    ) -> Self {
        Self {
            id,
            kind: StepAuditKind::StepStatusChanged,
            step_id: Some(step_id),
            actor,
            from_status: Some(from),
            to_status: Some(to),
            from_incident_state: None,
            to_incident_state: None,
            note,
            at,
        }
    }

    /// Helper to build an owner-claim row.
    #[must_use]
    pub fn owner_change(
        id: String,
        step_id: String,
        actor: String,
        note: Option<String>,
        at: String,
    ) -> Self {
        Self {
            id,
            kind: StepAuditKind::StepOwnerChanged,
            step_id: Some(step_id),
            actor,
            from_status: None,
            to_status: None,
            from_incident_state: None,
            to_incident_state: None,
            note,
            at,
        }
    }

    /// Helper to build an evidence-attached row.
    #[must_use]
    pub fn evidence(
        id: String,
        step_id: String,
        actor: String,
        evidence_uri: String,
        at: String,
    ) -> Self {
        Self {
            id,
            kind: StepAuditKind::EvidenceAttached,
            step_id: Some(step_id),
            actor,
            from_status: None,
            to_status: None,
            from_incident_state: None,
            to_incident_state: None,
            note: Some(evidence_uri),
            at,
        }
    }

    /// Helper to build an incident-state-change row.
    #[must_use]
    pub fn incident_state(
        id: String,
        actor: String,
        from: IncidentState,
        to: IncidentState,
        at: String,
    ) -> Self {
        Self {
            id,
            kind: StepAuditKind::IncidentStateChanged,
            step_id: None,
            actor,
            from_status: None,
            to_status: None,
            from_incident_state: Some(from),
            to_incident_state: Some(to),
            note: None,
            at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_as_str_is_stable() {
        assert_eq!(
            StepAuditKind::StepStatusChanged.as_str(),
            "step_status_changed"
        );
        assert_eq!(
            StepAuditKind::IncidentStateChanged.as_str(),
            "incident_state_changed"
        );
    }

    #[test]
    fn step_status_helper_round_trips_json() {
        let row = StepAuditEntry::step_status(
            "row-1".into(),
            "s1".into(),
            "alice".into(),
            StepStatus::Todo,
            StepStatus::InProgress,
            None,
            "2026-01-01T00:00:00Z".into(),
        );
        let raw = serde_json::to_string(&row).expect("ser");
        let back: StepAuditEntry = serde_json::from_str(&raw).expect("de");
        assert_eq!(row, back);
    }
}
