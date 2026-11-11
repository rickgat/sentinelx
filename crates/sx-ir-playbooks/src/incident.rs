//! Per-incident state: cloned step list + state machine.

use serde::{Deserialize, Serialize};

use crate::audit::StepAuditEntry;
use crate::phase::IrPhase;
use crate::playbook::Playbook;

/// Per-step execution status.
///
/// Forms a small state machine — see [`crate::state::is_legal_step_transition`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    /// Default — the step has not been started.
    Todo,
    /// An owner has been assigned and work is in flight.
    InProgress,
    /// The step is complete.
    Done,
    /// The step is intentionally not applicable to this incident; a
    /// `reason` is required by the state-machine guard.
    Skipped,
}

impl StepStatus {
    /// Lowercase serialisation used on wire + DB columns.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Todo => "todo",
            Self::InProgress => "in_progress",
            Self::Done => "done",
            Self::Skipped => "skipped",
        }
    }
}

/// Live incident state.
///
/// Forms a small state machine — see
/// [`crate::state::is_legal_incident_transition`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentState {
    /// Newly opened — no step has been touched.
    Open,
    /// At least one step is `in_progress` or `done`.
    InProgress,
    /// All `containment_eradication_recovery` steps are `done` or
    /// `skipped`. The incident may still re-open if a follow-up
    /// containment step is added.
    Contained,
    /// Every step is either `done` or `skipped`. Terminal.
    Closed,
}

impl IncidentState {
    /// Lowercase serialisation used on wire + DB columns.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::InProgress => "in_progress",
            Self::Contained => "contained",
            Self::Closed => "closed",
        }
    }
}

/// One executable step inside an [`Incident`]. Cloned from the parent
/// [`crate::PlaybookStep`] at incident-open time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentStep {
    /// Stable opaque id mirroring [`crate::PlaybookStep::id`].
    pub step_id: String,
    /// Lifecycle phase mirrored from the template.
    pub phase: IrPhase,
    /// Title at the moment the incident was opened (the catalog can
    /// evolve later — incidents stay pinned to their cloned copy).
    pub title: String,
    /// Description, ditto.
    pub description: String,
    /// Concrete owner (user id, email, or human handle) assigned for
    /// *this* incident. `None` until an operator claims the step.
    pub owner: Option<String>,
    /// Current status.
    pub status: StepStatus,
    /// Reason — required when `status == Skipped`, optional notes
    /// otherwise.
    pub reason: Option<String>,
    /// Free-form evidence URI / S3 key / log query the operator
    /// attached while running this step.
    #[serde(default)]
    pub evidence: Vec<String>,
    /// RFC 3339 timestamp of the last status update. Defaults to the
    /// incident creation time.
    pub updated_at: String,
}

impl IncidentStep {
    /// Build a fresh `IncidentStep` from a template step.
    #[must_use]
    pub fn from_template(template: &crate::playbook::PlaybookStep, now: &str) -> Self {
        Self {
            step_id: template.id.clone(),
            phase: template.phase,
            title: template.title.clone(),
            description: template.description.clone(),
            owner: None,
            status: StepStatus::Todo,
            reason: None,
            evidence: Vec::new(),
            updated_at: now.to_owned(),
        }
    }
}

/// A live incident — a cloned execution of a [`Playbook`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incident {
    /// Incident uuid (v7).
    pub id: String,
    /// Tenant uuid scoping the incident.
    pub tenant_id: String,
    /// Catalog id of the playbook this incident was opened against.
    pub playbook_id: String,
    /// Incident-level state.
    pub state: IncidentState,
    /// Display title (defaults to the playbook name + a short
    /// scenario blurb — set by the opener).
    pub title: String,
    /// Optional free-form severity label (`low` / `med` / `high` /
    /// `critical`) — the IR crate does not enforce a vocabulary.
    pub severity: Option<String>,
    /// Cloned + mutable step list, in phase order.
    pub steps: Vec<IncidentStep>,
    /// Append-only audit trail of step + state transitions.
    pub audit: Vec<StepAuditEntry>,
    /// RFC 3339 timestamp at open.
    pub opened_at: String,
    /// RFC 3339 timestamp of the last mutation.
    pub updated_at: String,
}

impl Incident {
    /// Open a new incident from a template + tenant + opener metadata.
    #[must_use]
    pub fn open(
        id: String,
        tenant_id: String,
        playbook: &Playbook,
        title: String,
        severity: Option<String>,
        now: &str,
    ) -> Self {
        Self {
            id,
            tenant_id,
            playbook_id: playbook.id.clone(),
            state: IncidentState::Open,
            title,
            severity,
            steps: playbook
                .steps
                .iter()
                .map(|t| IncidentStep::from_template(t, now))
                .collect(),
            audit: Vec::new(),
            opened_at: now.to_owned(),
            updated_at: now.to_owned(),
        }
    }

    /// Borrow the matching step, if any.
    #[must_use]
    pub fn step(&self, step_id: &str) -> Option<&IncidentStep> {
        self.steps.iter().find(|s| s.step_id == step_id)
    }

    /// Mutable borrow of the matching step, if any.
    pub fn step_mut(&mut self, step_id: &str) -> Option<&mut IncidentStep> {
        self.steps.iter_mut().find(|s| s.step_id == step_id)
    }

    /// Recompute the rolled-up incident state from the per-step status
    /// distribution. Used after every PATCH so the high-level state stays
    /// in lock-step with the steps.
    #[must_use]
    pub fn rollup_state(&self) -> IncidentState {
        let all_terminal = self
            .steps
            .iter()
            .all(|s| matches!(s.status, StepStatus::Done | StepStatus::Skipped));
        if all_terminal {
            return IncidentState::Closed;
        }
        let any_started = self.steps.iter().any(|s| {
            matches!(
                s.status,
                StepStatus::InProgress | StepStatus::Done | StepStatus::Skipped
            )
        });
        let containment_done = self
            .steps
            .iter()
            .filter(|s| s.phase == IrPhase::ContainmentEradicationRecovery)
            .all(|s| matches!(s.status, StepStatus::Done | StepStatus::Skipped));
        let has_containment = self
            .steps
            .iter()
            .any(|s| s.phase == IrPhase::ContainmentEradicationRecovery);
        if any_started && has_containment && containment_done {
            return IncidentState::Contained;
        }
        if any_started {
            return IncidentState::InProgress;
        }
        IncidentState::Open
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::PlaybookStep;

    fn mk_playbook() -> Playbook {
        Playbook {
            id: "demo".into(),
            name: "Demo".into(),
            summary: "summary".into(),
            steps: vec![
                PlaybookStep {
                    id: "p1".into(),
                    phase: IrPhase::Preparation,
                    title: "p1".into(),
                    description: "d".into(),
                    default_owner_role: "ic".into(),
                    evidence_hints: vec![],
                },
                PlaybookStep {
                    id: "d1".into(),
                    phase: IrPhase::DetectionAnalysis,
                    title: "d1".into(),
                    description: "d".into(),
                    default_owner_role: "ic".into(),
                    evidence_hints: vec![],
                },
                PlaybookStep {
                    id: "c1".into(),
                    phase: IrPhase::ContainmentEradicationRecovery,
                    title: "c1".into(),
                    description: "d".into(),
                    default_owner_role: "ic".into(),
                    evidence_hints: vec![],
                },
                PlaybookStep {
                    id: "x1".into(),
                    phase: IrPhase::PostIncident,
                    title: "x1".into(),
                    description: "d".into(),
                    default_owner_role: "ic".into(),
                    evidence_hints: vec![],
                },
            ],
        }
    }

    #[test]
    fn opens_in_open_state_with_cloned_steps() {
        let pb = mk_playbook();
        let inc = Incident::open(
            "00000000-0000-0000-0000-00000000aaaa".into(),
            "00000000-0000-0000-0000-000000000001".into(),
            &pb,
            "demo title".into(),
            Some("high".into()),
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(inc.state, IncidentState::Open);
        assert_eq!(inc.steps.len(), 4);
        assert!(inc.steps.iter().all(|s| s.status == StepStatus::Todo));
        assert!(inc.steps.iter().all(|s| s.owner.is_none()));
    }

    #[test]
    fn rollup_open_until_first_change() {
        let pb = mk_playbook();
        let inc = Incident::open(
            "x".into(),
            "t".into(),
            &pb,
            "t".into(),
            None,
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(inc.rollup_state(), IncidentState::Open);
    }

    #[test]
    fn rollup_in_progress_after_first_status_change() {
        let pb = mk_playbook();
        let mut inc = Incident::open(
            "x".into(),
            "t".into(),
            &pb,
            "t".into(),
            None,
            "2026-01-01T00:00:00Z",
        );
        if let Some(s) = inc.step_mut("d1") {
            s.status = StepStatus::InProgress;
        }
        assert_eq!(inc.rollup_state(), IncidentState::InProgress);
    }

    #[test]
    fn rollup_contained_when_containment_all_done() {
        let pb = mk_playbook();
        let mut inc = Incident::open(
            "x".into(),
            "t".into(),
            &pb,
            "t".into(),
            None,
            "2026-01-01T00:00:00Z",
        );
        // Mark detection in progress + containment done.
        if let Some(s) = inc.step_mut("d1") {
            s.status = StepStatus::Done;
        }
        if let Some(s) = inc.step_mut("c1") {
            s.status = StepStatus::Done;
        }
        assert_eq!(inc.rollup_state(), IncidentState::Contained);
    }

    #[test]
    fn rollup_closed_when_every_step_terminal() {
        let pb = mk_playbook();
        let mut inc = Incident::open(
            "x".into(),
            "t".into(),
            &pb,
            "t".into(),
            None,
            "2026-01-01T00:00:00Z",
        );
        for s in &mut inc.steps {
            s.status = StepStatus::Done;
        }
        assert_eq!(inc.rollup_state(), IncidentState::Closed);
    }
}
