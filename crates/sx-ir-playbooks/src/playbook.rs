//! Immutable playbook templates: ordered, phase-tagged steps.

use serde::{Deserialize, Serialize};

use crate::error::IrPlaybookError;
use crate::phase::IrPhase;

/// One template step inside a [`Playbook`].
///
/// The owner is a role string (e.g. `"incident_commander"`,
/// `"forensics_lead"`) — never a concrete user id — so a playbook can be
/// reused across teams.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaybookStep {
    /// Stable opaque id (lowercase, dash-separated). Cloned into
    /// [`crate::IncidentStep::step_id`] when an incident is opened.
    pub id: String,
    /// Lifecycle phase this step belongs to.
    pub phase: IrPhase,
    /// Short human-readable title.
    pub title: String,
    /// Long-form description: the playbook operator runs this verbatim.
    pub description: String,
    /// Suggested owner role (e.g. `"incident_commander"`). Concrete user
    /// assignment happens at incident time via the PATCH endpoint.
    pub default_owner_role: String,
    /// Evidence the operator should collect at this step (file path /
    /// log query / screenshot — free-form).
    #[serde(default)]
    pub evidence_hints: Vec<String>,
}

/// A pre-canned, immutable playbook template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Playbook {
    /// Stable opaque id (lowercase, dash-separated). Used as the catalog
    /// key + as the `playbook_id` foreign reference on incidents.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Two-to-three sentence summary of the scenario this covers.
    pub summary: String,
    /// Ordered steps. The order is significant: clients render them as a
    /// per-phase checklist in this exact order, grouped by phase.
    pub steps: Vec<PlaybookStep>,
}

impl Playbook {
    /// Parse a single playbook JSON document. Used by the static
    /// catalog loader and by tests that build fixtures inline.
    pub fn from_json(raw: &str) -> Result<Self, IrPlaybookError> {
        let pb: Self =
            serde_json::from_str(raw).map_err(|e| IrPlaybookError::Invalid(e.to_string()))?;
        pb.validate()?;
        Ok(pb)
    }

    /// Validate structural invariants:
    /// * non-empty id and name
    /// * at least one step
    /// * unique step ids
    /// * every NIST phase represented at least once
    pub fn validate(&self) -> Result<(), IrPlaybookError> {
        if self.id.is_empty() {
            return Err(IrPlaybookError::Invalid("playbook id empty".into()));
        }
        if self.name.is_empty() {
            return Err(IrPlaybookError::Invalid("playbook name empty".into()));
        }
        if self.steps.is_empty() {
            return Err(IrPlaybookError::Invalid(format!(
                "playbook '{}' has no steps",
                self.id
            )));
        }
        // Unique step ids.
        let mut seen: Vec<&str> = Vec::with_capacity(self.steps.len());
        for s in &self.steps {
            if s.id.is_empty() {
                return Err(IrPlaybookError::Invalid("step id empty".into()));
            }
            if seen.contains(&s.id.as_str()) {
                return Err(IrPlaybookError::Invalid(format!(
                    "duplicate step id '{}'",
                    s.id
                )));
            }
            seen.push(s.id.as_str());
        }
        // Every phase represented.
        for phase in IrPhase::ordered() {
            if !self.steps.iter().any(|s| s.phase == phase) {
                return Err(IrPlaybookError::Invalid(format!(
                    "playbook '{}' missing phase '{}'",
                    self.id,
                    phase.as_str()
                )));
            }
        }
        Ok(())
    }

    /// Borrow the step with matching id, if any.
    #[must_use]
    pub fn step(&self, step_id: &str) -> Option<&PlaybookStep> {
        self.steps.iter().find(|s| s.id == step_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_step(id: &str, phase: IrPhase) -> PlaybookStep {
        PlaybookStep {
            id: id.into(),
            phase,
            title: format!("title-{id}"),
            description: format!("desc-{id}"),
            default_owner_role: "ic".into(),
            evidence_hints: vec![],
        }
    }

    fn full_pb() -> Playbook {
        Playbook {
            id: "test".into(),
            name: "Test".into(),
            summary: "summary".into(),
            steps: vec![
                mk_step("s1", IrPhase::Preparation),
                mk_step("s2", IrPhase::DetectionAnalysis),
                mk_step("s3", IrPhase::ContainmentEradicationRecovery),
                mk_step("s4", IrPhase::PostIncident),
            ],
        }
    }

    #[test]
    fn validate_accepts_full_playbook() {
        assert!(full_pb().validate().is_ok());
    }

    #[test]
    fn validate_rejects_missing_phase() {
        let mut pb = full_pb();
        pb.steps.pop();
        let err = pb.validate().expect_err("must reject");
        match err {
            IrPlaybookError::Invalid(m) => assert!(m.contains("post_incident_activity")),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn validate_rejects_duplicate_step_id() {
        let mut pb = full_pb();
        pb.steps[1].id = "s1".into();
        let err = pb.validate().expect_err("must reject");
        match err {
            IrPlaybookError::Invalid(m) => assert!(m.contains("duplicate")),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn validate_rejects_empty_id() {
        let mut pb = full_pb();
        pb.id = String::new();
        assert!(pb.validate().is_err());
    }

    #[test]
    fn step_borrow_finds() {
        let pb = full_pb();
        assert!(pb.step("s2").is_some());
        assert!(pb.step("missing").is_none());
    }

    #[test]
    fn from_json_round_trip() {
        let pb = full_pb();
        let raw = serde_json::to_string(&pb).expect("ser");
        let back = Playbook::from_json(&raw).expect("de");
        assert_eq!(pb, back);
    }
}
