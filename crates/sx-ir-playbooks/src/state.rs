//! State-machine rules for step + incident transitions.
//!
//! Both rule sets are pure functions of `(from, to)` so callers can unit
//! test them without standing up the service.

use crate::incident::{IncidentState, StepStatus};

/// Return `true` iff the per-step status transition `from -> to` is
/// allowed.
///
/// Legal transitions:
/// ```text
///     Todo        -> InProgress | Skipped
///     InProgress  -> Done       | Skipped | Todo   (revert)
///     Done        -> InProgress                    (revert / reopen)
///     Skipped     -> Todo                          (un-skip)
///     ANY         -> SAME       (idempotent — no audit row written)
/// ```
#[must_use]
pub const fn is_legal_step_transition(from: StepStatus, to: StepStatus) -> bool {
    if matches!(
        (from, to),
        (StepStatus::Todo, StepStatus::Todo)
            | (StepStatus::InProgress, StepStatus::InProgress)
            | (StepStatus::Done, StepStatus::Done)
            | (StepStatus::Skipped, StepStatus::Skipped)
    ) {
        return true;
    }
    matches!(
        (from, to),
        (
            StepStatus::Todo,
            StepStatus::InProgress | StepStatus::Skipped
        ) | (
            StepStatus::InProgress,
            StepStatus::Done | StepStatus::Skipped | StepStatus::Todo,
        ) | (StepStatus::Done, StepStatus::InProgress)
            | (StepStatus::Skipped, StepStatus::Todo)
    )
}

/// Return `true` iff the incident-level state transition `from -> to` is
/// allowed by the playbook lifecycle.
///
/// Legal transitions:
/// ```text
///     Open         -> InProgress
///     InProgress   -> Contained | Closed | Open
///     Contained    -> InProgress | Closed
///     Closed       -> (terminal)
///     ANY          -> SAME (idempotent)
/// ```
#[must_use]
pub const fn is_legal_incident_transition(from: IncidentState, to: IncidentState) -> bool {
    if matches!(
        (from, to),
        (IncidentState::Open, IncidentState::Open)
            | (IncidentState::InProgress, IncidentState::InProgress)
            | (IncidentState::Contained, IncidentState::Contained)
            | (IncidentState::Closed, IncidentState::Closed)
    ) {
        return true;
    }
    matches!(
        (from, to),
        (
            IncidentState::Open | IncidentState::Contained,
            IncidentState::InProgress,
        ) | (
            IncidentState::InProgress,
            IncidentState::Contained | IncidentState::Closed | IncidentState::Open,
        ) | (IncidentState::Contained, IncidentState::Closed)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_legal_starts() {
        assert!(is_legal_step_transition(
            StepStatus::Todo,
            StepStatus::InProgress
        ));
        assert!(is_legal_step_transition(
            StepStatus::Todo,
            StepStatus::Skipped
        ));
    }

    #[test]
    fn step_legal_progression_to_done() {
        assert!(is_legal_step_transition(
            StepStatus::InProgress,
            StepStatus::Done
        ));
    }

    #[test]
    fn step_legal_revert_in_progress_to_todo() {
        assert!(is_legal_step_transition(
            StepStatus::InProgress,
            StepStatus::Todo
        ));
    }

    #[test]
    fn step_illegal_todo_to_done_direct() {
        assert!(!is_legal_step_transition(
            StepStatus::Todo,
            StepStatus::Done
        ));
    }

    #[test]
    fn step_illegal_skipped_to_done_direct() {
        assert!(!is_legal_step_transition(
            StepStatus::Skipped,
            StepStatus::Done
        ));
    }

    #[test]
    fn step_illegal_done_to_skipped() {
        assert!(!is_legal_step_transition(
            StepStatus::Done,
            StepStatus::Skipped
        ));
    }

    #[test]
    fn step_idempotent_allowed() {
        for s in [
            StepStatus::Todo,
            StepStatus::InProgress,
            StepStatus::Done,
            StepStatus::Skipped,
        ] {
            assert!(is_legal_step_transition(s, s));
        }
    }

    #[test]
    fn incident_legal_open_to_in_progress() {
        assert!(is_legal_incident_transition(
            IncidentState::Open,
            IncidentState::InProgress
        ));
    }

    #[test]
    fn incident_legal_in_progress_to_contained_to_closed() {
        assert!(is_legal_incident_transition(
            IncidentState::InProgress,
            IncidentState::Contained
        ));
        assert!(is_legal_incident_transition(
            IncidentState::Contained,
            IncidentState::Closed
        ));
    }

    #[test]
    fn incident_legal_reopen_from_contained() {
        assert!(is_legal_incident_transition(
            IncidentState::Contained,
            IncidentState::InProgress
        ));
    }

    #[test]
    fn incident_illegal_open_to_closed_direct() {
        assert!(!is_legal_incident_transition(
            IncidentState::Open,
            IncidentState::Closed
        ));
    }

    #[test]
    fn incident_illegal_closed_to_anything_else() {
        for to in [
            IncidentState::Open,
            IncidentState::InProgress,
            IncidentState::Contained,
        ] {
            assert!(!is_legal_incident_transition(IncidentState::Closed, to));
        }
    }

    #[test]
    fn incident_illegal_open_to_contained_direct() {
        assert!(!is_legal_incident_transition(
            IncidentState::Open,
            IncidentState::Contained
        ));
    }
}
