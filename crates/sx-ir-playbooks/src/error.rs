//! Errors surfaced by the IR playbooks crate.

use thiserror::Error;

/// Coarse-grained error type for the IR playbook service.
///
/// Mirrors the shape of every other `sx-*` service error in the
/// workspace so the HTTP layer can mechanically translate variants to
/// [`crate::error::IrPlaybookError`] -> `ApiError`.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum IrPlaybookError {
    /// Resource (playbook id, incident id, step id, tenant) does not
    /// exist in the caller's scope.
    #[error("not found")]
    NotFound,
    /// Step status transition is not allowed by the state machine.
    #[error("illegal step transition: {0}")]
    IllegalStepTransition(String),
    /// Incident state transition is not allowed by the state machine.
    #[error("illegal incident transition: {0}")]
    IllegalIncidentTransition(String),
    /// Caller-supplied payload failed semantic validation.
    #[error("invalid: {0}")]
    Invalid(String),
    /// Programmer error / impossible branch hit at runtime.
    #[error("internal: {0}")]
    Internal(String),
}
