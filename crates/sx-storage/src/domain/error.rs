//! Local mirror of `sx_core::error::DomainError`.

use thiserror::Error;

/// Domain-layer error mirror.
///
/// Repository ports return this type. Adapter crates map their I/O
/// errors into [`DomainError::Repository`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomainError {
    /// Validation failure on a primitive value.
    #[error("invalid value: {0}")]
    InvalidValue(String),

    /// An entity invariant was violated.
    #[error("invariant violated: {0}")]
    InvariantViolation(String),

    /// Lookup miss.
    #[error("not found: {entity} id={id}")]
    NotFound {
        /// Logical entity name (e.g. `"Tenant"`).
        entity: &'static str,
        /// Identifier (as `Display`) of the missing record.
        id: String,
    },

    /// Uniqueness or optimistic-concurrency conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// FSM rejected the requested transition.
    #[error("invalid state transition from {from} to {to}")]
    InvalidStateTransition {
        /// Originating state.
        from: String,
        /// Attempted destination state.
        to: String,
    },

    /// Action targeted something outside the engagement scope.
    #[error("scope violation: {0}")]
    ScopeViolation(String),

    /// Adapter-reported persistence error.
    #[error("repository error: {0}")]
    Repository(String),
}

impl DomainError {
    /// Convenience constructor for [`DomainError::InvalidValue`].
    #[must_use]
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::InvalidValue(msg.into())
    }

    /// Convenience constructor for [`DomainError::Conflict`].
    #[must_use]
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::Conflict(msg.into())
    }

    /// Convenience constructor for [`DomainError::Repository`].
    #[must_use]
    pub fn repository(msg: impl Into<String>) -> Self {
        Self::Repository(msg.into())
    }
}
