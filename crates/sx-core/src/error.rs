//! Domain-layer error type.
//!
//! `DomainError` is the canonical error type returned from every value-object
//! constructor, entity invariant check, state-machine transition, and
//! repository port in this crate. It is intentionally I/O-free: variants
//! describe *domain* failure modes only.

use thiserror::Error;

/// Errors that can be produced by the domain layer.
///
/// Concrete I/O failures (database, HTTP, etc.) are mapped into
/// [`DomainError::Repository`] by adapter crates.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomainError {
    /// A primitive value violated its validation contract.
    #[error("invalid value: {0}")]
    InvalidValue(String),

    /// An entity invariant (a multi-field rule) was broken.
    #[error("invariant violated: {0}")]
    InvariantViolation(String),

    /// A lookup by id (or natural key) failed.
    #[error("not found: {entity} id={id}")]
    NotFound {
        /// Logical entity name (e.g. `"Tenant"`, `"Engagement"`).
        entity: &'static str,
        /// Identifier (as `Display`) of the missing record.
        id: String,
    },

    /// A uniqueness or optimistic-concurrency conflict.
    #[error("conflict: {0}")]
    Conflict(String),

    /// A finite-state-machine transition was rejected.
    #[error("invalid state transition from {from} to {to}")]
    InvalidStateTransition {
        /// State the caller transitioned from.
        from: String,
        /// State the caller attempted to transition to.
        to: String,
    },

    /// An action targeted something outside the engagement scope.
    #[error("scope violation: {0}")]
    ScopeViolation(String),

    /// A persistence-layer error reported by an adapter.
    ///
    /// Adapter crates map their I/O errors into this variant before
    /// returning across the port boundary.
    #[error("repository error: {0}")]
    Repository(String),
}

impl DomainError {
    /// Convenience constructor for [`DomainError::InvalidValue`].
    #[must_use]
    pub fn invalid(msg: impl Into<String>) -> Self {
        Self::InvalidValue(msg.into())
    }

    /// Convenience constructor for [`DomainError::InvariantViolation`].
    #[must_use]
    pub fn invariant(msg: impl Into<String>) -> Self {
        Self::InvariantViolation(msg.into())
    }

    /// Convenience constructor for [`DomainError::ScopeViolation`].
    #[must_use]
    pub fn scope(msg: impl Into<String>) -> Self {
        Self::ScopeViolation(msg.into())
    }

    /// Convenience constructor for [`DomainError::Conflict`].
    #[must_use]
    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::Conflict(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::DomainError;

    #[test]
    fn display_invalid_value() {
        let e = DomainError::invalid("nope");
        assert_eq!(e.to_string(), "invalid value: nope");
    }

    #[test]
    fn display_not_found() {
        let e = DomainError::NotFound {
            entity: "Tenant",
            id: "abc".into(),
        };
        assert_eq!(e.to_string(), "not found: Tenant id=abc");
    }

    #[test]
    fn display_state_transition() {
        let e = DomainError::InvalidStateTransition {
            from: "Discovered".into(),
            to: "Closed".into(),
        };
        assert_eq!(
            e.to_string(),
            "invalid state transition from Discovered to Closed",
        );
    }
}
