//! Engagement-layer error type.
//!
//! `EngagementError` is the canonical error returned from every use case,
//! service, and port in the `sx-engagement` crate. Variants are intentionally
//! coarse so that the API surface does not leak internal details to callers.
//!
//! Every variant is safe to log via `Display` — no secrets, no token material,
//! no PII.

use thiserror::Error;

/// Public error surface of the sx-engagement crate.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EngagementError {
    /// A scan request targeted something outside the engagement scope.
    #[error("scope violation: {0}")]
    ScopeViolation(String),

    /// A scan target matched a global denylist entry.
    ///
    /// The denylist always wins, regardless of the engagement scope.
    #[error("denylisted target: {0}")]
    Denylisted(String),

    /// The engagement is not in `Active` state.
    #[error("engagement not active: {status}")]
    NotActive {
        /// Current status, formatted via `Display`.
        status: String,
    },

    /// The engagement is active but the current time sits outside its window.
    #[error("outside time window")]
    OutsideWindow,

    /// Fewer approvals on file than the policy requires.
    #[error("approvals required: have {have}, need {need}")]
    ApprovalsInsufficient {
        /// Approvals currently on file.
        have: u32,
        /// Approvals required by policy.
        need: u32,
    },

    /// A kill-switch has been tripped for the given scope.
    #[error("kill switch tripped: {scope}")]
    KillSwitchTripped {
        /// Display form of the scope (`global` / `tenant=<id>` / `engagement=...`).
        scope: String,
    },

    /// A persistence-layer adapter reported an I/O failure.
    #[error("repository: {0}")]
    Repository(String),

    /// An invalid finite-state-machine transition was attempted.
    #[error("invalid state transition from {from} to {to}")]
    InvalidStateTransition {
        /// State the caller transitioned from.
        from: String,
        /// State the caller attempted to transition to.
        to: String,
    },

    /// Validation of input failed at a use-case boundary.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// Programmer error or unexpected library failure.
    #[error("internal: {0}")]
    Internal(String),
}

impl EngagementError {
    /// Convenience constructor for [`EngagementError::ScopeViolation`].
    #[must_use]
    pub fn scope(msg: impl Into<String>) -> Self {
        Self::ScopeViolation(msg.into())
    }

    /// Convenience constructor for [`EngagementError::Denylisted`].
    #[must_use]
    pub fn denylisted(msg: impl Into<String>) -> Self {
        Self::Denylisted(msg.into())
    }

    /// Convenience constructor for [`EngagementError::Repository`].
    #[must_use]
    pub fn repository(msg: impl Into<String>) -> Self {
        Self::Repository(msg.into())
    }

    /// Convenience constructor for [`EngagementError::Internal`].
    #[must_use]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Convenience constructor for [`EngagementError::InvalidInput`].
    #[must_use]
    pub fn invalid_input(msg: impl Into<String>) -> Self {
        Self::InvalidInput(msg.into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::EngagementError;

    #[test]
    fn display_scope_violation() {
        let e = EngagementError::scope("not in CIDR");
        assert_eq!(e.to_string(), "scope violation: not in CIDR");
    }

    #[test]
    fn display_denylisted() {
        let e = EngagementError::denylisted("*.gov");
        assert_eq!(e.to_string(), "denylisted target: *.gov");
    }

    #[test]
    fn display_approvals_insufficient() {
        let e = EngagementError::ApprovalsInsufficient { have: 1, need: 2 };
        assert_eq!(e.to_string(), "approvals required: have 1, need 2");
    }

    #[test]
    fn display_kill_switch_tripped() {
        let e = EngagementError::KillSwitchTripped {
            scope: "global".into(),
        };
        assert_eq!(e.to_string(), "kill switch tripped: global");
    }

    #[test]
    fn display_outside_window() {
        let e = EngagementError::OutsideWindow;
        assert_eq!(e.to_string(), "outside time window");
    }

    #[test]
    fn display_invalid_state_transition() {
        let e = EngagementError::InvalidStateTransition {
            from: "Draft".into(),
            to: "Completed".into(),
        };
        assert_eq!(
            e.to_string(),
            "invalid state transition from Draft to Completed",
        );
    }

    #[test]
    fn constructors_classify_correctly() {
        assert!(matches!(
            EngagementError::repository("x"),
            EngagementError::Repository(_)
        ));
        assert!(matches!(
            EngagementError::internal("x"),
            EngagementError::Internal(_)
        ));
        assert!(matches!(
            EngagementError::invalid_input("x"),
            EngagementError::InvalidInput(_)
        ));
    }
}
