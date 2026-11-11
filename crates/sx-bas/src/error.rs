//! BAS-layer error type.
//!
//! [`BasError`] is the canonical error returned from every gate, service,
//! technique, and use case in this crate. Every variant is safe to log via
//! `Display` — it never carries secrets, payloads, or PII.

use thiserror::Error;

use crate::model::mode::AttackMode;

/// Public error surface of the `sx-bas` crate.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BasError {
    /// The requested technique is not registered.
    #[error("technique not found: {0}")]
    TechniqueNotFound(String),

    /// A duplicate technique id was registered.
    #[error("duplicate technique id: {0}")]
    DuplicateTechnique(String),

    /// The technique's declared `max_mode` is above the engagement's ceiling.
    #[error(
        "mode violation: technique '{technique_id}' max_mode={technique_max} \
         exceeds active mode {active}"
    )]
    ModeViolation {
        /// Identifier of the rejected technique.
        technique_id: String,
        /// Technique's declared maximum permissible mode.
        technique_max: AttackMode,
        /// Engagement's currently-active operating mode.
        active: AttackMode,
    },

    /// The active operating mode is outside its authorised change window.
    #[error("outside change window")]
    OutsideChangeWindow,

    /// Fewer approvers on file than the active mode requires.
    #[error("approvals required: have {have}, need {need}")]
    ApprovalsInsufficient {
        /// Approvals currently on file.
        have: u32,
        /// Approvals required by policy.
        need: u32,
    },

    /// The Rules of Engagement artifact is missing or expired.
    #[error("rules of engagement invalid: {0}")]
    RoeInvalid(String),

    /// The kill switch has been tripped — all further steps are aborted.
    #[error("kill switch tripped: {0}")]
    KillSwitchTripped(String),

    /// The technique attempted to execute a dangerous code path that is
    /// permanently disabled in this crate.
    #[error("execution blocked: {reason}")]
    ExecutionBlocked {
        /// Human-readable explanation. Never include payload material.
        reason: String,
    },

    /// Validation of input failed at a use-case boundary.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// The technique aborted because the per-step deadline expired.
    #[error("step deadline exceeded")]
    DeadlineExceeded,

    /// Programmer error or unexpected library failure.
    #[error("internal: {0}")]
    Internal(String),
}

impl BasError {
    /// Convenience constructor for [`BasError::InvalidInput`].
    #[must_use]
    pub fn invalid_input(msg: impl Into<String>) -> Self {
        Self::InvalidInput(msg.into())
    }

    /// Convenience constructor for [`BasError::Internal`].
    #[must_use]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Convenience constructor for [`BasError::ExecutionBlocked`].
    #[must_use]
    pub fn execution_blocked(reason: impl Into<String>) -> Self {
        Self::ExecutionBlocked {
            reason: reason.into(),
        }
    }

    /// Convenience constructor for [`BasError::RoeInvalid`].
    #[must_use]
    pub fn roe_invalid(msg: impl Into<String>) -> Self {
        Self::RoeInvalid(msg.into())
    }

    /// Convenience constructor for [`BasError::KillSwitchTripped`].
    #[must_use]
    pub fn kill_switch(msg: impl Into<String>) -> Self {
        Self::KillSwitchTripped(msg.into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::BasError;
    use crate::model::mode::AttackMode;

    #[test]
    fn display_mode_violation() {
        let e = BasError::ModeViolation {
            technique_id: "x".into(),
            technique_max: AttackMode::RedTeam,
            active: AttackMode::SafeInteractive,
        };
        let s = e.to_string();
        assert!(s.contains("mode violation"));
        assert!(s.contains("red_team"));
        assert!(s.contains("safe_interactive"));
    }

    #[test]
    fn display_execution_blocked() {
        let e = BasError::execution_blocked("dangerous_execution disabled");
        assert_eq!(
            e.to_string(),
            "execution blocked: dangerous_execution disabled",
        );
    }

    #[test]
    fn display_kill_switch() {
        let e = BasError::kill_switch("global");
        assert_eq!(e.to_string(), "kill switch tripped: global");
    }

    #[test]
    fn display_approvals_insufficient() {
        let e = BasError::ApprovalsInsufficient { have: 1, need: 2 };
        assert_eq!(e.to_string(), "approvals required: have 1, need 2");
    }

    #[test]
    fn display_deadline() {
        assert_eq!(
            BasError::DeadlineExceeded.to_string(),
            "step deadline exceeded",
        );
    }
}
