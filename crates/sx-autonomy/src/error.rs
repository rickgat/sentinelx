//! Crate-level error type.
//!
//! Every fallible API in `sx-autonomy` returns an [`AutonomyError`]. Variants
//! are intentionally coarse; downstream adapters map their own errors into
//! the appropriate variant before crossing the use-case boundary. No variant
//! ever carries secrets, tokens, or raw tenant identifiers in its `Display`
//! output.

use thiserror::Error;

/// Public error surface of the `sx-autonomy` crate.
#[derive(Debug, Error)]
pub enum AutonomyError {
    /// Validation failed at a use-case boundary (e.g. empty technique list).
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// The continuous validation engine was asked to act on an engagement
    /// whose kill switch has tripped.
    #[error("engagement kill switch tripped: validation engine halted")]
    KillSwitchTripped,

    /// The underlying BAS simulator returned an error.
    #[error("bas simulator error: {0}")]
    SimulatorError(String),

    /// The validation engine's report sink rejected an append.
    #[error("validation report sink error: {0}")]
    SinkError(String),

    /// The PR generator was asked to push to a protected branch.
    #[error("protected branch refused: {0}")]
    ProtectedBranch(String),

    /// The diff exceeds the configured `max_diff_loc` ceiling.
    #[error("diff too large: {actual} lines (max {max})")]
    DiffTooLarge {
        /// Lines counted across all proposed file changes.
        actual: u32,
        /// Configured maximum.
        max: u32,
    },

    /// The PR generator config contained a malformed regex.
    #[error("config: {0}")]
    Config(String),

    /// Remote GitHub call failed.
    #[error("github client error: {0}")]
    GithubClient(String),

    /// The PR generator received an empty change set.
    #[error("empty change set: PR would have no diff")]
    EmptyChangeSet,

    /// Threat-network endpoint is not HTTPS.
    #[error("threat-network endpoint must be https")]
    InsecureEndpoint,

    /// The submitted consent artifact is missing or expired.
    #[error("threat-network consent missing or invalid: {0}")]
    MissingConsent(String),

    /// Threat-network HTTP call returned a non-2xx status.
    #[error("threat-network submission failed: status {status}")]
    NetworkSubmissionFailed {
        /// HTTP status code returned by the upstream ledger.
        status: u16,
    },

    /// Transport-level failure when calling the threat network.
    #[error("threat-network transport: {0}")]
    NetworkTransport(String),

    /// JSON serialisation of an outbound body failed.
    #[error("serialization: {0}")]
    Serialization(String),

    /// Programmer error or unexpected library failure.
    #[error("internal: {0}")]
    Internal(String),
}

impl AutonomyError {
    /// Convenience constructor for [`AutonomyError::InvalidInput`].
    #[must_use]
    pub fn invalid_input(msg: impl Into<String>) -> Self {
        Self::InvalidInput(msg.into())
    }

    /// Convenience constructor for [`AutonomyError::Config`].
    #[must_use]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Convenience constructor for [`AutonomyError::GithubClient`].
    #[must_use]
    pub fn github(msg: impl Into<String>) -> Self {
        Self::GithubClient(msg.into())
    }

    /// Convenience constructor for [`AutonomyError::Internal`].
    #[must_use]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::AutonomyError;

    #[test]
    fn display_protected_branch() {
        let e = AutonomyError::ProtectedBranch("main".into());
        assert_eq!(e.to_string(), "protected branch refused: main");
    }

    #[test]
    fn display_diff_too_large() {
        let e = AutonomyError::DiffTooLarge {
            actual: 300,
            max: 200,
        };
        assert!(e.to_string().contains("300"));
        assert!(e.to_string().contains("200"));
    }

    #[test]
    fn display_insecure_endpoint() {
        assert_eq!(
            AutonomyError::InsecureEndpoint.to_string(),
            "threat-network endpoint must be https",
        );
    }

    #[test]
    fn display_network_submission_failed() {
        let e = AutonomyError::NetworkSubmissionFailed { status: 503 };
        assert!(e.to_string().contains("503"));
    }
}
