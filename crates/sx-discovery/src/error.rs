//! Crate-level error type.
//!
//! Every fallible API in this crate returns [`DiscoveryError`]. Variants are
//! intentionally coarse — adapter layers map their I/O errors into the
//! appropriate variant before crossing the use-case boundary.

use thiserror::Error;

/// All errors produced by the discovery crate.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// The pre-flight [`crate::service::safety_gate::SafetyGate`] denied the
    /// request because scope validation or denylist rules rejected the
    /// target.
    #[error("safety gate denied: {0}")]
    SafetyGate(String),

    /// No scanner with the requested id is currently registered.
    #[error("scanner not registered: {0}")]
    ScannerNotFound(String),

    /// The rate limiter refused to issue a token within the allowed budget.
    #[error("rate limited")]
    RateLimited,

    /// The engagement kill switch tripped before or during the scan.
    #[error("kill switch tripped")]
    KillSwitchTripped,

    /// A network or per-step timeout expired.
    #[error("timeout")]
    Timeout,

    /// A low-level I/O error.
    #[error("io: {0}")]
    Io(String),

    /// Configuration was invalid or missing a required field.
    #[error("config: {0}")]
    Config(String),

    /// An invariant in the discovery layer was violated. Treat as a bug.
    #[error("internal: {0}")]
    Internal(String),
}

impl DiscoveryError {
    /// Convenience constructor for [`DiscoveryError::SafetyGate`].
    #[must_use]
    pub fn safety_gate(msg: impl Into<String>) -> Self {
        Self::SafetyGate(msg.into())
    }

    /// Convenience constructor for [`DiscoveryError::Config`].
    #[must_use]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Convenience constructor for [`DiscoveryError::Io`].
    #[must_use]
    pub fn io(msg: impl Into<String>) -> Self {
        Self::Io(msg.into())
    }

    /// Convenience constructor for [`DiscoveryError::Internal`].
    #[must_use]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

#[cfg(test)]
mod tests {
    use super::DiscoveryError;

    #[test]
    fn display_includes_reason() {
        assert_eq!(
            DiscoveryError::safety_gate("denied").to_string(),
            "safety gate denied: denied",
        );
        assert_eq!(DiscoveryError::RateLimited.to_string(), "rate limited");
        assert_eq!(
            DiscoveryError::KillSwitchTripped.to_string(),
            "kill switch tripped",
        );
    }
}
