//! Error type for `sx-risk`.
//!
//! Risk scoring is a deterministic, config-driven computation; errors here
//! cover (a) malformed configuration, (b) malformed input from upstream
//! callers, (c) failures bubbled up from EPSS / KEV provider adapters, and
//! (d) internal logic errors that should never fire in production.

use thiserror::Error;

/// Errors produced by the risk scoring engine.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RiskError {
    /// The supplied [`crate::model::RiskScoringConfig`] (or any nested
    /// table such as `severity_band_scores`) violated an invariant.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// A field on [`crate::model::RiskInput`] (or upstream
    /// [`crate::controller::RiskCalculationInput`]) was out of range,
    /// non-finite, or otherwise unparseable.
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// An EPSS or KEV provider adapter returned an error.
    ///
    /// Adapter crates wrap their underlying I/O failures (HTTP, JSON,
    /// timeouts) into this variant before crossing the port boundary.
    #[error("provider error: {0}")]
    Provider(String),

    /// An internal logic failure that should be unreachable in
    /// production — included so that the scoring code can never `unwrap`
    /// or `panic`.
    #[error("internal: {0}")]
    Internal(String),
}

impl RiskError {
    /// Convenience constructor for [`RiskError::Config`].
    #[must_use]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Convenience constructor for [`RiskError::InvalidInput`].
    #[must_use]
    pub fn invalid_input(msg: impl Into<String>) -> Self {
        Self::InvalidInput(msg.into())
    }

    /// Convenience constructor for [`RiskError::Provider`].
    #[must_use]
    pub fn provider(msg: impl Into<String>) -> Self {
        Self::Provider(msg.into())
    }

    /// Convenience constructor for [`RiskError::Internal`].
    #[must_use]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::RiskError;

    #[test]
    fn display_config() {
        assert_eq!(
            RiskError::config("bad weights").to_string(),
            "invalid configuration: bad weights",
        );
    }

    #[test]
    fn display_invalid_input() {
        assert_eq!(
            RiskError::invalid_input("oops").to_string(),
            "invalid input: oops",
        );
    }

    #[test]
    fn display_provider() {
        assert_eq!(
            RiskError::provider("epss down").to_string(),
            "provider error: epss down",
        );
    }

    #[test]
    fn display_internal() {
        assert_eq!(
            RiskError::internal("unreachable").to_string(),
            "internal: unreachable",
        );
    }
}
