//! Error type for the policy engine.

use thiserror::Error;

/// Errors emitted by [`crate::engine::PolicyEngine`] implementations and
/// policy-parsing helpers.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// Source could not be parsed into a valid [`crate::policy::Policy`].
    ///
    /// Carries the underlying parser message for diagnostics.
    #[error("policy parse error: {0}")]
    Parse(String),

    /// Backend reached during evaluation but the rule could not be executed
    /// (e.g. unsupported source variant, regex compilation failure, type
    /// mismatch the DSL cannot recover from).
    #[error("policy evaluation error: {0}")]
    Evaluate(String),

    /// Evaluation exceeded the bounded execution window
    /// ([`crate::engine::EVALUATE_TIMEOUT`]).
    #[error("policy evaluation timed out")]
    Timeout,
}
