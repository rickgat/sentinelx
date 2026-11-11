//! Error type shared by every `sx-ai-audit` operation.

use thiserror::Error;

/// Fallible outcome of an AI-audit operation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AiAuditError {
    /// A probe (or other live action) was attempted against a target that
    /// is **not in the authorized engagement scope**. The string names the
    /// offending target reference. No bytes are ever sent in this case.
    #[error("target `{0}` is out of engagement scope")]
    OutOfScope(String),

    /// A caller-supplied value failed validation (empty tenant id, etc.).
    #[error("invalid input: {0}")]
    Invalid(String),

    /// The thing under test could not be reached / returned a transport
    /// error. Carries an operator-readable detail.
    #[error("target unavailable: {0}")]
    TargetUnavailable(String),

    /// A model-file or AI-BOM payload could not be parsed.
    #[error("parse error: {0}")]
    Parse(String),

    /// A backing sink / store failed.
    #[error("sink error: {0}")]
    Sink(String),

    /// Catch-all internal failure.
    #[error("internal error: {0}")]
    Internal(String),
}
