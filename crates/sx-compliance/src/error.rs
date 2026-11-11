//! `ComplianceError` — the canonical error type for the sx-compliance crate.
//!
//! Every fallible operation in this crate returns [`ComplianceError`]. The
//! variants intentionally avoid leaking internal call-site details so that
//! upstream callers can render them as user-facing diagnostics without
//! further redaction.

use thiserror::Error;

/// Public error surface of the sx-compliance crate.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ComplianceError {
    /// The supplied [`crate::model::framework::Framework`] discriminator
    /// does not correspond to a known catalog entry.
    #[error("unknown framework: {0}")]
    UnknownFramework(String),

    /// The supplied [`crate::model::mapping::FindingCategory`] string did
    /// not parse — see [`crate::model::mapping::FindingCategory::parse`].
    #[error("unknown category: {0}")]
    UnknownCategory(String),

    /// A required input field was empty (e.g. `finding_id`,
    /// [`crate::model::evidence::Evidence::finding_ref`]).
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// The append-only [`crate::controller::collect_evidence::EvidenceSink`]
    /// reported a transport-level failure.
    #[error("evidence sink: {0}")]
    EvidenceSink(String),

    /// Programmer error or unexpected library failure.
    #[error("internal: {0}")]
    Internal(String),
}

impl ComplianceError {
    /// Convenience constructor for [`ComplianceError::InvalidInput`].
    #[must_use]
    pub fn invalid_input(msg: impl Into<String>) -> Self {
        Self::InvalidInput(msg.into())
    }

    /// Convenience constructor for [`ComplianceError::EvidenceSink`].
    #[must_use]
    pub fn evidence_sink(msg: impl Into<String>) -> Self {
        Self::EvidenceSink(msg.into())
    }

    /// Convenience constructor for [`ComplianceError::Internal`].
    #[must_use]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::ComplianceError;

    #[test]
    fn invalid_input_renders() {
        let e = ComplianceError::invalid_input("empty finding_ref");
        assert_eq!(e.to_string(), "invalid input: empty finding_ref");
    }

    #[test]
    fn distinct_variants_are_not_equal() {
        assert_ne!(
            ComplianceError::UnknownFramework("x".into()),
            ComplianceError::UnknownCategory("x".into())
        );
    }
}
