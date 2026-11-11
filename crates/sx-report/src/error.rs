//! Crate-level error type.
//!
//! Every fallible API in `sx-report` surfaces a [`ReportError`]. Renderer
//! adapter errors (PDF, JSON, CSV) are mapped into the appropriate variant
//! before crossing the use-case boundary.

use thiserror::Error;

/// All errors produced by the report crate.
#[derive(Debug, Error)]
pub enum ReportError {
    /// The caller supplied a format string we do not recognise.
    #[error("unsupported report format: {0}")]
    UnsupportedFormat(String),

    /// The use-case was asked to render a format for which no renderer is
    /// registered.
    #[error("renderer not registered for format: {0}")]
    RendererNotRegistered(String),

    /// Two renderers were registered for the same format, or zero renderers
    /// were supplied.
    #[error("invalid renderer registry: {0}")]
    InvalidRegistry(String),

    /// The [`crate::model::ReportContext`] failed local validation (e.g.
    /// empty engagement name).
    #[error("invalid report context: {0}")]
    InvalidContext(String),

    /// A PDF renderer failed at the printpdf layer.
    #[error("pdf rendering failed: {0}")]
    Pdf(String),

    /// A JSON renderer (SARIF or STIX) failed to serialise.
    #[error("json serialization failed: {0}")]
    Json(String),

    /// A CSV renderer failed.
    #[error("csv encoding failed: {0}")]
    Csv(String),

    /// A renderer attempted to produce a filename that would escape its
    /// container (path separators, `..`, etc.).
    #[error("filename sanitisation rejected: {0}")]
    UnsafeFilename(String),

    /// An invariant in the report layer was violated. Treat as a bug.
    #[error("internal: {0}")]
    Internal(String),
}

impl ReportError {
    /// Construct an [`ReportError::UnsupportedFormat`].
    #[must_use]
    pub fn unsupported_format(s: impl Into<String>) -> Self {
        Self::UnsupportedFormat(s.into())
    }

    /// Construct an [`ReportError::RendererNotRegistered`].
    #[must_use]
    pub fn renderer_not_registered(s: impl Into<String>) -> Self {
        Self::RendererNotRegistered(s.into())
    }

    /// Construct an [`ReportError::InvalidRegistry`].
    #[must_use]
    pub fn invalid_registry(s: impl Into<String>) -> Self {
        Self::InvalidRegistry(s.into())
    }

    /// Construct an [`ReportError::InvalidContext`].
    #[must_use]
    pub fn invalid_context(s: impl Into<String>) -> Self {
        Self::InvalidContext(s.into())
    }

    /// Construct an [`ReportError::Pdf`].
    #[must_use]
    pub fn pdf(s: impl Into<String>) -> Self {
        Self::Pdf(s.into())
    }

    /// Construct an [`ReportError::Json`].
    #[must_use]
    pub fn json(s: impl Into<String>) -> Self {
        Self::Json(s.into())
    }

    /// Construct an [`ReportError::Csv`].
    #[must_use]
    pub fn csv(s: impl Into<String>) -> Self {
        Self::Csv(s.into())
    }

    /// Construct an [`ReportError::UnsafeFilename`].
    #[must_use]
    pub fn unsafe_filename(s: impl Into<String>) -> Self {
        Self::UnsafeFilename(s.into())
    }

    /// Construct an [`ReportError::Internal`].
    #[must_use]
    pub fn internal(s: impl Into<String>) -> Self {
        Self::Internal(s.into())
    }
}

#[cfg(test)]
mod tests {
    use super::ReportError;

    #[test]
    fn display_includes_reason() {
        assert_eq!(
            ReportError::unsupported_format("xml").to_string(),
            "unsupported report format: xml"
        );
        assert_eq!(
            ReportError::pdf("layout").to_string(),
            "pdf rendering failed: layout"
        );
    }
}
