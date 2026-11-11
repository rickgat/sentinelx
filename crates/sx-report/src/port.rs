//! Report-renderer ports.
//!
//! Defines the [`Renderer`] trait and supporting value objects. Concrete
//! renderers live under [`crate::renderer`].

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::ReportError;
use crate::model::report::ReportContext;

/// Output format selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportFormat {
    /// Executive PDF — high-level posture, top-5 risks, trend chart.
    ExecutivePdf,
    /// Technical PDF — full per-finding listing.
    TechnicalPdf,
    /// SARIF 2.1.0 JSON.
    Sarif,
    /// STIX 2.1 bundle JSON.
    Stix,
    /// CSV per-finding export.
    Csv,
    /// Differential PDF — week-over-week (or arbitrary window) diff of
    /// findings. Requires a `[since, until]` window supplied by the caller.
    DiffPdf,
}

impl ReportFormat {
    /// Parse a case-insensitive format string.
    ///
    /// Accepted values:
    /// `executive_pdf` / `executive` / `executive-pdf`,
    /// `technical_pdf` / `technical` / `technical-pdf`,
    /// `sarif`, `stix`, `csv`.
    ///
    /// This is a convenience wrapper around the [`std::str::FromStr`]
    /// implementation so call sites can write
    /// `ReportFormat::from_str("sarif")`.
    ///
    /// # Errors
    /// Returns [`ReportError::UnsupportedFormat`] for unknown strings.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, ReportError> {
        <Self as std::str::FromStr>::from_str(s)
    }

    /// Canonical short form, suitable for filenames and query strings.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ExecutivePdf => "executive_pdf",
            Self::TechnicalPdf => "technical_pdf",
            Self::Sarif => "sarif",
            Self::Stix => "stix",
            Self::Csv => "csv",
            Self::DiffPdf => "diff_pdf",
        }
    }

    /// IANA MIME type for the produced artefact.
    #[must_use]
    pub const fn mime(self) -> &'static str {
        match self {
            Self::ExecutivePdf | Self::TechnicalPdf | Self::DiffPdf => "application/pdf",
            // SARIF is delivered as standard JSON; the registered media-type
            // `application/sarif+json` is unofficial and not yet IANA-registered.
            Self::Sarif | Self::Stix => "application/json",
            Self::Csv => "text/csv; charset=utf-8",
        }
    }

    /// Filename extension (no leading dot).
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::ExecutivePdf | Self::TechnicalPdf | Self::DiffPdf => "pdf",
            Self::Sarif | Self::Stix => "json",
            Self::Csv => "csv",
        }
    }
}

impl std::fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ReportFormat {
    type Err = ReportError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.trim().to_ascii_lowercase();
        Ok(match lower.as_str() {
            "executive_pdf" | "executive" | "executive-pdf" => Self::ExecutivePdf,
            "technical_pdf" | "technical" | "technical-pdf" => Self::TechnicalPdf,
            "sarif" => Self::Sarif,
            "stix" => Self::Stix,
            "csv" => Self::Csv,
            "diff_pdf" | "diff" | "diff-pdf" => Self::DiffPdf,
            _ => return Err(ReportError::unsupported_format(s.to_owned())),
        })
    }
}

/// Output artefact returned by a [`Renderer`].
#[derive(Debug, Clone)]
pub struct ReportArtifact {
    /// Format actually produced.
    pub format: ReportFormat,
    /// MIME content-type, e.g. `application/pdf`.
    pub mime_type: &'static str,
    /// Sanitised filename, e.g. `executive-2026-05-30.pdf`.
    pub filename: String,
    /// Raw bytes.
    pub bytes: Vec<u8>,
}

impl ReportArtifact {
    /// Construct a [`ReportArtifact`], rejecting filenames that contain a
    /// path separator or `..` traversal.
    ///
    /// # Errors
    /// Returns [`ReportError::UnsafeFilename`] when the filename contains
    /// `/`, `\`, `..`, or a NUL byte, or is empty.
    pub fn new(
        format: ReportFormat,
        filename: impl Into<String>,
        bytes: Vec<u8>,
    ) -> Result<Self, ReportError> {
        let filename = filename.into();
        sanitise_filename(&filename)?;
        Ok(Self {
            format,
            mime_type: format.mime(),
            filename,
            bytes,
        })
    }
}

fn sanitise_filename(name: &str) -> Result<(), ReportError> {
    if name.is_empty() {
        return Err(ReportError::unsafe_filename("empty"));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(ReportError::unsafe_filename(format!(
            "path separator in {name}"
        )));
    }
    if name.split('.').any(|seg| seg == "..") || name == ".." {
        return Err(ReportError::unsafe_filename(format!(
            "parent reference in {name}"
        )));
    }
    if name.contains('\0') {
        return Err(ReportError::unsafe_filename(format!("nul byte in {name}")));
    }
    Ok(())
}

/// Polymorphic renderer.
///
/// All renderers are async to keep room for future renderers that perform
/// async work (e.g. fetching a tenant logo from object storage). Phase-1
/// renderers are CPU-bound and return immediately.
#[async_trait]
pub trait Renderer: Send + Sync + std::fmt::Debug {
    /// The format this renderer produces.
    fn format(&self) -> ReportFormat;

    /// Render a [`ReportContext`] into a [`ReportArtifact`].
    ///
    /// # Errors
    /// Implementations propagate [`ReportError`] from their underlying
    /// serializer (`printpdf`, `serde_json`, etc.).
    async fn render(&self, ctx: &ReportContext) -> Result<ReportArtifact, ReportError>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("executive_pdf", ReportFormat::ExecutivePdf)]
    #[case("executive", ReportFormat::ExecutivePdf)]
    #[case("executive-pdf", ReportFormat::ExecutivePdf)]
    #[case("technical_pdf", ReportFormat::TechnicalPdf)]
    #[case("technical", ReportFormat::TechnicalPdf)]
    #[case("SARIF", ReportFormat::Sarif)]
    #[case("Stix", ReportFormat::Stix)]
    #[case(" csv ", ReportFormat::Csv)]
    fn report_format_from_str_round_trip(#[case] input: &str, #[case] expected: ReportFormat) {
        let f = ReportFormat::from_str(input).unwrap();
        assert_eq!(f, expected);
        // Canonical form round-trips through from_str.
        assert_eq!(ReportFormat::from_str(expected.as_str()).unwrap(), expected);
    }

    #[test]
    fn report_format_from_str_rejects_garbage() {
        assert!(ReportFormat::from_str("xml").is_err());
    }

    #[test]
    fn report_format_mime_csv_is_text_csv() {
        assert_eq!(
            ReportFormat::Csv.mime(),
            "text/csv; charset=utf-8",
            "CSV must declare UTF-8 charset"
        );
        assert!(ReportFormat::Csv.mime().starts_with("text/csv"));
    }

    #[test]
    fn report_format_extensions() {
        assert_eq!(ReportFormat::ExecutivePdf.extension(), "pdf");
        assert_eq!(ReportFormat::TechnicalPdf.extension(), "pdf");
        assert_eq!(ReportFormat::Sarif.extension(), "json");
        assert_eq!(ReportFormat::Stix.extension(), "json");
        assert_eq!(ReportFormat::Csv.extension(), "csv");
    }

    #[test]
    fn artifact_rejects_path_traversal() {
        let r = ReportArtifact::new(ReportFormat::Csv, "../escape.csv", vec![]);
        assert!(r.is_err());
        let r = ReportArtifact::new(ReportFormat::Csv, "a/b.csv", vec![]);
        assert!(r.is_err());
        let r = ReportArtifact::new(ReportFormat::Csv, "", vec![]);
        assert!(r.is_err());
    }

    #[test]
    fn artifact_accepts_clean_name() {
        let r = ReportArtifact::new(ReportFormat::Csv, "report-2026-05-30.csv", vec![1, 2, 3]);
        assert!(r.is_ok());
    }
}
