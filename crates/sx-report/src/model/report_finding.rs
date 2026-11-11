//! Renderer-facing finding row.

use serde::{Deserialize, Serialize};
use sx_core::value_object::cvss::CvssScore;
use sx_core::value_object::ids::FindingId;
use sx_core::value_object::severity::Severity;

/// Lifecycle status — flattened to a string so renderers don't need to
/// import the full domain enum.
///
/// Adapters convert from [`sx_core::entity::finding_status::FindingStatus`]
/// via `Display`.
pub type FindingStatusLabel = String;

/// One row in a report, denormalised for rendering.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportFinding {
    /// Stable finding identifier (`UUIDv7`).
    pub id: FindingId,
    /// Human-readable label for the affected asset (FQDN, URL or asset name).
    pub asset_label: String,
    /// Severity bucket.
    pub severity: Severity,
    /// Short title.
    pub title: String,
    /// Free-form Markdown description.
    pub description: String,
    /// CVSS score envelope, when known.
    pub cvss: Option<CvssScore>,
    /// Finding lifecycle status, lower-snake-cased.
    pub status: FindingStatusLabel,
    /// External references — RFC-3986 URIs (advisories, CWE, vendor pages).
    pub references: Vec<String>,
}

impl ReportFinding {
    /// Helper to build a [`ReportFinding`]. All free-form fields are
    /// trimmed; empty `title` is rejected.
    ///
    /// # Errors
    /// Returns [`crate::ReportError::InvalidContext`] if `title` is empty
    /// after trimming.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: FindingId,
        asset_label: impl Into<String>,
        severity: Severity,
        title: impl Into<String>,
        description: impl Into<String>,
        cvss: Option<CvssScore>,
        status: impl Into<String>,
        references: Vec<String>,
    ) -> Result<Self, crate::ReportError> {
        let title = title.into().trim().to_owned();
        if title.is_empty() {
            return Err(crate::ReportError::invalid_context(
                "report finding title cannot be empty",
            ));
        }
        Ok(Self {
            id,
            asset_label: asset_label.into(),
            severity,
            title,
            description: description.into(),
            cvss,
            status: status.into(),
            references,
        })
    }

    /// Best CVSS score for display: prefer v4, fall back to v3.
    #[must_use]
    pub fn cvss_primary(&self) -> Option<f32> {
        self.cvss.map(|c| c.primary())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_title() {
        let r = ReportFinding::new(
            FindingId::new(),
            "asset",
            Severity::High,
            "   ",
            "",
            None,
            "discovered",
            vec![],
        );
        assert!(r.is_err());
    }

    #[test]
    fn cvss_primary_prefers_v4() {
        let f = ReportFinding::new(
            FindingId::new(),
            "asset",
            Severity::High,
            "t",
            "",
            Some(CvssScore::new(Some(7.0), Some(8.0)).unwrap()),
            "discovered",
            vec![],
        )
        .unwrap();
        assert!((f.cvss_primary().unwrap() - 8.0).abs() < 1e-6);
    }
}
