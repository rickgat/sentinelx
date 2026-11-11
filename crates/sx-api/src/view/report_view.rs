//! Report-rendering DTOs.
//!
//! PDF payloads are intentionally large; the HTTP layer never embeds a
//! base64-encoded PDF into the JSON envelope. For `executive_pdf`,
//! `technical_pdf` and `diff_pdf`, `inline_payload` is always `None` and
//! the caller is expected to follow up with a download endpoint. For the
//! text-like formats (`sarif`, `stix`, `csv`), `inline_payload` carries
//! the base64 payload so the caller can render the artifact in a single
//! round trip.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /v1/reports/render` request body.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct ReportRenderRequestView {
    /// Tenant uuid that owns the engagement.
    #[validate(length(min = 1))]
    pub tenant_id: String,
    /// Engagement uuid to render.
    #[validate(length(min = 1))]
    pub engagement_id: String,
    /// Output format. One of: `executive_pdf`, `technical_pdf`, `sarif`,
    /// `stix`, `csv`, `diff_pdf`.
    #[validate(custom(function = "validate_format"))]
    pub format: String,
}

/// `POST /v1/reports/render` response body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReportRenderResponseView {
    /// Suggested file name (with extension).
    pub filename: String,
    /// MIME type of the rendered artifact.
    pub mime_type: String,
    /// Byte count of the rendered artifact.
    pub byte_count: usize,
    /// Base64-encoded payload — present only for SARIF/STIX/CSV formats.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inline_payload: Option<String>,
}

/// `POST /v1/reports/diff` request body.
///
/// Carries the engagement scope and a `[since, until]` RFC-3339 UTC window
/// the differential engine compares against the engagement's findings.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct ReportDiffRequestView {
    /// Tenant uuid that owns the engagement. The handler force-overwrites
    /// this with the authenticated tenant scope, so a client cannot diff
    /// another tenant by mutating the body.
    #[validate(length(min = 1))]
    pub tenant_id: String,
    /// Engagement uuid to diff.
    #[validate(length(min = 1))]
    pub engagement_id: String,
    /// Window lower bound, RFC-3339 UTC. Inclusive.
    #[validate(length(min = 1))]
    pub since: String,
    /// Window upper bound, RFC-3339 UTC. Inclusive. Must be strictly after
    /// `since`.
    #[validate(length(min = 1))]
    pub until: String,
    /// Whether to also materialise a `diff_pdf` artifact. When `false`, the
    /// response carries only the JSON summary. Defaults to `false`.
    #[serde(default)]
    pub render_pdf: bool,
}

/// One finding row inside a diff bucket.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiffFindingView {
    /// Finding id.
    pub id: String,
    /// Severity bucket — lower-case (`critical`, `high`, …, `info`).
    pub severity: String,
    /// Short title.
    pub title: String,
    /// Lifecycle status at the time of the diff.
    pub status: String,
    /// First-seen RFC-3339 UTC timestamp.
    pub first_seen: String,
    /// Last-seen RFC-3339 UTC timestamp.
    pub last_seen: String,
}

/// Per-severity drift datum.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SeverityDriftEntryView {
    /// Severity bucket.
    pub severity: String,
    /// Count of open findings before the window started.
    pub before: u32,
    /// Count of open findings after the window closed.
    pub after: u32,
    /// `after - before`.
    pub delta: i64,
}

/// Top-line metrics block.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiffMetricsView {
    /// `added.len() - resolved.len()`.
    pub net_change_count: i64,
    /// `reopened.len()`.
    pub regression_count: u32,
}

/// Narrow projection of a previously rendered report.
///
/// Backs `GET /v1/reports`. Carries only the metadata the dashboard
/// list view renders — the full base64 payload is intentionally
/// excluded so the list response stays small even when the in-memory
/// dispatcher retains many entries.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReportSummaryView {
    /// Stable report id (uuid v7 minted at render time).
    pub id: String,
    /// Report kind — mirrors the `format` string accepted by render
    /// (`executive_pdf`, `technical_pdf`, `sarif`, `stix`, `csv`,
    /// `diff_pdf`).
    pub kind: String,
    /// RFC 3339 UTC timestamp the report was rendered at.
    pub generated_at: String,
    /// Output format (echoes `kind` today; kept separate so a future
    /// schema can split logical kind from wire format).
    pub format: String,
    /// Byte count of the rendered artifact.
    pub size_bytes: usize,
}

/// `POST /v1/reports/diff` response body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReportDiffResponseView {
    /// Tenant uuid (echoed back).
    pub tenant_id: String,
    /// Engagement uuid (echoed back).
    pub engagement_id: String,
    /// Window lower bound (RFC-3339 UTC).
    pub since: String,
    /// Window upper bound (RFC-3339 UTC).
    pub until: String,
    /// Findings whose `first_seen` falls inside the window.
    pub added: Vec<DiffFindingView>,
    /// Findings closed/accepted inside the window.
    pub resolved: Vec<DiffFindingView>,
    /// Findings re-opened (first seen before window, still open, last
    /// touched in window).
    pub reopened: Vec<DiffFindingView>,
    /// Per-severity drift list, sorted Critical → Info for deterministic
    /// output.
    pub severity_drift: Vec<SeverityDriftEntryView>,
    /// Derived metrics.
    pub metrics: DiffMetricsView,
    /// Optional rendered PDF artifact metadata — present when `render_pdf`
    /// was set on the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdf: Option<ReportRenderResponseView>,
}

/// Validate that `value` is one of the supported render formats.
fn validate_format(value: &str) -> Result<(), validator::ValidationError> {
    match value {
        "executive_pdf" | "technical_pdf" | "sarif" | "stix" | "csv" | "diff_pdf" => Ok(()),
        _ => Err(validator::ValidationError::new("invalid_format")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_supported_formats() {
        for f in [
            "executive_pdf",
            "technical_pdf",
            "sarif",
            "stix",
            "csv",
            "diff_pdf",
        ] {
            let r = ReportRenderRequestView {
                tenant_id: "t".into(),
                engagement_id: "e".into(),
                format: f.into(),
            };
            assert!(r.validate().is_ok(), "should accept {f}");
        }
    }

    #[test]
    fn rejects_unknown_format() {
        let r = ReportRenderRequestView {
            tenant_id: "t".into(),
            engagement_id: "e".into(),
            format: "docx".into(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn diff_request_validates_required_fields() {
        let good = ReportDiffRequestView {
            tenant_id: "t".into(),
            engagement_id: "e".into(),
            since: "2026-05-23T00:00:00Z".into(),
            until: "2026-05-30T00:00:00Z".into(),
            render_pdf: false,
        };
        assert!(good.validate().is_ok());

        let bad = ReportDiffRequestView {
            tenant_id: String::new(),
            engagement_id: "e".into(),
            since: "2026-05-23T00:00:00Z".into(),
            until: "2026-05-30T00:00:00Z".into(),
            render_pdf: false,
        };
        assert!(bad.validate().is_err());
    }
}
