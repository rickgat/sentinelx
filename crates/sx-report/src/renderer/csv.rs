//! RFC-4180 CSV finding export.
//!
//! Columns: `finding_id, severity, title, asset, cvss, status, references`.
//!
//! Output is prefixed with a UTF-8 BOM so Excel opens it correctly.

use async_trait::async_trait;

use crate::error::ReportError;
use crate::model::report::ReportContext;
use crate::port::{Renderer, ReportArtifact, ReportFormat};

/// CSV renderer.
#[derive(Debug, Default, Clone, Copy)]
pub struct CsvRenderer;

impl CsvRenderer {
    /// Construct a [`CsvRenderer`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];
const COLUMNS: &[&str] = &[
    "finding_id",
    "severity",
    "title",
    "asset",
    "cvss",
    "status",
    "references",
];

#[async_trait]
impl Renderer for CsvRenderer {
    fn format(&self) -> ReportFormat {
        ReportFormat::Csv
    }

    async fn render(&self, ctx: &ReportContext) -> Result<ReportArtifact, ReportError> {
        let mut out = Vec::with_capacity(256 + ctx.findings.len() * 128);
        out.extend_from_slice(&UTF8_BOM);
        // Header.
        write_row(&mut out, COLUMNS.iter().copied());
        // Rows.
        for f in &ctx.findings {
            let cvss = f
                .cvss_primary()
                .map(|v| format!("{v:.1}"))
                .unwrap_or_default();
            let refs = f.references.join(";");
            let id = f.id.to_string();
            let sev = f.severity.to_string();
            let cells = [
                id.as_str(),
                sev.as_str(),
                f.title.as_str(),
                f.asset_label.as_str(),
                cvss.as_str(),
                f.status.as_str(),
                refs.as_str(),
            ];
            write_row(&mut out, cells.iter().copied());
        }

        let filename = format!("findings-{}.csv", ctx.date_slug());
        ReportArtifact::new(ReportFormat::Csv, filename, out)
    }
}

fn write_row<'a, I: IntoIterator<Item = &'a str>>(out: &mut Vec<u8>, cells: I) {
    let mut first = true;
    for cell in cells {
        if !first {
            out.push(b',');
        }
        first = false;
        write_field(out, cell);
    }
    // RFC-4180 records use CRLF.
    out.push(b'\r');
    out.push(b'\n');
}

fn write_field(out: &mut Vec<u8>, value: &str) {
    let needs_quote =
        value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r');
    if !needs_quote {
        out.extend_from_slice(value.as_bytes());
        return;
    }
    out.push(b'"');
    for ch in value.chars() {
        if ch == '"' {
            // Escape by doubling.
            out.push(b'"');
            out.push(b'"');
        } else {
            // char -> UTF-8 bytes
            let mut buf = [0u8; 4];
            let s = ch.encode_utf8(&mut buf);
            out.extend_from_slice(s.as_bytes());
        }
    }
    out.push(b'"');
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::model::posture::PostureSummary;
    use crate::model::report_finding::ReportFinding;
    use sx_core::value_object::ids::{EngagementId, FindingId, TenantId};
    use sx_core::value_object::severity::Severity;
    use time::macros::datetime;

    fn ctx_with(findings: Vec<ReportFinding>) -> ReportContext {
        ReportContext::new(
            TenantId::new(),
            EngagementId::new(),
            "Acme",
            "Q2 Engagement",
            "Operator",
            datetime!(2026-05-30 12:00:00 UTC),
            PostureSummary::empty(),
            findings,
        )
        .unwrap()
    }

    fn finding(title: &str, refs: Vec<String>) -> ReportFinding {
        ReportFinding::new(
            FindingId::new(),
            "host.example.com",
            Severity::High,
            title,
            "desc",
            None,
            "discovered",
            refs,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn csv_starts_with_utf8_bom() {
        let ctx = ctx_with(vec![]);
        let art = CsvRenderer::new().render(&ctx).await.unwrap();
        assert_eq!(&art.bytes[..3], &UTF8_BOM, "must begin with UTF-8 BOM");
    }

    #[tokio::test]
    async fn csv_quoting_handles_embedded_commas_and_quotes() {
        let ctx = ctx_with(vec![finding(
            r#"comma, and "quotes" inside"#,
            vec!["https://example.com/a, b".to_owned()],
        )]);
        let art = CsvRenderer::new().render(&ctx).await.unwrap();
        let s = std::str::from_utf8(&art.bytes[3..]).unwrap();
        // Title is quoted and inner quotes doubled.
        assert!(s.contains(r#""comma, and ""quotes"" inside""#));
        // Reference (single field via join with ';') still has a comma => quoted.
        assert!(s.contains(r#""https://example.com/a, b""#));
        // Header row present.
        assert!(s.starts_with("finding_id,severity,title,asset,cvss,status,references\r\n"));
    }

    #[tokio::test]
    async fn csv_filename_includes_date() {
        let ctx = ctx_with(vec![]);
        let art = CsvRenderer::new().render(&ctx).await.unwrap();
        assert_eq!(art.filename, "findings-2026-05-30.csv");
        assert_eq!(art.mime_type, "text/csv; charset=utf-8");
    }
}
