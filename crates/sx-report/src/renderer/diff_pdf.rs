//! Differential PDF renderer.
//!
//! Reuses the same printpdf pipeline as the technical/executive renderers
//! ([`super::pdf_common`]) but renders three columns — Added / Resolved /
//! Regressed — plus a per-severity drift bar chart. The PDF is
//! deterministic for a given [`ReportContext::diff`] payload.

use async_trait::async_trait;
use printpdf::{Color, Mm, PdfConformance, PdfDocument, PdfLayerReference, Rgb};
use sx_core::value_object::severity::Severity;

use crate::diff::{DiffFinding, ReportDiff, SeverityDriftEntry};
use crate::error::ReportError;
use crate::model::report::ReportContext;
use crate::port::{Renderer, ReportArtifact, ReportFormat};
use crate::renderer::pdf_common::{
    add_builtin_fonts, draw_hline, draw_text, fill_rect, fmt_timestamp, normalise_pdf_bytes,
    severity_color, wrap_text, BuiltinFonts, MARGIN_X_MM, MARGIN_Y_MM, PAGE_H_MM, PAGE_W_MM,
};

/// Differential PDF renderer.
#[derive(Debug, Default, Clone, Copy)]
pub struct DiffPdfRenderer;

impl DiffPdfRenderer {
    /// Construct a [`DiffPdfRenderer`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Renderer for DiffPdfRenderer {
    fn format(&self) -> ReportFormat {
        ReportFormat::DiffPdf
    }

    async fn render(&self, ctx: &ReportContext) -> Result<ReportArtifact, ReportError> {
        let diff = ctx.diff.as_ref().ok_or_else(|| {
            ReportError::invalid_context("diff_pdf renderer requires ctx.diff to be set")
        })?;
        let bytes = render_diff(ctx, diff)?;
        let bytes = normalise_pdf_bytes(bytes, ctx);
        let filename = format!("diff-{}.pdf", ctx.date_slug());
        ReportArtifact::new(ReportFormat::DiffPdf, filename, bytes)
    }
}

fn render_diff(ctx: &ReportContext, diff: &ReportDiff) -> Result<Vec<u8>, ReportError> {
    let (doc, cover_page, cover_layer) = PdfDocument::new(
        "SentinelX Differential Report",
        Mm(PAGE_W_MM),
        Mm(PAGE_H_MM),
        "cover",
    );
    let doc = doc
        .with_creation_date(ctx.generated_at)
        .with_metadata_date(ctx.generated_at)
        .with_mod_date(ctx.generated_at)
        .with_document_id(deterministic_doc_id(ctx))
        .with_author("SentinelX")
        .with_creator("SentinelX Reporting Engine")
        .with_producer(concat!("SentinelX/", env!("CARGO_PKG_VERSION")))
        .with_conformance(PdfConformance::default());

    let fonts = add_builtin_fonts(&doc)?;

    // Cover.
    {
        let layer = doc.get_page(cover_page).get_layer(cover_layer);
        draw_cover(&layer, ctx, diff, &fonts);
    }

    // Severity drift chart.
    let (drift_page, drift_layer_idx) = doc.add_page(Mm(PAGE_W_MM), Mm(PAGE_H_MM), "drift");
    {
        let layer = doc.get_page(drift_page).get_layer(drift_layer_idx);
        draw_drift(&layer, diff, &fonts);
    }

    // Three sections — each on its own page for the sake of layout.
    let sections: &[(&str, &[DiffFinding], Color)] = &[
        (
            "Added (NEW)",
            &diff.added,
            Color::Rgb(Rgb::new(0.13, 0.55, 0.13, None)),
        ),
        (
            "Resolved",
            &diff.resolved,
            Color::Rgb(Rgb::new(0.30, 0.55, 0.85, None)),
        ),
        (
            "Regressed (REOPENED)",
            &diff.reopened,
            Color::Rgb(Rgb::new(0.78, 0.10, 0.12, None)),
        ),
    ];

    for (title, findings, accent) in sections {
        let (page, layer_idx) = doc.add_page(Mm(PAGE_W_MM), Mm(PAGE_H_MM), *title);
        let layer = doc.get_page(page).get_layer(layer_idx);
        draw_section(&layer, title, findings, accent.clone(), &fonts);
    }

    doc.save_to_bytes()
        .map_err(|e| ReportError::pdf(e.to_string()))
}

fn deterministic_doc_id(ctx: &ReportContext) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"diff|");
    h.update(ctx.tenant_id.to_string().as_bytes());
    h.update(b"|");
    h.update(ctx.engagement_id.to_string().as_bytes());
    let digest = h.finalize();
    let slice = digest.get(..16).unwrap_or(digest.as_slice());
    hex::encode(slice)
}

fn draw_cover(
    layer: &PdfLayerReference,
    ctx: &ReportContext,
    diff: &ReportDiff,
    fonts: &BuiltinFonts,
) {
    fill_rect(
        layer,
        0.0,
        PAGE_H_MM - 12.0,
        PAGE_W_MM,
        12.0,
        Color::Rgb(Rgb::new(0.13, 0.27, 0.55, None)),
    );
    layer.set_fill_color(Color::Rgb(Rgb::new(1.0, 1.0, 1.0, None)));
    draw_text(
        layer,
        "CONFIDENTIAL - DIFFERENTIAL REPORT",
        14.0,
        MARGIN_X_MM,
        PAGE_H_MM - 9.0,
        &fonts.bold,
    );
    layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));

    draw_text(
        layer,
        "SentinelX Differential Report",
        24.0,
        MARGIN_X_MM,
        PAGE_H_MM - 55.0,
        &fonts.bold,
    );

    let mut y = PAGE_H_MM - 75.0;
    let line = |layer: &PdfLayerReference, label: &str, value: &str, y: f32| {
        draw_text(layer, label, 11.0, MARGIN_X_MM, y, &fonts.bold);
        draw_text(layer, value, 11.0, MARGIN_X_MM + 50.0, y, &fonts.regular);
    };
    line(layer, "Tenant:", &ctx.tenant_name, y);
    y -= 7.0;
    line(layer, "Engagement:", &ctx.engagement_name, y);
    y -= 7.0;
    line(layer, "Generated:", &fmt_timestamp(&ctx.generated_at), y);
    y -= 7.0;
    line(layer, "Window since:", &fmt_timestamp(&diff.since), y);
    y -= 7.0;
    line(layer, "Window until:", &fmt_timestamp(&diff.until), y);
    y -= 7.0;
    line(layer, "Findings added:", &diff.added.len().to_string(), y);
    y -= 7.0;
    line(
        layer,
        "Findings resolved:",
        &diff.resolved.len().to_string(),
        y,
    );
    y -= 7.0;
    line(
        layer,
        "Findings regressed:",
        &diff.reopened.len().to_string(),
        y,
    );
    y -= 7.0;
    line(
        layer,
        "Net change:",
        &format!("{:+}", diff.metrics.net_change_count),
        y,
    );

    draw_hline(
        layer,
        MARGIN_X_MM,
        PAGE_W_MM - MARGIN_X_MM,
        MARGIN_Y_MM,
        0.5,
    );
    draw_text(
        layer,
        "Window-bounded delta of findings: Added, Resolved, Regressed, plus severity drift.",
        9.0,
        MARGIN_X_MM,
        MARGIN_Y_MM - 5.0,
        &fonts.italic,
    );
}

fn draw_drift(layer: &PdfLayerReference, diff: &ReportDiff, fonts: &BuiltinFonts) {
    draw_text(
        layer,
        "Severity Drift (Before / After)",
        18.0,
        MARGIN_X_MM,
        PAGE_H_MM - 30.0,
        &fonts.bold,
    );
    draw_hline(
        layer,
        MARGIN_X_MM,
        PAGE_W_MM - MARGIN_X_MM,
        PAGE_H_MM - 34.0,
        0.4,
    );

    // Always render the canonical ordering Critical, High, Medium, Low, Info.
    let order = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    let mut y = PAGE_H_MM - 50.0;
    let bar_max = 110.0; // mm

    // Pick a max value across both before/after to normalise the bar widths.
    let max_count: u32 = order
        .iter()
        .map(|s| {
            let e = diff
                .severity_drift
                .get(s)
                .copied()
                .unwrap_or_else(SeverityDriftEntry::default);
            e.before.max(e.after)
        })
        .max()
        .unwrap_or(1)
        .max(1);

    for sev in order {
        let entry = diff.severity_drift.get(&sev).copied().unwrap_or_default();
        draw_text(
            layer,
            &sev.to_string().to_ascii_uppercase(),
            10.0,
            MARGIN_X_MM,
            y + 2.0,
            &fonts.bold,
        );

        // Before bar.
        let before_w = bar_max * f32::from(u16::try_from(entry.before).unwrap_or(u16::MAX))
            / f32::from(u16::try_from(max_count).unwrap_or(u16::MAX));
        fill_rect(
            layer,
            MARGIN_X_MM + 30.0,
            y,
            before_w.max(0.5),
            5.0,
            Color::Rgb(Rgb::new(0.55, 0.55, 0.55, None)),
        );
        layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
        draw_text(
            layer,
            &format!("before {}", entry.before),
            8.0,
            MARGIN_X_MM + 30.0 + before_w.max(0.5) + 2.0,
            y + 1.5,
            &fonts.regular,
        );
        y -= 6.0;

        // After bar.
        let after_w = bar_max * f32::from(u16::try_from(entry.after).unwrap_or(u16::MAX))
            / f32::from(u16::try_from(max_count).unwrap_or(u16::MAX));
        fill_rect(
            layer,
            MARGIN_X_MM + 30.0,
            y,
            after_w.max(0.5),
            5.0,
            severity_color(sev),
        );
        layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
        draw_text(
            layer,
            &format!("after  {}  (delta {:+})", entry.after, entry.delta()),
            8.0,
            MARGIN_X_MM + 30.0 + after_w.max(0.5) + 2.0,
            y + 1.5,
            &fonts.regular,
        );
        y -= 12.0;
    }
}

fn draw_section(
    layer: &PdfLayerReference,
    title: &str,
    findings: &[DiffFinding],
    accent: Color,
    fonts: &BuiltinFonts,
) {
    // Accent banner.
    fill_rect(layer, 0.0, PAGE_H_MM - 12.0, PAGE_W_MM, 12.0, accent);
    layer.set_fill_color(Color::Rgb(Rgb::new(1.0, 1.0, 1.0, None)));
    draw_text(
        layer,
        title,
        14.0,
        MARGIN_X_MM,
        PAGE_H_MM - 9.0,
        &fonts.bold,
    );
    layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));

    let mut y = PAGE_H_MM - 30.0;
    draw_text(
        layer,
        &format!("{} finding(s)", findings.len()),
        11.0,
        MARGIN_X_MM,
        y,
        &fonts.italic,
    );
    y -= 8.0;

    if findings.is_empty() {
        draw_text(
            layer,
            "(none in this window)",
            11.0,
            MARGIN_X_MM,
            y,
            &fonts.italic,
        );
        return;
    }

    for f in findings {
        if y < MARGIN_Y_MM + 10.0 {
            // Single-page section — bail rather than overflowing.
            draw_text(layer, "[...]", 9.0, MARGIN_X_MM, y, &fonts.italic);
            break;
        }
        // Severity tag.
        let badge_w = 20.0;
        let badge_h = 5.0;
        fill_rect(
            layer,
            MARGIN_X_MM,
            y,
            badge_w,
            badge_h,
            severity_color(f.severity),
        );
        layer.set_fill_color(Color::Rgb(Rgb::new(1.0, 1.0, 1.0, None)));
        draw_text(
            layer,
            &f.severity.to_string().to_ascii_uppercase(),
            7.0,
            MARGIN_X_MM + 2.0,
            y + 1.0,
            &fonts.bold,
        );
        layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));

        // Title.
        let title_x = MARGIN_X_MM + badge_w + 4.0;
        let title_lines = wrap_text(&f.title, 60);
        let first_line = title_lines.first().map_or("", String::as_str);
        draw_text(layer, first_line, 11.0, title_x, y + 1.0, &fonts.bold);
        y -= 5.0;
        // Footer of the row: status + id.
        draw_text(
            layer,
            &format!("status={}   id={}", f.status, f.id),
            8.0,
            title_x,
            y,
            &fonts.regular,
        );
        y -= 6.0;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::case_sensitive_file_extension_comparisons)]
mod tests {
    use super::*;
    use crate::diff::{compute_diff_in_memory, FindingSnapshot};
    use crate::model::posture::PostureSummary;
    use sx_core::value_object::ids::{EngagementId, FindingId, TenantId};
    use time::macros::datetime;

    fn ctx_with_diff() -> ReportContext {
        let since = datetime!(2026-05-23 00:00:00 UTC);
        let until = datetime!(2026-05-30 00:00:00 UTC);
        let snap = FindingSnapshot {
            id: FindingId::new(),
            engagement_id: None,
            severity: Severity::High,
            title: "Diff item".to_owned(),
            status: "open".to_owned(),
            first_seen: datetime!(2026-05-25 12:00:00 UTC),
            last_seen: datetime!(2026-05-25 12:00:00 UTC),
        };
        let diff =
            compute_diff_in_memory(TenantId::new(), EngagementId::new(), since, until, &[snap]);
        ReportContext::new(
            TenantId::new(),
            EngagementId::new(),
            "Acme",
            "Q2",
            "ops",
            datetime!(2026-05-30 12:00:00 UTC),
            PostureSummary::empty(),
            vec![],
        )
        .unwrap()
        .with_diff(diff)
    }

    #[tokio::test]
    async fn diff_pdf_renders_when_diff_present() {
        let ctx = ctx_with_diff();
        let art = DiffPdfRenderer::new().render(&ctx).await.unwrap();
        assert!(art.bytes.starts_with(b"%PDF-"));
        assert_eq!(art.format, ReportFormat::DiffPdf);
        assert!(art.filename.ends_with(".pdf"));
    }

    #[tokio::test]
    async fn diff_pdf_errors_when_diff_missing() {
        let ctx = ReportContext::new(
            TenantId::new(),
            EngagementId::new(),
            "Acme",
            "Q2",
            "ops",
            datetime!(2026-05-30 12:00:00 UTC),
            PostureSummary::empty(),
            vec![],
        )
        .unwrap();
        let res = DiffPdfRenderer::new().render(&ctx).await;
        assert!(res.is_err());
    }
}
