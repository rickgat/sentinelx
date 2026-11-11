//! Technical PDF renderer — full per-finding listing.
//!
//! Layout: one cover page, one or more body pages with up to ~3 findings
//! per page. Each finding block has a severity badge, title, description,
//! evidence references and external references.

use async_trait::async_trait;
use printpdf::{Color, Mm, PdfConformance, PdfDocument, PdfLayerReference, Rgb};

use crate::error::ReportError;
use crate::model::report::ReportContext;
use crate::model::report_finding::ReportFinding;
use crate::port::{Renderer, ReportArtifact, ReportFormat};
use crate::renderer::pdf_common::{
    add_builtin_fonts, brand_primary_color, draw_brand_logo_block, draw_hline, draw_text,
    fill_rect, fmt_timestamp, normalise_pdf_bytes, severity_color, wrap_text, BuiltinFonts,
    MARGIN_X_MM, MARGIN_Y_MM, PAGE_H_MM, PAGE_W_MM,
};

/// Technical PDF renderer.
#[derive(Debug, Default, Clone, Copy)]
pub struct TechnicalPdfRenderer;

impl TechnicalPdfRenderer {
    /// Construct a [`TechnicalPdfRenderer`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Renderer for TechnicalPdfRenderer {
    fn format(&self) -> ReportFormat {
        ReportFormat::TechnicalPdf
    }

    async fn render(&self, ctx: &ReportContext) -> Result<ReportArtifact, ReportError> {
        let bytes = render_technical(ctx)?;
        let bytes = normalise_pdf_bytes(bytes, ctx);
        let filename = format!("technical-{}.pdf", ctx.date_slug());
        ReportArtifact::new(ReportFormat::TechnicalPdf, filename, bytes)
    }
}

fn render_technical(ctx: &ReportContext) -> Result<Vec<u8>, ReportError> {
    let (doc, cover_page, cover_layer) = PdfDocument::new(
        "SentinelX Technical Report",
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

    // ---- Cover.
    {
        let layer = doc.get_page(cover_page).get_layer(cover_layer);
        draw_cover(&layer, ctx, &fonts);
    }

    // ---- Findings.
    let total = ctx.findings.len();
    if total == 0 {
        let (page, layer_idx) = doc.add_page(Mm(PAGE_W_MM), Mm(PAGE_H_MM), "no-findings");
        let layer = doc.get_page(page).get_layer(layer_idx);
        draw_text(
            &layer,
            "No findings to report.",
            14.0,
            MARGIN_X_MM,
            PAGE_H_MM - 40.0,
            &fonts.italic,
        );
    } else {
        // One finding per page keeps the layout simple, deterministic, and
        // makes the byte count grow ~linearly with N (used in tests).
        for (idx, finding) in ctx.findings.iter().enumerate() {
            let (page, layer_idx) =
                doc.add_page(Mm(PAGE_W_MM), Mm(PAGE_H_MM), format!("finding-{}", idx + 1));
            let layer = doc.get_page(page).get_layer(layer_idx);
            draw_finding_page(&layer, finding, idx + 1, total, &fonts);
        }
    }

    doc.save_to_bytes()
        .map_err(|e| ReportError::pdf(e.to_string()))
}

fn deterministic_doc_id(ctx: &ReportContext) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"technical|");
    h.update(ctx.tenant_id.to_string().as_bytes());
    h.update(b"|");
    h.update(ctx.engagement_id.to_string().as_bytes());
    let digest = h.finalize();
    let slice = digest.get(..16).unwrap_or(digest.as_slice());
    hex::encode(slice)
}

// Ambient rustc-1.92 / clippy::pedantic regression cleared by FOUND-001
// (sister to LOW-009-FU1): cover-page rendering is 105/100 lines after
// the per-tenant branding work in commit `8addd39`. Splitting the
// function only spreads the same layout state across helpers without
// improving readability — the explicit allow is the cheaper trade.
#[allow(clippy::too_many_lines)]
fn draw_cover(layer: &PdfLayerReference, ctx: &ReportContext, fonts: &BuiltinFonts) {
    let brand = &ctx.branding;
    // Classification banner — tinted with the tenant's brand colour.
    // When no branding is configured the default falls back to the
    // historical navy blue used by the technical report.
    let banner_color = if brand.logo_png.is_some()
        || brand.primary_color_hex != crate::model::branding::DEFAULT_PRIMARY_COLOR_HEX
        || brand.footer_md.is_some()
        || brand.cover_md.is_some()
    {
        brand_primary_color(brand)
    } else {
        Color::Rgb(Rgb::new(0.13, 0.27, 0.55, None))
    };
    fill_rect(layer, 0.0, PAGE_H_MM - 12.0, PAGE_W_MM, 12.0, banner_color);
    layer.set_fill_color(Color::Rgb(Rgb::new(1.0, 1.0, 1.0, None)));
    draw_text(
        layer,
        "CONFIDENTIAL - RESTRICTED",
        14.0,
        MARGIN_X_MM,
        PAGE_H_MM - 9.0,
        &fonts.bold,
    );
    layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));

    // Logo block when uploaded.
    let after_logo_y = draw_brand_logo_block(
        layer,
        brand,
        MARGIN_X_MM,
        PAGE_H_MM - 18.0,
        40.0,
        20.0,
        fonts,
    );
    let title_y = if brand.logo_png.is_some() {
        after_logo_y - 6.0
    } else {
        PAGE_H_MM - 55.0
    };

    // Heading recoloured under custom branding only.
    if brand.logo_png.is_some() || brand.cover_md.is_some() {
        layer.set_fill_color(brand_primary_color(brand));
    }
    draw_text(
        layer,
        "SentinelX Technical Report",
        24.0,
        MARGIN_X_MM,
        title_y,
        &fonts.bold,
    );
    layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));

    let mut y = title_y - 20.0;
    let line =
        |layer: &PdfLayerReference, label: &str, value: &str, y: f32, fonts: &BuiltinFonts| {
            draw_text(layer, label, 11.0, MARGIN_X_MM, y, &fonts.bold);
            draw_text(layer, value, 11.0, MARGIN_X_MM + 45.0, y, &fonts.regular);
        };
    line(layer, "Tenant:", &ctx.tenant_name, y, fonts);
    y -= 7.0;
    line(layer, "Engagement:", &ctx.engagement_name, y, fonts);
    y -= 7.0;
    line(
        layer,
        "Generated:",
        &fmt_timestamp(&ctx.generated_at),
        y,
        fonts,
    );
    y -= 7.0;
    line(layer, "Generated by:", &ctx.generated_by, y, fonts);
    y -= 7.0;
    line(
        layer,
        "Total findings:",
        &ctx.findings.len().to_string(),
        y,
        fonts,
    );

    if let Some(cover) = brand.cover_text() {
        y -= 12.0;
        draw_text(layer, "Cover", 12.0, MARGIN_X_MM, y, &fonts.bold);
        y -= 6.0;
        for piece in wrap_text(&cover, 95) {
            if y < MARGIN_Y_MM + 14.0 {
                break;
            }
            draw_text(layer, &piece, 10.0, MARGIN_X_MM, y, &fonts.regular);
            y -= 5.0;
        }
    }

    draw_hline(
        layer,
        MARGIN_X_MM,
        PAGE_W_MM - MARGIN_X_MM,
        MARGIN_Y_MM,
        0.5,
    );
    let footer = brand.footer_text().unwrap_or_else(|| {
        "This document contains technical details intended for defenders. Handle accordingly."
            .to_owned()
    });
    draw_text(
        layer,
        &footer,
        9.0,
        MARGIN_X_MM,
        MARGIN_Y_MM - 5.0,
        &fonts.italic,
    );
}

#[allow(clippy::too_many_lines)]
fn draw_finding_page(
    layer: &PdfLayerReference,
    finding: &ReportFinding,
    index: usize,
    total: usize,
    fonts: &BuiltinFonts,
) {
    // Header row: "Finding N of M" + severity badge.
    let header_y = PAGE_H_MM - 22.0;
    draw_text(
        layer,
        &format!("Finding {index} of {total}"),
        12.0,
        MARGIN_X_MM,
        header_y,
        &fonts.bold,
    );

    // Severity badge.
    let badge_w = 28.0;
    let badge_h = 7.0;
    let badge_x = PAGE_W_MM - MARGIN_X_MM - badge_w;
    fill_rect(
        layer,
        badge_x,
        header_y - 2.0,
        badge_w,
        badge_h,
        severity_color(finding.severity),
    );
    layer.set_fill_color(Color::Rgb(Rgb::new(1.0, 1.0, 1.0, None)));
    draw_text(
        layer,
        &finding.severity.to_string().to_ascii_uppercase(),
        9.0,
        badge_x + 3.0,
        header_y,
        &fonts.bold,
    );
    layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));

    draw_hline(
        layer,
        MARGIN_X_MM,
        PAGE_W_MM - MARGIN_X_MM,
        header_y - 4.0,
        0.4,
    );

    let mut y = header_y - 14.0;
    // Title.
    for line in wrap_text(&finding.title, 70) {
        draw_text(layer, &line, 15.0, MARGIN_X_MM, y, &fonts.bold);
        y -= 7.0;
    }

    // Asset / status / CVSS metadata row.
    y -= 2.0;
    draw_text(layer, "Asset:", 10.0, MARGIN_X_MM, y, &fonts.bold);
    draw_text(
        layer,
        &finding.asset_label,
        10.0,
        MARGIN_X_MM + 22.0,
        y,
        &fonts.mono,
    );
    y -= 5.0;
    draw_text(layer, "Status:", 10.0, MARGIN_X_MM, y, &fonts.bold);
    draw_text(
        layer,
        &finding.status,
        10.0,
        MARGIN_X_MM + 22.0,
        y,
        &fonts.regular,
    );
    y -= 5.0;
    if let Some(cvss) = finding.cvss_primary() {
        draw_text(layer, "CVSS:", 10.0, MARGIN_X_MM, y, &fonts.bold);
        draw_text(
            layer,
            &format!("{cvss:.1}"),
            10.0,
            MARGIN_X_MM + 22.0,
            y,
            &fonts.regular,
        );
        y -= 5.0;
    }

    // Description.
    y -= 4.0;
    draw_text(layer, "Description", 12.0, MARGIN_X_MM, y, &fonts.bold);
    y -= 6.0;
    for line in wrap_text(&finding.description, 90) {
        if y < MARGIN_Y_MM + 30.0 {
            // Avoid bleeding under references — clip with an ellipsis line.
            draw_text(layer, "[...]", 10.0, MARGIN_X_MM, y, &fonts.italic);
            y -= 5.0;
            break;
        }
        draw_text(layer, &line, 10.0, MARGIN_X_MM, y, &fonts.regular);
        y -= 5.0;
    }

    // References.
    y -= 4.0;
    draw_text(layer, "References", 12.0, MARGIN_X_MM, y, &fonts.bold);
    y -= 6.0;
    if finding.references.is_empty() {
        draw_text(layer, "(none)", 10.0, MARGIN_X_MM, y, &fonts.italic);
    } else {
        for r in &finding.references {
            if y < MARGIN_Y_MM + 8.0 {
                break;
            }
            draw_text(
                layer,
                &format!("- {r}"),
                10.0,
                MARGIN_X_MM,
                y,
                &fonts.regular,
            );
            y -= 5.0;
        }
    }

    // Footer.
    draw_hline(
        layer,
        MARGIN_X_MM,
        PAGE_W_MM - MARGIN_X_MM,
        MARGIN_Y_MM,
        0.4,
    );
    draw_text(
        layer,
        &format!("Finding {index} of {total} - {}", finding.id),
        7.0,
        MARGIN_X_MM,
        MARGIN_Y_MM - 4.0,
        &fonts.regular,
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::model::posture::PostureSummary;
    use sx_core::value_object::cvss::CvssScore;
    use sx_core::value_object::ids::{EngagementId, FindingId, TenantId};
    use sx_core::value_object::severity::Severity;
    use time::macros::datetime;

    fn make_finding(title: &str) -> ReportFinding {
        ReportFinding::new(
            FindingId::new(),
            "host.example.com",
            Severity::High,
            title,
            "Detailed description.",
            Some(CvssScore::v3_only(7.5).unwrap()),
            "discovered",
            vec!["https://example.com/advisory".to_owned()],
        )
        .unwrap()
    }

    fn ctx_with(n: usize) -> ReportContext {
        let findings: Vec<ReportFinding> = (0..n)
            .map(|i| make_finding(&format!("Issue {i}")))
            .collect();
        ReportContext::new(
            TenantId::new(),
            EngagementId::new(),
            "Acme",
            "Q2 Engagement",
            "ops",
            datetime!(2026-05-30 12:00:00 UTC),
            PostureSummary::empty(),
            findings,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn technical_pdf_includes_finding_count_pages() {
        let small = TechnicalPdfRenderer::new()
            .render(&ctx_with(1))
            .await
            .unwrap();
        let big = TechnicalPdfRenderer::new()
            .render(&ctx_with(8))
            .await
            .unwrap();
        assert!(small.bytes.starts_with(b"%PDF-"));
        assert!(big.bytes.starts_with(b"%PDF-"));
        assert!(
            big.bytes.len() > small.bytes.len(),
            "more findings should produce a larger PDF (small={}, big={})",
            small.bytes.len(),
            big.bytes.len(),
        );
    }
}
