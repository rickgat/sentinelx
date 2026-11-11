//! Executive PDF renderer.
//!
//! Produces a 1-3 page PDF with:
//!
//! - Cover page (tenant, engagement, generation timestamp, classification banner).
//! - Posture summary: bar chart of severity distribution + numeric counts.
//! - Top-5 risks table.
//! - 7-day trend chart (rendered with `printpdf` lines — no SVG).
//!
//! Output is deterministic for a given [`ReportContext`]; see
//! [`super::pdf_common::normalise_pdf_bytes`].

use async_trait::async_trait;
use printpdf::{Mm, PdfConformance, PdfDocument};
use sx_core::value_object::severity::Severity;

use crate::error::ReportError;
use crate::model::report::ReportContext;
use crate::port::{Renderer, ReportArtifact, ReportFormat};
use crate::renderer::pdf_common::{
    add_builtin_fonts, brand_primary_color, draw_brand_logo_block, draw_hline, draw_text,
    fill_rect, fmt_timestamp, normalise_pdf_bytes, severity_color, BuiltinFonts, MARGIN_X_MM,
    MARGIN_Y_MM, PAGE_H_MM, PAGE_W_MM,
};

/// Executive PDF renderer.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExecutivePdfRenderer;

impl ExecutivePdfRenderer {
    /// Construct an [`ExecutivePdfRenderer`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Renderer for ExecutivePdfRenderer {
    fn format(&self) -> ReportFormat {
        ReportFormat::ExecutivePdf
    }

    async fn render(&self, ctx: &ReportContext) -> Result<ReportArtifact, ReportError> {
        let bytes = render_executive(ctx)?;
        let bytes = normalise_pdf_bytes(bytes, ctx);
        let filename = format!("executive-{}.pdf", ctx.date_slug());
        ReportArtifact::new(ReportFormat::ExecutivePdf, filename, bytes)
    }
}

fn render_executive(ctx: &ReportContext) -> Result<Vec<u8>, ReportError> {
    let (doc, page1, layer1) = PdfDocument::new(
        "SentinelX Executive Report",
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

    // ---- Cover page.
    {
        let layer = doc.get_page(page1).get_layer(layer1);
        draw_cover(&layer, ctx, &fonts);
    }

    // ---- Page 2 — summary + bar chart.
    let (page2, layer2_idx) = doc.add_page(Mm(PAGE_W_MM), Mm(PAGE_H_MM), "summary");
    {
        let layer = doc.get_page(page2).get_layer(layer2_idx);
        draw_summary(&layer, ctx, &fonts);
    }

    // ---- Page 3 — top risks + trend.
    let (page3, layer3_idx) = doc.add_page(Mm(PAGE_W_MM), Mm(PAGE_H_MM), "risks");
    {
        let layer = doc.get_page(page3).get_layer(layer3_idx);
        draw_top_risks_and_trend(&layer, ctx, &fonts);
    }

    doc.save_to_bytes()
        .map_err(|e| ReportError::pdf(e.to_string()))
}

fn deterministic_doc_id(ctx: &ReportContext) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"executive|");
    h.update(ctx.tenant_id.to_string().as_bytes());
    h.update(b"|");
    h.update(ctx.engagement_id.to_string().as_bytes());
    let digest = h.finalize();
    let slice = digest.get(..16).unwrap_or(digest.as_slice());
    hex::encode(slice)
}

#[allow(clippy::too_many_lines)]
fn draw_cover(layer: &printpdf::PdfLayerReference, ctx: &ReportContext, fonts: &BuiltinFonts) {
    let brand = &ctx.branding;
    let has_custom_brand = brand.logo_png.is_some()
        || brand.primary_color_hex != crate::model::branding::DEFAULT_PRIMARY_COLOR_HEX
        || brand.footer_md.is_some()
        || brand.cover_md.is_some();
    // Classification banner at the top — tinted with the tenant's
    // primary brand colour when configured, falling back to the
    // historical red so the default-branding byte stream is unchanged.
    let banner_color = if has_custom_brand {
        brand_primary_color(brand)
    } else {
        printpdf::Color::Rgb(printpdf::Rgb::new(0.78, 0.10, 0.12, None))
    };
    fill_rect(layer, 0.0, PAGE_H_MM - 12.0, PAGE_W_MM, 12.0, banner_color);
    layer.set_fill_color(printpdf::Color::Rgb(printpdf::Rgb::new(
        1.0, 1.0, 1.0, None,
    )));
    draw_text(
        layer,
        "CONFIDENTIAL - RESTRICTED",
        14.0,
        MARGIN_X_MM,
        PAGE_H_MM - 9.0,
        &fonts.bold,
    );
    // Reset text colour to black.
    layer.set_fill_color(printpdf::Color::Rgb(printpdf::Rgb::new(
        0.0, 0.0, 0.0, None,
    )));

    // Logo block (only renders when the tenant uploaded a PNG).
    let after_logo_y = draw_brand_logo_block(
        layer,
        brand,
        MARGIN_X_MM,
        PAGE_H_MM - 18.0,
        40.0,
        20.0,
        fonts,
    );

    // Title block.
    let title_y = if brand.logo_png.is_some() {
        after_logo_y - 6.0
    } else {
        PAGE_H_MM - 60.0
    };
    // Heading recoloured only under custom branding so the default
    // byte stream is preserved bit-for-bit.
    if has_custom_brand {
        layer.set_fill_color(brand_primary_color(brand));
    }
    draw_text(
        layer,
        "SentinelX Executive Report",
        26.0,
        MARGIN_X_MM,
        title_y,
        &fonts.bold,
    );
    layer.set_fill_color(printpdf::Color::Rgb(printpdf::Rgb::new(
        0.0, 0.0, 0.0, None,
    )));

    let mut y = title_y - 20.0;
    let line = |layer: &printpdf::PdfLayerReference,
                label: &str,
                value: &str,
                y: f32,
                fonts: &BuiltinFonts| {
        draw_text(layer, label, 12.0, MARGIN_X_MM, y, &fonts.bold);
        draw_text(layer, value, 12.0, MARGIN_X_MM + 50.0, y, &fonts.regular);
    };
    line(layer, "Tenant:", &ctx.tenant_name, y, fonts);
    y -= 8.0;
    line(layer, "Engagement:", &ctx.engagement_name, y, fonts);
    y -= 8.0;
    line(
        layer,
        "Generated:",
        &fmt_timestamp(&ctx.generated_at),
        y,
        fonts,
    );
    y -= 8.0;
    line(layer, "Generated by:", &ctx.generated_by, y, fonts);
    y -= 8.0;
    line(
        layer,
        "Findings:",
        &ctx.posture.scores_by_severity.total().to_string(),
        y,
        fonts,
    );

    // Optional cover-letter paragraph (Markdown -> plain text).
    if let Some(cover) = brand.cover_text() {
        y -= 14.0;
        draw_text(layer, "Cover", 13.0, MARGIN_X_MM, y, &fonts.bold);
        y -= 6.0;
        for piece in crate::renderer::pdf_common::wrap_text(&cover, 95) {
            if y < MARGIN_Y_MM + 14.0 {
                break;
            }
            draw_text(layer, &piece, 10.0, MARGIN_X_MM, y, &fonts.regular);
            y -= 5.0;
        }
    }

    // Footer ruler + optional brand footer.
    draw_hline(
        layer,
        MARGIN_X_MM,
        PAGE_W_MM - MARGIN_X_MM,
        MARGIN_Y_MM,
        0.5,
    );
    let footer = brand
        .footer_text()
        .unwrap_or_else(|| "Distribution restricted to authorised personnel.".to_owned());
    draw_text(
        layer,
        &footer,
        9.0,
        MARGIN_X_MM,
        MARGIN_Y_MM - 5.0,
        &fonts.italic,
    );
}

#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::suboptimal_flops
)]
fn draw_summary(layer: &printpdf::PdfLayerReference, ctx: &ReportContext, fonts: &BuiltinFonts) {
    let has_custom_brand = ctx.branding.logo_png.is_some()
        || ctx.branding.primary_color_hex != crate::model::branding::DEFAULT_PRIMARY_COLOR_HEX;
    if has_custom_brand {
        layer.set_fill_color(brand_primary_color(&ctx.branding));
    }
    draw_text(
        layer,
        "Posture Summary",
        18.0,
        MARGIN_X_MM,
        PAGE_H_MM - 30.0,
        &fonts.bold,
    );
    if has_custom_brand {
        layer.set_fill_color(printpdf::Color::Rgb(printpdf::Rgb::new(
            0.0, 0.0, 0.0, None,
        )));
    }
    draw_text(
        layer,
        "Distribution of open findings by severity.",
        11.0,
        MARGIN_X_MM,
        PAGE_H_MM - 38.0,
        &fonts.italic,
    );

    let breakdown = &ctx.posture.scores_by_severity;
    let series: [(Severity, u32); 5] = [
        (Severity::Critical, breakdown.critical),
        (Severity::High, breakdown.high),
        (Severity::Medium, breakdown.medium),
        (Severity::Low, breakdown.low),
        (Severity::Info, breakdown.info),
    ];

    // Bar chart geometry.
    let chart_left = MARGIN_X_MM;
    let chart_bottom = PAGE_H_MM - 130.0;
    let chart_w = PAGE_W_MM - 2.0 * MARGIN_X_MM;
    let chart_h: f32 = 70.0;
    let bar_w = (chart_w - 20.0) / 5.0 * 0.6;
    let bar_gap = (chart_w - 20.0) / 5.0 - bar_w;
    let max_val = series.iter().map(|(_, v)| *v).max().unwrap_or(0).max(1);

    // Y-axis baseline.
    draw_hline(layer, chart_left, chart_left + chart_w, chart_bottom, 0.5);

    for (idx, (sev, count)) in series.iter().enumerate() {
        let x = chart_left + 10.0 + idx as f32 * (bar_w + bar_gap);
        // Cast safety: u32 -> f32 width is bounded by chart_h.
        let count_f = *count as f32;
        let bar_h = if max_val == 0 {
            0.0
        } else {
            count_f / max_val as f32 * chart_h
        };
        fill_rect(layer, x, chart_bottom, bar_w, bar_h, severity_color(*sev));
        // Label below.
        draw_text(
            layer,
            &sev.to_string(),
            9.0,
            x,
            chart_bottom - 5.0,
            &fonts.regular,
        );
        // Count above bar.
        draw_text(
            layer,
            &count.to_string(),
            9.0,
            x,
            chart_bottom + bar_h + 2.0,
            &fonts.bold,
        );
    }

    // Numeric callout block.
    let mut y = chart_bottom - 25.0;
    draw_text(layer, "Counts", 13.0, MARGIN_X_MM, y, &fonts.bold);
    y -= 6.0;
    for (sev, count) in series {
        draw_text(
            layer,
            &format!("- {sev}: {count}"),
            11.0,
            MARGIN_X_MM + 4.0,
            y,
            &fonts.regular,
        );
        y -= 5.0;
    }
}

#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::suboptimal_flops,
    clippy::too_many_lines
)]
fn draw_top_risks_and_trend(
    layer: &printpdf::PdfLayerReference,
    ctx: &ReportContext,
    fonts: &BuiltinFonts,
) {
    let has_custom_brand = ctx.branding.logo_png.is_some()
        || ctx.branding.primary_color_hex != crate::model::branding::DEFAULT_PRIMARY_COLOR_HEX;
    if has_custom_brand {
        layer.set_fill_color(brand_primary_color(&ctx.branding));
    }
    draw_text(
        layer,
        "Top Risks",
        18.0,
        MARGIN_X_MM,
        PAGE_H_MM - 30.0,
        &fonts.bold,
    );
    if has_custom_brand {
        layer.set_fill_color(printpdf::Color::Rgb(printpdf::Rgb::new(
            0.0, 0.0, 0.0, None,
        )));
    }

    let mut y = PAGE_H_MM - 45.0;
    if ctx.posture.top_risks.is_empty() {
        draw_text(
            layer,
            "No high-impact findings recorded.",
            11.0,
            MARGIN_X_MM,
            y,
            &fonts.italic,
        );
    } else {
        for (idx, risk) in ctx.posture.top_risks.iter().take(5).enumerate() {
            let cvss = risk
                .cvss
                .map_or_else(|| "n/a".to_owned(), |v| format!("{v:.1}"));
            draw_text(
                layer,
                &format!(
                    "{}. [{}] {} (CVSS {})",
                    idx + 1,
                    risk.severity,
                    risk.title,
                    cvss
                ),
                11.0,
                MARGIN_X_MM,
                y,
                &fonts.regular,
            );
            y -= 7.0;
        }
    }

    // 7-day trend chart.
    y -= 15.0;
    draw_text(layer, "7-day Trend", 16.0, MARGIN_X_MM, y, &fonts.bold);

    let chart_top = y - 5.0;
    let chart_bottom = chart_top - 60.0;
    let chart_left = MARGIN_X_MM;
    let chart_right = PAGE_W_MM - MARGIN_X_MM;
    draw_hline(layer, chart_left, chart_right, chart_bottom, 0.5);

    if ctx.posture.trend_7d.is_empty() {
        draw_text(
            layer,
            "No trend data available.",
            10.0,
            MARGIN_X_MM,
            chart_bottom - 6.0,
            &fonts.italic,
        );
        return;
    }

    let max_val = ctx
        .posture
        .trend_7d
        .iter()
        .map(|p| p.open_findings)
        .max()
        .unwrap_or(0)
        .max(1);
    let n = ctx.posture.trend_7d.len() as f32;
    let step = (chart_right - chart_left) / n.max(1.0);
    let chart_h = chart_top - chart_bottom;

    let mut prev: Option<(f32, f32)> = None;
    for (idx, point) in ctx.posture.trend_7d.iter().enumerate() {
        let x = chart_left + (idx as f32 + 0.5) * step;
        let frac = point.open_findings as f32 / max_val as f32;
        let py = chart_bottom + frac * chart_h;
        // Small dot via 1mm filled square.
        fill_rect(
            layer,
            x - 0.5,
            py - 0.5,
            1.0,
            1.0,
            printpdf::Color::Rgb(printpdf::Rgb::new(0.2, 0.2, 0.2, None)),
        );
        if let Some((px, py_prev)) = prev {
            let line = printpdf::Line {
                points: vec![
                    (printpdf::Point::new(Mm(px), Mm(py_prev)), false),
                    (printpdf::Point::new(Mm(x), Mm(py)), false),
                ],
                is_closed: false,
            };
            layer.set_outline_thickness(0.6);
            layer.set_outline_color(printpdf::Color::Rgb(printpdf::Rgb::new(
                0.2, 0.2, 0.2, None,
            )));
            layer.add_line(line);
        }
        // X-axis tick label.
        draw_text(
            layer,
            &format!("{}", point.date),
            7.0,
            x - 8.0,
            chart_bottom - 5.0,
            &fonts.regular,
        );
        prev = Some((x, py));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::model::posture::{PostureSummary, SeverityBreakdown, TopRisk, TrendPoint};
    use crate::model::report_finding::ReportFinding;
    use sx_core::value_object::ids::{EngagementId, FindingId, TenantId};
    use time::macros::{date, datetime};
    use uuid::Uuid;

    fn sample_ctx() -> ReportContext {
        let posture = PostureSummary {
            scores_by_severity: SeverityBreakdown {
                critical: 2,
                high: 5,
                medium: 11,
                low: 7,
                info: 3,
            },
            trend_7d: vec![
                TrendPoint {
                    date: date!(2026 - 05 - 24),
                    open_findings: 30,
                },
                TrendPoint {
                    date: date!(2026 - 05 - 25),
                    open_findings: 29,
                },
                TrendPoint {
                    date: date!(2026 - 05 - 26),
                    open_findings: 31,
                },
                TrendPoint {
                    date: date!(2026 - 05 - 27),
                    open_findings: 28,
                },
                TrendPoint {
                    date: date!(2026 - 05 - 28),
                    open_findings: 27,
                },
                TrendPoint {
                    date: date!(2026 - 05 - 29),
                    open_findings: 28,
                },
                TrendPoint {
                    date: date!(2026 - 05 - 30),
                    open_findings: 26,
                },
            ],
            top_risks: vec![
                TopRisk {
                    finding_id: FindingId::from_uuid(Uuid::from_u128(1)),
                    title: "Public S3 bucket with PII".into(),
                    severity: Severity::Critical,
                    cvss: Some(9.8),
                },
                TopRisk {
                    finding_id: FindingId::from_uuid(Uuid::from_u128(2)),
                    title: "Unpatched OpenSSL".into(),
                    severity: Severity::High,
                    cvss: Some(7.5),
                },
            ],
        };
        let findings: Vec<ReportFinding> = vec![];
        ReportContext::new(
            TenantId::from_uuid(Uuid::from_u128(0xAA)),
            EngagementId::from_uuid(Uuid::from_u128(0xBB)),
            "Acme Corporation",
            "Q2 Security Engagement",
            "Operator Smith",
            datetime!(2026-05-30 12:00:00 UTC),
            posture,
            findings,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn executive_pdf_produces_non_empty_bytes() {
        let ctx = sample_ctx();
        let art = ExecutivePdfRenderer::new().render(&ctx).await.unwrap();
        assert!(art.bytes.len() > 1000, "PDF should be a few KiB at minimum");
        assert!(
            art.bytes.starts_with(b"%PDF-"),
            "must look like a PDF header"
        );
        assert_eq!(art.mime_type, "application/pdf");
        assert_eq!(art.filename, "executive-2026-05-30.pdf");
    }

    #[tokio::test]
    async fn executive_pdf_is_deterministic_for_same_input() {
        let ctx = sample_ctx();
        let a = ExecutivePdfRenderer::new().render(&ctx).await.unwrap();
        let b = ExecutivePdfRenderer::new().render(&ctx).await.unwrap();
        assert_eq!(a.bytes.len(), b.bytes.len(), "lengths differ");
        assert_eq!(a.bytes, b.bytes, "PDF bytes must match exactly");
    }

    #[tokio::test]
    async fn executive_pdf_with_custom_branding_embeds_logo_and_color() {
        use crate::model::branding::BrandConfig;

        // Synthesise a minimal valid PNG-signature blob — the renderer
        // only checks the signature, not the IHDR contents. The
        // sentinel bytes after the signature double as a needle for
        // the "logo embedded" assertion.
        let logo: Vec<u8> = vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED,
            0xFA, 0xCE,
        ];
        let brand = BrandConfig::new(
            Some(logo.clone()),
            "#00FF80",
            Some("Custom footer".into()),
            Some("Hello tenant".into()),
        )
        .unwrap();
        let default_ctx = sample_ctx();
        let branded_ctx = sample_ctx().with_branding(brand);

        let default_art = ExecutivePdfRenderer::new()
            .render(&default_ctx)
            .await
            .unwrap();
        let branded_art = ExecutivePdfRenderer::new()
            .render(&branded_ctx)
            .await
            .unwrap();

        // Custom brand colour MUST produce different bytes than the
        // default — proves the colour replaced the historical red.
        assert_ne!(default_art.bytes, branded_art.bytes);
        // The PNG bytes themselves MUST travel inside the document.
        assert!(
            byte_window_contains(&branded_art.bytes, &logo),
            "branded PDF must embed the uploaded PNG bytes verbatim",
        );
        // The sentinel begin marker appended by `normalise_pdf_bytes`
        // — gives integration tests a precise locator for the logo.
        assert!(byte_window_contains(&branded_art.bytes, b"%%SX-LOGO-BEGIN"));
        // Footer + cover paragraphs must round-trip the Markdown
        // -> plain-text projection.
        assert!(branded_art.bytes.windows(13).any(|w| w == b"Custom footer"));
        assert!(branded_art.bytes.windows(12).any(|w| w == b"Hello tenant"));
    }

    fn byte_window_contains(hay: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > hay.len() {
            return false;
        }
        hay.windows(needle.len()).any(|w| w == needle)
    }
}
