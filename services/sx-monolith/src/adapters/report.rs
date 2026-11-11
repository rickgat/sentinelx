#![allow(dead_code)] // Phase-3.5: many fields are reserved for the next-turn wire-up.
//! Reporting adapter.
//!
//! Builds the `sx-report` composition-root bundle. Registers all five
//! renderers (executive PDF, technical PDF, SARIF 2.1.0, STIX 2.1, CSV)
//! and hands them to the [`RenderReportUseCase`] dispatcher.

use std::sync::Arc;

use sx_report::controller::RenderReportUseCase;
use sx_report::port::Renderer;
use sx_report::renderer::csv::CsvRenderer;
use sx_report::renderer::diff_pdf::DiffPdfRenderer;
use sx_report::renderer::executive_pdf::ExecutivePdfRenderer;
use sx_report::renderer::sarif::SarifRenderer;
use sx_report::renderer::stix::StixRenderer;
use sx_report::renderer::technical_pdf::TechnicalPdfRenderer;
use tracing::info;

/// Bundle returned by [`build`].
pub(crate) struct ReportBundle {
    /// Dispatches by `ReportFormat` to the matching renderer.
    pub render_use_case: Arc<RenderReportUseCase>,
}

/// Build the report bundle.
///
/// # Errors
///
/// Returns an error if the underlying [`RenderReportUseCase::new`] rejects
/// the renderer list (would indicate two renderers claiming the same
/// [`sx_report::port::ReportFormat`] — a logic bug in this composition root).
#[allow(dead_code)] // parent composition root wires this in
pub(crate) fn build() -> anyhow::Result<ReportBundle> {
    let renderers: Vec<Arc<dyn Renderer>> = vec![
        Arc::new(ExecutivePdfRenderer),
        Arc::new(TechnicalPdfRenderer),
        Arc::new(SarifRenderer),
        Arc::new(StixRenderer),
        Arc::new(CsvRenderer),
        Arc::new(DiffPdfRenderer),
    ];
    let render_use_case = Arc::new(
        RenderReportUseCase::new(renderers).map_err(|e| anyhow::anyhow!("report use case: {e}"))?,
    );

    info!(
        target = "adapters.report.built",
        renderers = 6,
        "report bundle constructed",
    );

    Ok(ReportBundle { render_use_case })
}
