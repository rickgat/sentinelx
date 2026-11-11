//! `RenderReportUseCase` — dispatch a [`crate::port::ReportFormat`] to its
//! registered [`crate::port::Renderer`].

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{debug, instrument};

use crate::error::ReportError;
use crate::model::report::ReportContext;
use crate::port::{Renderer, ReportArtifact, ReportFormat};

/// Use-case: take a [`ReportFormat`] and a [`ReportContext`], dispatch to
/// the appropriate [`Renderer`], return the produced [`ReportArtifact`].
pub struct RenderReportUseCase {
    renderers: HashMap<ReportFormat, Arc<dyn Renderer>>,
}

impl std::fmt::Debug for RenderReportUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RenderReportUseCase")
            .field(
                "registered_formats",
                &self.renderers.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl RenderReportUseCase {
    /// Build a use-case from a list of renderers.
    ///
    /// # Errors
    /// Returns [`ReportError::InvalidRegistry`] when `renderers` is empty
    /// or when two renderers claim the same [`ReportFormat`].
    pub fn new(renderers: Vec<Arc<dyn Renderer>>) -> Result<Self, ReportError> {
        if renderers.is_empty() {
            return Err(ReportError::invalid_registry(
                "renderer registry cannot be empty",
            ));
        }
        let mut map: HashMap<ReportFormat, Arc<dyn Renderer>> = HashMap::new();
        for r in renderers {
            let fmt = r.format();
            if map.insert(fmt, r).is_some() {
                return Err(ReportError::invalid_registry(format!(
                    "duplicate renderer for format {fmt}",
                )));
            }
        }
        Ok(Self { renderers: map })
    }

    /// Which formats this use-case can produce.
    #[must_use]
    pub fn supported_formats(&self) -> Vec<ReportFormat> {
        let mut keys: Vec<ReportFormat> = self.renderers.keys().copied().collect();
        keys.sort_by_key(|f| f.as_str());
        keys
    }

    /// Render `ctx` in `format`.
    ///
    /// # Errors
    /// - [`ReportError::RendererNotRegistered`] if no renderer is registered
    ///   for `format`.
    /// - Any error returned by the underlying renderer.
    #[instrument(skip(self, ctx), fields(format = %format))]
    pub async fn execute(
        &self,
        format: ReportFormat,
        ctx: &ReportContext,
    ) -> Result<ReportArtifact, ReportError> {
        let renderer = self
            .renderers
            .get(&format)
            .ok_or_else(|| ReportError::renderer_not_registered(format.as_str().to_owned()))?;
        debug!("dispatching to renderer for {format}");
        renderer.render(ctx).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::model::posture::PostureSummary;
    use crate::model::report_finding::ReportFinding;
    use crate::renderer::csv::CsvRenderer;
    use crate::renderer::executive_pdf::ExecutivePdfRenderer;
    use crate::renderer::sarif::SarifRenderer;
    use crate::renderer::stix::StixRenderer;
    use crate::renderer::technical_pdf::TechnicalPdfRenderer;
    use sx_core::value_object::ids::{EngagementId, FindingId, TenantId};
    use sx_core::value_object::severity::Severity;
    use time::macros::datetime;

    fn all_renderers() -> Vec<Arc<dyn Renderer>> {
        vec![
            Arc::new(ExecutivePdfRenderer::new()),
            Arc::new(TechnicalPdfRenderer::new()),
            Arc::new(SarifRenderer::new()),
            Arc::new(StixRenderer::new()),
            Arc::new(CsvRenderer::new()),
        ]
    }

    fn sample_ctx() -> ReportContext {
        let finding = ReportFinding::new(
            FindingId::new(),
            "host.example.com",
            Severity::Critical,
            "An issue",
            "details",
            None,
            "discovered",
            vec!["https://example.com/advisory".to_owned()],
        )
        .unwrap();
        ReportContext::new(
            TenantId::new(),
            EngagementId::new(),
            "Acme",
            "Q2",
            "ops",
            datetime!(2026-05-30 12:00:00 UTC),
            PostureSummary::empty(),
            vec![finding],
        )
        .unwrap()
    }

    #[test]
    fn new_rejects_empty() {
        let r = RenderReportUseCase::new(vec![]);
        assert!(r.is_err());
    }

    #[test]
    fn new_rejects_duplicates() {
        let r = RenderReportUseCase::new(vec![
            Arc::new(CsvRenderer::new()),
            Arc::new(CsvRenderer::new()),
        ]);
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn render_report_use_case_returns_for_each_registered_format() {
        let uc = RenderReportUseCase::new(all_renderers()).unwrap();
        let ctx = sample_ctx();
        for fmt in [
            ReportFormat::ExecutivePdf,
            ReportFormat::TechnicalPdf,
            ReportFormat::Sarif,
            ReportFormat::Stix,
            ReportFormat::Csv,
        ] {
            let art = uc.execute(fmt, &ctx).await.unwrap();
            assert_eq!(art.format, fmt);
            assert!(!art.bytes.is_empty(), "{fmt} produced no bytes");
            assert!(!art.filename.is_empty());
        }
    }

    #[tokio::test]
    async fn render_report_use_case_errors_on_unknown_format() {
        // Build a use-case with only CSV registered.
        let uc = RenderReportUseCase::new(vec![Arc::new(CsvRenderer::new())]).unwrap();
        let ctx = sample_ctx();
        match uc.execute(ReportFormat::Sarif, &ctx).await {
            Err(ReportError::RendererNotRegistered(_)) => (),
            Err(other) => panic!("expected RendererNotRegistered, got {other:?}"),
            Ok(_) => panic!("must reject unregistered format"),
        }
    }
}
