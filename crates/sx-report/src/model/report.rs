//! Report context + the matching request envelope.

use serde::{Deserialize, Serialize};
use sx_core::value_object::ids::{EngagementId, TenantId};
use time::OffsetDateTime;

use crate::diff::ReportDiff;
use crate::error::ReportError;
use crate::model::branding::BrandConfig;
use crate::model::posture::PostureSummary;
use crate::model::report_finding::ReportFinding;
use crate::port::ReportFormat;

/// Request shape received at the API boundary.
///
/// The use-case combines this with repository lookups to build a
/// [`ReportContext`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportRequest {
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Engagement scope.
    pub engagement_id: EngagementId,
    /// Requested format.
    pub format: ReportFormat,
}

/// Everything a renderer needs.
///
/// `ReportContext` is the single input to [`crate::port::Renderer::render`]
/// — renderers do not perform I/O, so this struct must carry everything
/// they will display.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportContext {
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Engagement scope.
    pub engagement_id: EngagementId,
    /// Engagement display name (for headers/cover pages).
    pub engagement_name: String,
    /// Tenant display name (for headers/cover pages).
    pub tenant_name: String,
    /// Operator display name — who triggered the report.
    pub generated_by: String,
    /// Generation time. Renderers MUST use this — never the system clock —
    /// so that output is deterministic for a given input.
    pub generated_at: OffsetDateTime,
    /// Aggregate posture summary.
    pub posture: PostureSummary,
    /// Per-finding payload (used by the technical PDF, SARIF, STIX, CSV).
    pub findings: Vec<ReportFinding>,
    /// Per-tenant branding overrides (P2-002). Renderers respect
    /// `primary_color_hex`, `logo_png`, `footer_md`, and `cover_md`.
    /// Defaults to [`BrandConfig::default`] so the pre-P2-002 byte
    /// output is preserved when no tenant has configured branding.
    #[serde(default)]
    pub branding: BrandConfig,
    /// Optional diff payload — populated only when the caller is rendering
    /// the [`crate::port::ReportFormat::DiffPdf`] format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<ReportDiff>,
}

impl ReportContext {
    /// Build a [`ReportContext`] and validate display fields.
    ///
    /// # Errors
    /// Returns [`ReportError::InvalidContext`] when `engagement_name`,
    /// `tenant_name` or `generated_by` are empty after trimming.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        engagement_id: EngagementId,
        tenant_name: impl Into<String>,
        engagement_name: impl Into<String>,
        generated_by: impl Into<String>,
        generated_at: OffsetDateTime,
        posture: PostureSummary,
        findings: Vec<ReportFinding>,
    ) -> Result<Self, ReportError> {
        let tenant_name = tenant_name.into().trim().to_owned();
        let engagement_name = engagement_name.into().trim().to_owned();
        let generated_by = generated_by.into().trim().to_owned();
        for (label, value) in [
            ("tenant_name", &tenant_name),
            ("engagement_name", &engagement_name),
            ("generated_by", &generated_by),
        ] {
            if value.is_empty() {
                return Err(ReportError::invalid_context(format!(
                    "{label} cannot be empty"
                )));
            }
        }
        Ok(Self {
            tenant_id,
            engagement_id,
            engagement_name,
            tenant_name,
            generated_by,
            generated_at,
            posture,
            findings,
            branding: BrandConfig::default(),
            diff: None,
        })
    }

    /// Replace the [`BrandConfig`] on a previously-built context.
    ///
    /// Builder-style helper for callers (typically the
    /// `ReportRenderPort` adapter) that load branding from a separate
    /// repository after constructing the rest of the context.
    #[must_use]
    pub fn with_branding(mut self, branding: BrandConfig) -> Self {
        self.branding = branding;
        self
    }

    /// Attach a diff payload (consuming-builder).
    ///
    /// Required by [`crate::port::ReportFormat::DiffPdf`]; ignored by all
    /// other renderers.
    #[must_use]
    pub fn with_diff(mut self, diff: ReportDiff) -> Self {
        self.diff = Some(diff);
        self
    }

    /// Convenience: a short slug derived from `generated_at` suitable for
    /// embedding in a filename (`YYYY-MM-DD`).
    #[must_use]
    pub fn date_slug(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}",
            self.generated_at.year(),
            u8::from(self.generated_at.month()),
            self.generated_at.day(),
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn rejects_empty_tenant_name() {
        let r = ReportContext::new(
            TenantId::new(),
            EngagementId::new(),
            "  ",
            "engagement",
            "ops",
            datetime!(2026-05-30 12:00:00 UTC),
            PostureSummary::empty(),
            vec![],
        );
        assert!(r.is_err());
    }

    #[test]
    fn date_slug_pads_zeros() {
        let ctx = ReportContext::new(
            TenantId::new(),
            EngagementId::new(),
            "Acme",
            "Q2 Engagement",
            "ops",
            datetime!(2026-01-05 12:00:00 UTC),
            PostureSummary::empty(),
            vec![],
        )
        .unwrap();
        assert_eq!(ctx.date_slug(), "2026-01-05");
    }
}
