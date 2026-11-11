//! Domain-shaped value objects assembled for report rendering.
//!
//! These types are intentionally renderer-facing: they flatten what
//! `sx-core` carries (e.g. an `AssetId` is replaced by `asset_label`) so
//! that renderers can drop the heavy domain types and operate on small
//! display-ready structs.

pub mod branding;
pub mod posture;
pub mod report;
pub mod report_finding;
pub mod template;

pub use branding::{BrandConfig, DEFAULT_PRIMARY_COLOR_HEX, MAX_LOGO_BYTES};
pub use posture::{PostureSummary, SeverityBreakdown, TopRisk, TrendPoint};
pub use report::{ReportContext, ReportRequest};
pub use report_finding::ReportFinding;
pub use template::{
    ReportTemplate, ReportTemplateId, TemplateContext, TemplateSurface, TemplateValue,
    MAX_BLOCK_DEPTH, MAX_ITERATIONS_PER_LOOP, MAX_OUTPUT_BYTES, MAX_TEMPLATE_BYTES,
};
