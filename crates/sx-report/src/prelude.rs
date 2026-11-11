//! Re-exports for typical call sites.
//!
//! ```rust,ignore
//! use sx_report::prelude::*;
//! ```

pub use crate::controller::{
    CreateTemplateInput, RenderReportUseCase, ReportTemplateUseCase, TemplateAuditAction,
    TemplateAuditEvent, TemplateAuditSink, TemplateRepository, UpdateTemplateInput,
};
pub use crate::error::ReportError;
pub use crate::model::branding::BrandConfig;
pub use crate::model::posture::{PostureSummary, SeverityBreakdown, TopRisk, TrendPoint};
pub use crate::model::report::ReportContext;
pub use crate::model::report_finding::ReportFinding;
pub use crate::model::template::{
    ReportTemplate, ReportTemplateId, TemplateContext, TemplateSurface, TemplateValue,
};
pub use crate::port::{Renderer, ReportArtifact, ReportFormat};
pub use crate::renderer::csv::CsvRenderer;
pub use crate::renderer::executive_pdf::ExecutivePdfRenderer;
pub use crate::renderer::sarif::SarifRenderer;
pub use crate::renderer::stix::StixRenderer;
pub use crate::renderer::technical_pdf::TechnicalPdfRenderer;
pub use crate::scheduler::{
    CronEvaluator, EmailDispatcher, InMemoryScheduleStore, LettreSmtpDispatcher, RecordedEmail,
    RecordingDispatcher, ReportSchedule, ScheduleStore, Scheduler, SchedulerReportArtifact,
    SchedulerReportPort, SmtpConfig, TickReport,
};
