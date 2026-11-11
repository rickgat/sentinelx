//! Use-cases (controllers) — orchestrate renderer selection and template
//! registry mutations.

pub mod render_report;
pub mod template_registry;

pub use render_report::RenderReportUseCase;
pub use template_registry::{
    CreateTemplateInput, ReportTemplateUseCase, TemplateAuditAction, TemplateAuditEvent,
    TemplateAuditSink, TemplateRepository, UpdateTemplateInput,
};
