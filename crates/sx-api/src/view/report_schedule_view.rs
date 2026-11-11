//! Scheduled-report distribution DTOs (P2-001).
//!
//! Operators register cron-scheduled report renders that the background
//! scheduler delivers to the configured recipients / channels.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// One registered report schedule (response DTO).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportScheduleView {
    /// Schedule uuid.
    pub id: String,
    /// Engagement the report is rendered for.
    pub engagement_id: Option<String>,
    /// Report format (`executive_pdf`, `technical_pdf`, `sarif`, …).
    pub format: String,
    /// Cron expression driving the cadence.
    pub cron_expr: String,
    /// Email recipients.
    pub recipients: Vec<String>,
    /// Whether the schedule is active.
    pub enabled: bool,
    /// RFC 3339 timestamp of the next scheduled run.
    pub next_run_at: String,
}

/// Request body for `POST /v1/reports/schedules`.
#[derive(Debug, Clone, Deserialize, Validate)]
pub struct CreateReportScheduleRequest {
    /// Engagement uuid the report is rendered for.
    #[validate(length(min = 1, max = 64))]
    pub engagement_id: String,
    /// Report format identifier.
    #[validate(length(min = 1, max = 32))]
    pub format: String,
    /// Cron expression (validated by the scheduler engine).
    #[validate(length(min = 1, max = 128))]
    pub cron_expr: String,
    /// At least one email recipient.
    #[validate(length(min = 1, max = 50))]
    pub recipients: Vec<String>,
}
