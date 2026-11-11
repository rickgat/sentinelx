//! Comprehensive platform report DTOs (#3).
//!
//! A single, server-generated executive report aggregated across the
//! platform's modules. Returned both as structured fields (for machine
//! consumers / dashboards) and as a fully-rendered Markdown document (for
//! durable, shareable, signable artifacts).

use serde::{Deserialize, Serialize};

/// One severity bucket count.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SeverityCountView {
    /// Severity label (`critical`, `high`, …).
    pub severity: String,
    /// Number of findings in that bucket.
    pub count: u64,
}

/// Per-framework compliance control coverage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrameworkCoverageView {
    /// Framework code (`pcidss`, `soc2`, …).
    pub framework: String,
    /// Number of controls catalogued for that framework.
    pub controls: u64,
}

/// The aggregated comprehensive report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ComprehensiveReportView {
    /// RFC 3339 generation timestamp.
    pub generated_at: String,
    /// Tenant the report was generated for.
    pub tenant_id: String,
    /// Total findings considered.
    pub total_findings: u64,
    /// Weighted posture score (0–100, higher is better).
    pub posture_score: u64,
    /// Findings grouped by severity.
    pub by_severity: Vec<SeverityCountView>,
    /// Compliance control coverage per framework.
    pub compliance: Vec<FrameworkCoverageView>,
    /// Fully-rendered Markdown document.
    pub markdown: String,
}
