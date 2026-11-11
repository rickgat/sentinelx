//! Posture summary aggregates used by the executive PDF (and the JSON
//! exporters when they want to embed an "overview" block).

use serde::{Deserialize, Serialize};
use sx_core::value_object::ids::FindingId;
use sx_core::value_object::severity::Severity;
use time::Date;

use crate::model::report_finding::ReportFinding;

/// Severity-bucket counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityBreakdown {
    /// Count of [`Severity::Critical`] findings.
    pub critical: u32,
    /// Count of [`Severity::High`] findings.
    pub high: u32,
    /// Count of [`Severity::Medium`] findings.
    pub medium: u32,
    /// Count of [`Severity::Low`] findings.
    pub low: u32,
    /// Count of [`Severity::Info`] findings.
    pub info: u32,
}

impl SeverityBreakdown {
    /// Total finding count across all buckets.
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.critical + self.high + self.medium + self.low + self.info
    }

    /// Tally a [`Severity`] into the matching bucket.
    pub const fn tally(&mut self, severity: Severity) {
        match severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
        }
    }

    /// Build a breakdown by tallying every entry in `findings`.
    #[must_use]
    pub fn from_findings(findings: &[ReportFinding]) -> Self {
        let mut b = Self::default();
        for f in findings {
            b.tally(f.severity);
        }
        b
    }
}

/// One day on the trend chart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrendPoint {
    /// Calendar date of this data point.
    pub date: Date,
    /// Total open findings on that day.
    pub open_findings: u32,
}

/// A highlighted "top risk" referenced in the executive summary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TopRisk {
    /// Backing finding id.
    pub finding_id: FindingId,
    /// Title for display.
    pub title: String,
    /// Severity bucket.
    pub severity: Severity,
    /// Primary CVSS for display (v4 preferred, then v3).
    pub cvss: Option<f32>,
}

/// Posture summary embedded in [`crate::model::report::ReportContext`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostureSummary {
    /// Per-severity counts.
    pub scores_by_severity: SeverityBreakdown,
    /// Up to seven prior calendar days, oldest-first.
    pub trend_7d: Vec<TrendPoint>,
    /// Up to five highest-impact items, severity-then-CVSS-descending.
    pub top_risks: Vec<TopRisk>,
}

impl PostureSummary {
    /// Empty posture — useful for tests and "no findings" reports.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            scores_by_severity: SeverityBreakdown {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                info: 0,
            },
            trend_7d: Vec::new(),
            top_risks: Vec::new(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn breakdown_total_sums_buckets() {
        let mut b = SeverityBreakdown::default();
        b.tally(Severity::High);
        b.tally(Severity::High);
        b.tally(Severity::Critical);
        assert_eq!(b.total(), 3);
        assert_eq!(b.high, 2);
        assert_eq!(b.critical, 1);
    }

    #[test]
    fn empty_posture_is_zero() {
        let p = PostureSummary::empty();
        assert_eq!(p.scores_by_severity.total(), 0);
        assert!(p.top_risks.is_empty());
    }
}
