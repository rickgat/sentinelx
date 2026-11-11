//! Remediation outcomes + regression DTOs.
//!
//! Projects the rich `sx_remediation::service::outcomes` value objects
//! onto a stable JSON shape suitable for the dashboard. Every numeric
//! duration on the wire is **seconds** — the dashboard renders
//! days/hours from there.

use serde::{Deserialize, Serialize};

/// `GET /v1/remediation/outcomes/metrics?window_days=N` query string.
#[derive(Debug, Clone, Deserialize)]
pub struct OutcomesMetricsQuery {
    /// Lookback window in whole days. Optional — defaults to 30 inside
    /// the controller when absent.
    pub window_days: Option<u32>,
}

/// `GET /v1/remediation/outcomes/regressions?limit=N` query string.
#[derive(Debug, Clone, Deserialize)]
pub struct OutcomesRegressionsQuery {
    /// Maximum number of regression rows returned. Optional — defaults
    /// to 50 inside the controller, capped at 500.
    pub limit: Option<u32>,
}

/// Per-severity mean-time-to-remediate bucket.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MttrBucketView {
    /// Severity label.
    pub severity: String,
    /// Number of closures that fed the mean.
    pub sample_size: u64,
    /// MTTR in seconds. Dashboard converts to days/hours for display.
    pub mttr_seconds: i64,
}

/// Per-`check_id` regression ranking row.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegressingTechniqueView {
    /// `check_id` that regressed.
    pub check_id: String,
    /// Regressions observed in the window.
    pub regression_count: u64,
    /// Closures observed in the window.
    pub closure_count: u64,
}

/// `GET /v1/remediation/outcomes/metrics` response body.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemediationMetricsView {
    /// Tenant the snapshot covers.
    pub tenant_id: String,
    /// Window the snapshot covers, in whole seconds.
    pub window_seconds: i64,
    /// MTTR buckets ordered critical -> info.
    pub mttr_by_severity: Vec<MttrBucketView>,
    /// `regressions / max(closures, 1)` over the window.
    pub regression_rate: f64,
    /// Top regressing techniques, capped at 10.
    pub top_regressing: Vec<RegressingTechniqueView>,
    /// Closure count that fed the rate.
    pub closure_count: u64,
    /// Regression count that fed the rate.
    pub regression_count: u64,
}

/// Single regression event row.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegressionEventView {
    /// Stable id for the regression row.
    pub id: String,
    /// Tenant the regression belongs to.
    pub tenant_id: String,
    /// Asset the regression was recorded against.
    pub asset_id: String,
    /// `check_id` that reappeared.
    pub check_id: String,
    /// Prior outcome id (the closure that this regression supersedes).
    pub prior_outcome_id: String,
    /// Finding id that opened (the new occurrence).
    pub new_finding_id: String,
    /// When the regression was detected (RFC 3339).
    pub detected_at: String,
    /// Time delta between the prior closure and the new finding, in
    /// whole seconds.
    pub gap_seconds: i64,
}

/// `GET /v1/remediation/outcomes/regressions` response body.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegressionListView {
    /// Regression rows, newest-first.
    pub items: Vec<RegressionEventView>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn metrics_view_serialises_with_camel_cased_severity() {
        let v = RemediationMetricsView {
            tenant_id: "t-1".into(),
            window_seconds: 86_400,
            mttr_by_severity: vec![MttrBucketView {
                severity: "critical".into(),
                sample_size: 3,
                mttr_seconds: 600,
            }],
            regression_rate: 0.25,
            top_regressing: vec![],
            closure_count: 4,
            regression_count: 1,
        };
        let json = serde_json::to_string(&v).expect("serialise");
        assert!(json.contains("\"severity\":\"critical\""));
        assert!(json.contains("\"mttr_seconds\":600"));
        assert!(json.contains("\"closure_count\":4"));
    }

    #[test]
    fn regression_view_round_trips() {
        let v = RegressionEventView {
            id: "00000000-0000-0000-0000-000000000001".into(),
            tenant_id: "t-1".into(),
            asset_id: "a-1".into(),
            check_id: "C-OPEN-PORT".into(),
            prior_outcome_id: "00000000-0000-0000-0000-000000000002".into(),
            new_finding_id: "00000000-0000-0000-0000-000000000003".into(),
            detected_at: "2026-06-01T00:00:00Z".into(),
            gap_seconds: 3_600,
        };
        let s = serde_json::to_string(&v).expect("serialise");
        let parsed: RegressionEventView = serde_json::from_str(&s).expect("deserialise");
        assert_eq!(parsed.check_id, "C-OPEN-PORT");
        assert_eq!(parsed.gap_seconds, 3_600);
    }
}
