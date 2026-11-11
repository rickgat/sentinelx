//! `SX-FINDINGS-SLA` — measures the percentage of critical security
//! findings remediated within their service-level objective.
//!
//! Per TRD §28.2 a credible compliance posture requires more than
//! "we found things"; reviewers want time-to-remediate evidence. This
//! collector reads aggregate stats from a [`FindingSlaStats`]
//! abstraction (production: `sx-risk` / `sx-remediation`; tests:
//! deterministic stub) and emits both raw counts and the derived SLA
//! compliance percentage.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::collector::schedule::EvidenceSchedule;
use crate::collector::types::{Evidence, EvidenceContentType};
use crate::collector::{CollectionContext, CollectorError, EvidenceCollector};
use crate::model::framework::Framework;

/// Control identifier produced by this collector.
pub const CONTROL_ID: &str = "SX-FINDINGS-SLA";

/// Collector implementation version, stamped into every emitted record.
pub const VERSION: &str = "1.0.0";

/// Aggregate counts the collector needs to compute the percentage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlaCounts {
    /// Total critical findings that *closed* within the window.
    pub critical_closed: u64,
    /// Subset of [`Self::critical_closed`] closed within their SLA.
    pub critical_closed_within_sla: u64,
}

/// Abstraction over the SLA stats source.
#[async_trait]
pub trait FindingSlaStats: Send + Sync + std::fmt::Debug {
    /// Return the aggregate counts for the current evaluation window.
    ///
    /// # Errors
    /// Returns [`CollectorError::Internal`] on transport failure.
    async fn counts(&self) -> Result<SlaCounts, CollectorError>;
}

/// JSON envelope encoded into the [`Evidence::payload`] field.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct FindingsSlaEvidence {
    /// Raw aggregate counts.
    pub counts: SlaCounts,
    /// Percentage of critical findings closed within SLA (0.0..=100.0).
    pub percent_within_sla: f64,
    /// `true` when [`Self::percent_within_sla`] >=
    /// [`Self::target_percent`].
    pub healthy: bool,
    /// Target percentage the collector evaluated against.
    pub target_percent: f64,
}

/// Default SLA target — 95% of critical findings closed in-window.
pub const DEFAULT_TARGET_PERCENT: f64 = 95.0;

/// Concrete collector for `SX-FINDINGS-SLA`.
#[derive(Debug)]
pub struct SxFindingsSlaCollector {
    stats: Box<dyn FindingSlaStats>,
    target_percent: f64,
}

impl SxFindingsSlaCollector {
    /// Construct a new collector with the default target
    /// ([`DEFAULT_TARGET_PERCENT`]).
    #[must_use]
    pub fn new(stats: Box<dyn FindingSlaStats>) -> Self {
        Self::with_target(stats, DEFAULT_TARGET_PERCENT)
    }

    /// Construct a new collector with a custom target percentage.
    #[must_use]
    pub fn with_target(stats: Box<dyn FindingSlaStats>, target_percent: f64) -> Self {
        Self {
            stats,
            target_percent,
        }
    }
}

#[async_trait]
impl EvidenceCollector for SxFindingsSlaCollector {
    fn control_id(&self) -> &'static str {
        CONTROL_ID
    }
    fn framework(&self) -> Framework {
        Framework::Nist80053
    }
    fn schedule(&self) -> EvidenceSchedule {
        EvidenceSchedule::Daily { hour_utc: 5 }
    }

    async fn collect(&self, ctx: &CollectionContext) -> Result<Evidence, CollectorError> {
        let counts = self.stats.counts().await?;
        // Avoid division-by-zero: when no critical findings closed in
        // the window we treat SLA compliance as 100% (vacuous truth).
        // The raw counts are still preserved in the evidence so a
        // reviewer can see "n=0" if needed.
        #[allow(clippy::cast_precision_loss)]
        let percent_within_sla = if counts.critical_closed == 0 {
            100.0
        } else {
            (counts.critical_closed_within_sla as f64 / counts.critical_closed as f64) * 100.0
        };
        let healthy = percent_within_sla >= self.target_percent;

        let envelope = FindingsSlaEvidence {
            counts,
            percent_within_sla,
            healthy,
            target_percent: self.target_percent,
        };
        let payload = serde_json::to_vec(&envelope)
            .map_err(|e| CollectorError::PayloadEncoding(e.to_string()))?;

        Ok(Evidence::new(
            CONTROL_ID,
            Framework::Nist80053,
            ctx.now,
            EvidenceContentType::Json,
            payload,
            VERSION,
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Mutex;

    use time::macros::datetime;

    use super::*;

    #[derive(Debug)]
    struct StubStats {
        counts: Mutex<SlaCounts>,
    }

    #[async_trait]
    impl FindingSlaStats for StubStats {
        async fn counts(&self) -> Result<SlaCounts, CollectorError> {
            Ok(*self.counts.lock().unwrap())
        }
    }

    fn stub(closed: u64, within: u64) -> StubStats {
        StubStats {
            counts: Mutex::new(SlaCounts {
                critical_closed: closed,
                critical_closed_within_sla: within,
            }),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn healthy_when_at_or_above_target() {
        let c = SxFindingsSlaCollector::new(Box::new(stub(100, 96)));
        let ctx = CollectionContext::new(datetime!(2026-06-12 05:00:00 UTC), "att-1");
        let ev = c.collect(&ctx).await.unwrap();
        let parsed: FindingsSlaEvidence = serde_json::from_slice(&ev.payload).unwrap();
        assert!(parsed.healthy);
        assert!((parsed.percent_within_sla - 96.0).abs() < 1e-9);
        assert!((parsed.target_percent - 95.0).abs() < 1e-9);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unhealthy_when_below_target() {
        let c = SxFindingsSlaCollector::new(Box::new(stub(100, 80)));
        let ctx = CollectionContext::new(datetime!(2026-06-12 05:00:00 UTC), "att-1");
        let ev = c.collect(&ctx).await.unwrap();
        let parsed: FindingsSlaEvidence = serde_json::from_slice(&ev.payload).unwrap();
        assert!(!parsed.healthy);
        assert!((parsed.percent_within_sla - 80.0).abs() < 1e-9);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn empty_window_is_vacuously_healthy() {
        let c = SxFindingsSlaCollector::new(Box::new(stub(0, 0)));
        let ctx = CollectionContext::new(datetime!(2026-06-12 05:00:00 UTC), "att-1");
        let ev = c.collect(&ctx).await.unwrap();
        let parsed: FindingsSlaEvidence = serde_json::from_slice(&ev.payload).unwrap();
        assert!(parsed.healthy);
        assert!((parsed.percent_within_sla - 100.0).abs() < 1e-9);
        assert_eq!(parsed.counts.critical_closed, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn custom_target_overrides_default() {
        let c = SxFindingsSlaCollector::with_target(Box::new(stub(100, 90)), 85.0);
        let ctx = CollectionContext::new(datetime!(2026-06-12 05:00:00 UTC), "att-1");
        let ev = c.collect(&ctx).await.unwrap();
        let parsed: FindingsSlaEvidence = serde_json::from_slice(&ev.payload).unwrap();
        assert!(parsed.healthy);
        assert!((parsed.target_percent - 85.0).abs() < 1e-9);
    }
}
