//! `SX-KILL-SWITCH-TESTED` — proves that the platform's autonomous
//! action kill-switch has been exercised within the last 90 days.
//!
//! Per TRD §28.2 the kill-switch is the operator's hard-stop on every
//! autonomous remediation. SOC 2 / ISO 27001 reviewers expect ongoing
//! attestation that it actually works, not just that it exists. This
//! collector calls into a [`KillSwitchTestLookup`] abstraction (so the
//! production wiring can read from `sx-audit` and tests can supply a
//! deterministic stub) and emits a JSON envelope describing the last
//! recorded test event.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::collector::schedule::{EvidenceSchedule, WeekdayCode};
use crate::collector::types::{Evidence, EvidenceContentType};
use crate::collector::{CollectionContext, CollectorError, EvidenceCollector};
use crate::model::framework::Framework;

/// Control identifier produced by this collector.
pub const CONTROL_ID: &str = "SX-KILL-SWITCH-TESTED";

/// Collector implementation version, stamped into every emitted record.
pub const VERSION: &str = "1.0.0";

/// Maximum age of an acceptable kill-switch test event.
pub const MAX_AGE_DAYS: i64 = 90;

/// Abstraction over "when was the kill-switch last tested?".
///
/// Production binds this to `sx-audit` event lookup; tests bind it
/// to an in-memory stub. Boxed-trait shape keeps the collector
/// constructor object-safe without dragging generics into the
/// registry.
#[async_trait]
pub trait KillSwitchTestLookup: Send + Sync + std::fmt::Debug {
    /// Return the timestamp of the most recent kill-switch test event,
    /// or [`None`] if none have ever been recorded.
    ///
    /// # Errors
    /// Returns [`CollectorError::Internal`] for transport failures.
    async fn last_test_at(&self) -> Result<Option<OffsetDateTime>, CollectorError>;
}

/// Concrete collector for `SX-KILL-SWITCH-TESTED`.
#[derive(Debug)]
pub struct SxKillSwitchTestedCollector {
    lookup: Box<dyn KillSwitchTestLookup>,
}

impl SxKillSwitchTestedCollector {
    /// Construct a new collector bound to `lookup`.
    #[must_use]
    pub fn new(lookup: Box<dyn KillSwitchTestLookup>) -> Self {
        Self { lookup }
    }
}

/// JSON envelope encoded into the [`Evidence::payload`] field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillSwitchEvidence {
    /// `true` when a test event was found inside the 90-day window.
    pub healthy: bool,
    /// RFC 3339 UTC timestamp of the most recent test, if any.
    pub last_test_at: Option<String>,
    /// Age (in whole days) of the most recent test, capped at
    /// [`i64::MAX`]. `None` when no test was ever recorded.
    pub age_days: Option<i64>,
    /// Threshold the collector evaluated against — pinned to
    /// [`MAX_AGE_DAYS`] so reviewers can audit the constant from
    /// the evidence alone.
    pub threshold_days: i64,
}

#[async_trait]
impl EvidenceCollector for SxKillSwitchTestedCollector {
    fn control_id(&self) -> &'static str {
        CONTROL_ID
    }
    fn framework(&self) -> Framework {
        Framework::Soc2
    }
    fn schedule(&self) -> EvidenceSchedule {
        EvidenceSchedule::Weekly {
            weekday: WeekdayCode::Monday,
            hour_utc: 6,
        }
    }

    async fn collect(&self, ctx: &CollectionContext) -> Result<Evidence, CollectorError> {
        let last = self.lookup.last_test_at().await?;
        let (healthy, age_days, last_iso) = match last {
            Some(ts) => {
                let age = ctx.now - ts;
                let age_days = age.whole_days();
                let healthy = age <= Duration::days(MAX_AGE_DAYS);
                let iso = ts
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(|e| CollectorError::PayloadEncoding(e.to_string()))?;
                (healthy, Some(age_days), Some(iso))
            }
            None => (false, None, None),
        };

        let envelope = KillSwitchEvidence {
            healthy,
            last_test_at: last_iso,
            age_days,
            threshold_days: MAX_AGE_DAYS,
        };
        let payload = serde_json::to_vec(&envelope)
            .map_err(|e| CollectorError::PayloadEncoding(e.to_string()))?;

        let evidence = Evidence::new(
            CONTROL_ID,
            Framework::Soc2,
            ctx.now,
            EvidenceContentType::Json,
            payload,
            VERSION,
        );

        if !healthy {
            // Note: we still emit the evidence (auditors want the
            // record of the gap) and signal the failure via the
            // collector error channel so the dispatcher can route it
            // to the dashboard. To keep this MVP slice simple we
            // prefer "evidence wins" and return Ok — the `healthy`
            // boolean inside the payload carries the signal.
        }

        Ok(evidence)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Mutex;

    use time::macros::datetime;

    use super::*;

    #[derive(Debug, Default)]
    struct StubLookup {
        last: Mutex<Option<OffsetDateTime>>,
    }

    #[async_trait]
    impl KillSwitchTestLookup for StubLookup {
        async fn last_test_at(&self) -> Result<Option<OffsetDateTime>, CollectorError> {
            Ok(*self.last.lock().unwrap())
        }
    }

    fn now() -> OffsetDateTime {
        datetime!(2026-06-12 09:00:00 UTC)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn healthy_when_last_test_within_90_days() {
        let stub = StubLookup {
            last: Mutex::new(Some(datetime!(2026-05-01 00:00:00 UTC))),
        };
        let collector = SxKillSwitchTestedCollector::new(Box::new(stub));
        let ctx = CollectionContext::new(now(), "att-1");
        let ev = collector.collect(&ctx).await.unwrap();
        let parsed: KillSwitchEvidence = serde_json::from_slice(&ev.payload).unwrap();
        assert!(parsed.healthy);
        assert_eq!(parsed.threshold_days, 90);
        assert_eq!(parsed.age_days, Some(42));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unhealthy_when_last_test_older_than_90_days() {
        let stub = StubLookup {
            last: Mutex::new(Some(datetime!(2026-01-01 00:00:00 UTC))),
        };
        let collector = SxKillSwitchTestedCollector::new(Box::new(stub));
        let ctx = CollectionContext::new(now(), "att-1");
        let ev = collector.collect(&ctx).await.unwrap();
        let parsed: KillSwitchEvidence = serde_json::from_slice(&ev.payload).unwrap();
        assert!(!parsed.healthy);
        assert!(parsed.age_days.unwrap_or(0) > 90);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unhealthy_when_never_tested() {
        let stub = StubLookup::default();
        let collector = SxKillSwitchTestedCollector::new(Box::new(stub));
        let ctx = CollectionContext::new(now(), "att-1");
        let ev = collector.collect(&ctx).await.unwrap();
        let parsed: KillSwitchEvidence = serde_json::from_slice(&ev.payload).unwrap();
        assert!(!parsed.healthy);
        assert!(parsed.last_test_at.is_none());
        assert!(parsed.age_days.is_none());
        assert_eq!(ev.control_id, CONTROL_ID);
        assert_eq!(ev.collector_version, VERSION);
    }
}
