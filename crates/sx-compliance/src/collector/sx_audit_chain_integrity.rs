//! `SX-AUDIT-CHAIN-INTEGRITY` — attests that the append-only audit
//! chain for the last 7 days verifies cleanly.
//!
//! Per TRD §28.2 the audit chain is `SentinelX`'s tamper-evident
//! ledger; reviewers want continuous proof that the cryptographic
//! linkage holds. This collector hides the actual verification behind
//! the [`AuditChainVerifier`] abstraction (production wires it to
//! `sx-audit`; tests use a stub) and serialises the verifier's report
//! as the evidence payload.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::collector::schedule::EvidenceSchedule;
use crate::collector::types::{Evidence, EvidenceContentType};
use crate::collector::{CollectionContext, CollectorError, EvidenceCollector};
use crate::model::framework::Framework;

/// Control identifier produced by this collector.
pub const CONTROL_ID: &str = "SX-AUDIT-CHAIN-INTEGRITY";

/// Collector implementation version, stamped into every emitted record.
pub const VERSION: &str = "1.0.0";

/// Inclusive window the collector verifies, in days.
pub const WINDOW_DAYS: i64 = 7;

/// Result of a chain verification run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainVerificationReport {
    /// Number of audit records inspected.
    pub records_examined: u64,
    /// `true` when every link in the chain verified cleanly.
    pub verified: bool,
    /// If [`Self::verified`] is `false`, the id of the first failing
    /// record. Stored as a `String` so the collector does not depend
    /// on the underlying audit-record id type.
    pub first_failing_id: Option<String>,
    /// Window the verifier covered (start, end), RFC 3339.
    pub window_start: String,
    /// End of window, RFC 3339.
    pub window_end: String,
}

/// Abstraction over `sx-audit`'s chain-verification entry point.
///
/// Implementations are responsible for reading the audit ledger,
/// re-computing each record's hash linkage, and reporting on the last
/// `window_days` worth of entries.
#[async_trait]
pub trait AuditChainVerifier: Send + Sync + std::fmt::Debug {
    /// Verify the chain over the last `window_days` ending at `now`.
    ///
    /// # Errors
    /// Returns [`CollectorError::Internal`] on transport failure;
    /// integrity failures are reported via
    /// [`ChainVerificationReport::verified`], not via the result.
    async fn verify_chain(
        &self,
        now: OffsetDateTime,
        window_days: i64,
    ) -> Result<ChainVerificationReport, CollectorError>;
}

/// Concrete collector for `SX-AUDIT-CHAIN-INTEGRITY`.
#[derive(Debug)]
pub struct SxAuditChainIntegrityCollector {
    verifier: Box<dyn AuditChainVerifier>,
}

impl SxAuditChainIntegrityCollector {
    /// Construct a new collector bound to `verifier`.
    #[must_use]
    pub fn new(verifier: Box<dyn AuditChainVerifier>) -> Self {
        Self { verifier }
    }
}

#[async_trait]
impl EvidenceCollector for SxAuditChainIntegrityCollector {
    fn control_id(&self) -> &'static str {
        CONTROL_ID
    }
    fn framework(&self) -> Framework {
        Framework::Iso27001
    }
    fn schedule(&self) -> EvidenceSchedule {
        EvidenceSchedule::Daily { hour_utc: 4 }
    }

    async fn collect(&self, ctx: &CollectionContext) -> Result<Evidence, CollectorError> {
        let report = self.verifier.verify_chain(ctx.now, WINDOW_DAYS).await?;
        let payload = serde_json::to_vec(&report)
            .map_err(|e| CollectorError::PayloadEncoding(e.to_string()))?;
        Ok(Evidence::new(
            CONTROL_ID,
            Framework::Iso27001,
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
    struct StubVerifier {
        report: Mutex<ChainVerificationReport>,
    }

    #[async_trait]
    impl AuditChainVerifier for StubVerifier {
        async fn verify_chain(
            &self,
            _now: OffsetDateTime,
            _window_days: i64,
        ) -> Result<ChainVerificationReport, CollectorError> {
            Ok(self.report.lock().unwrap().clone())
        }
    }

    fn ok_report() -> ChainVerificationReport {
        ChainVerificationReport {
            records_examined: 12_345,
            verified: true,
            first_failing_id: None,
            window_start: "2026-06-05T00:00:00Z".into(),
            window_end: "2026-06-12T00:00:00Z".into(),
        }
    }

    fn bad_report() -> ChainVerificationReport {
        ChainVerificationReport {
            records_examined: 12_345,
            verified: false,
            first_failing_id: Some("rec-99".into()),
            window_start: "2026-06-05T00:00:00Z".into(),
            window_end: "2026-06-12T00:00:00Z".into(),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn emits_evidence_when_chain_verifies() {
        let stub = StubVerifier {
            report: Mutex::new(ok_report()),
        };
        let c = SxAuditChainIntegrityCollector::new(Box::new(stub));
        let ctx = CollectionContext::new(datetime!(2026-06-12 04:00:00 UTC), "att-1");
        let ev = c.collect(&ctx).await.unwrap();
        let parsed: ChainVerificationReport = serde_json::from_slice(&ev.payload).unwrap();
        assert!(parsed.verified);
        assert_eq!(parsed.records_examined, 12_345);
        assert_eq!(ev.control_id, CONTROL_ID);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn captures_failure_when_chain_breaks() {
        let stub = StubVerifier {
            report: Mutex::new(bad_report()),
        };
        let c = SxAuditChainIntegrityCollector::new(Box::new(stub));
        let ctx = CollectionContext::new(datetime!(2026-06-12 04:00:00 UTC), "att-1");
        let ev = c.collect(&ctx).await.unwrap();
        let parsed: ChainVerificationReport = serde_json::from_slice(&ev.payload).unwrap();
        assert!(!parsed.verified);
        assert_eq!(parsed.first_failing_id.as_deref(), Some("rec-99"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn collector_reports_iso27001_framework_and_daily_schedule() {
        let stub = StubVerifier {
            report: Mutex::new(ok_report()),
        };
        let c = SxAuditChainIntegrityCollector::new(Box::new(stub));
        assert_eq!(c.framework(), Framework::Iso27001);
        assert_eq!(c.schedule(), EvidenceSchedule::Daily { hour_utc: 4 });
        assert_eq!(c.control_id(), CONTROL_ID);
    }
}
