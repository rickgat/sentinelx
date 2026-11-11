//! SOC routing port for drift findings raised on `Frozen → Active`.
//!
//! When an operator unfreezes a per-user baseline, [`detect_drift`](crate::drift::detect_drift)
//! produces a list of [`DriftFinding`](crate::drift::DriftFinding) records. Each
//! one needs to be routed to the SOC pipeline (the same pipeline that picks
//! up regular UEBA anomalies). This crate cannot take a hard dependency on
//! the SOC alert sink trait (`sx_soc::AlertSink`) because:
//!
//! 1. The SOC sink expects a full `Alert` shape that only the monolith
//!    composition root can assemble (it carries the per-tenant alert id
//!    ring, the rate-limit token bucket, the redaction policy, etc.).
//! 2. The unit tests need a narrow, mockable port that does not pull in
//!    `tokio::mpsc` channels.
//!
//! The [`FindingPipelineSink`] port is the narrow shim. The monolith
//! installs a real adapter that translates each [`DriftFinding`] into an
//! `sx_soc::Alert` of `Severity::Medium` and forwards it to the existing
//! `BufferAlertSink`.

use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;

use crate::drift::DriftFinding;

/// Where drift findings get routed when an operator unfreezes a baseline.
///
/// Implementations MUST be idempotent on repeated emissions of the same
/// `(tenant, user, dimension, key)` tuple — the unfreeze path is not
/// transactional, so a retry could attempt to emit the same finding twice.
#[async_trait]
pub trait FindingPipelineSink: Send + Sync + std::fmt::Debug {
    /// Route `finding` for `(tenant_id, user_id)` to SOC.
    async fn route(&self, tenant_id: &str, user_id: &str, finding: DriftFinding);
}

/// Default sink — drops every finding on the floor.
///
/// Used when no SOC pipeline is wired (dev / standalone monolith). The
/// drift detection still runs and the audit log still records the
/// transition; only the SOC alert fan-out is silent.
#[derive(Debug, Default, Clone)]
pub struct NullFindingPipelineSink;

#[async_trait]
impl FindingPipelineSink for NullFindingPipelineSink {
    async fn route(&self, _tenant_id: &str, _user_id: &str, _finding: DriftFinding) {
        // Intentionally empty — see struct doc.
    }
}

/// Test-only capturing sink. The integration test for the poisoning
/// scenario uses this to assert that drift findings actually fan out.
#[derive(Debug, Default, Clone)]
pub struct CapturingFindingPipelineSink {
    inner: Arc<Mutex<Vec<(String, String, DriftFinding)>>>,
}

impl CapturingFindingPipelineSink {
    /// Construct an empty capturing sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drain the captured records. Returns an empty `Vec` if the
    /// internal lock is poisoned (treated as "no records" — this sink
    /// is test-only and a poisoned lock is surfaced by the subsequent
    /// assertion).
    #[must_use]
    pub fn drain(&self) -> Vec<(String, String, DriftFinding)> {
        self.inner
            .lock()
            .map(|mut g| g.drain(..).collect())
            .unwrap_or_default()
    }

    /// Number of records captured so far. Returns `0` if the internal
    /// lock is poisoned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// `true` when no findings have been captured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl FindingPipelineSink for CapturingFindingPipelineSink {
    async fn route(&self, tenant_id: &str, user_id: &str, finding: DriftFinding) {
        if let Ok(mut g) = self.inner.lock() {
            g.push((tenant_id.to_owned(), user_id.to_owned(), finding));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn sample_finding() -> DriftFinding {
        DriftFinding {
            dimension: "hour_of_day".into(),
            key: "3".into(),
            snapshot_count: 1,
            live_count: 100,
            sigma: 9.0,
            reason: "test".into(),
        }
    }

    #[tokio::test]
    async fn null_sink_swallows_findings() {
        let sink = NullFindingPipelineSink;
        sink.route("t-1", "alice", sample_finding()).await;
    }

    #[tokio::test]
    async fn capturing_sink_collects_routed_findings() {
        let sink = CapturingFindingPipelineSink::new();
        assert!(sink.is_empty());
        sink.route("t-1", "alice", sample_finding()).await;
        sink.route("t-1", "bob", sample_finding()).await;
        assert_eq!(sink.len(), 2);
        let drained = sink.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].0, "t-1");
        assert_eq!(drained[0].1, "alice");
        assert!(sink.is_empty());
    }
}
