//! Minimal audit sink for runtime-ingestion batches.
//!
//! Each accepted ingestion call produces one [`IngestionAuditEvent`] row
//! summarising the batch (tenant, `alert_count`, accepted/rejected count,
//! HMAC outcome). The crate deliberately defines its own narrow port
//! ([`IngestionAuditSink`]) instead of binding to `sx-audit::AuditSink`
//! directly — keeping this crate's tests and the composition root
//! independent of the heavier hash-chain machinery in `sx-audit`. An
//! adapter at the monolith composition root forwards these into the
//! tenant-wide chain.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use time::OffsetDateTime;

use crate::error::RuntimeError;

/// Outcome of an ingestion batch — drives the audit row's `decision`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditOutcome {
    /// All alerts in the batch were accepted.
    Accepted,
    /// Some alerts were accepted, some skipped (e.g. unsupported source).
    Partial,
    /// The whole batch was rejected (auth, replay window, malformed JSON).
    Rejected,
}

impl AuditOutcome {
    /// Canonical lowercase label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Partial => "partial",
            Self::Rejected => "rejected",
        }
    }
}

/// One audit row per ingestion batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestionAuditEvent {
    /// Owning tenant.
    pub tenant_id: String,
    /// Wall-clock time the batch was processed.
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    /// Total number of alerts in the batch.
    pub alert_count: usize,
    /// Number of alerts that produced a [`crate::RuntimeFinding`].
    pub accepted: usize,
    /// Number of alerts that were rejected after the batch was authorised.
    pub rejected: usize,
    /// Overall batch outcome.
    pub outcome: AuditOutcome,
    /// Optional human-readable reason — never includes raw payloads or
    /// signing-key material.
    pub reason: Option<String>,
}

impl IngestionAuditEvent {
    /// Convenience constructor stamped at the current wall clock.
    #[must_use]
    pub fn new(
        tenant_id: &str,
        alert_count: usize,
        accepted: usize,
        rejected: usize,
        outcome: AuditOutcome,
        reason: Option<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.to_owned(),
            at: OffsetDateTime::now_utc(),
            alert_count,
            accepted,
            rejected,
            outcome,
            reason,
        }
    }
}

/// Persistence port for runtime-ingestion audit rows.
#[async_trait]
pub trait IngestionAuditSink: Send + Sync + std::fmt::Debug {
    /// Persist the audit event. Implementations must be idempotent under
    /// retries.
    async fn record(&self, event: IngestionAuditEvent) -> Result<(), RuntimeError>;
}

/// Default no-op sink used when no audit backend is wired in. Useful in
/// tests and during incremental rollout.
#[derive(Debug, Default, Clone)]
pub struct NullAuditSink;

#[async_trait]
impl IngestionAuditSink for NullAuditSink {
    async fn record(&self, event: IngestionAuditEvent) -> Result<(), RuntimeError> {
        tracing::debug!(
            target: "sx_runtime",
            tenant_id = event.tenant_id,
            count = event.alert_count,
            outcome = event.outcome.as_str(),
            "ingestion audit (null sink)"
        );
        Ok(())
    }
}

/// In-memory sink that records events into a `Vec` for assertions in
/// tests. Cheap to clone — the storage sits behind an `Arc<Mutex>`.
#[derive(Debug, Default)]
pub struct RecordingAuditSink {
    inner: std::sync::Arc<Mutex<Vec<IngestionAuditEvent>>>,
}

impl Clone for RecordingAuditSink {
    fn clone(&self) -> Self {
        Self {
            inner: std::sync::Arc::clone(&self.inner),
        }
    }
}

impl RecordingAuditSink {
    /// Construct an empty recording sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the recorded events.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeError::Internal`] only if the internal mutex was
    /// poisoned by a panicking writer — never observed in normal use.
    pub fn snapshot(&self) -> Result<Vec<IngestionAuditEvent>, RuntimeError> {
        self.inner
            .lock()
            .map(|g| g.clone())
            .map_err(|_| RuntimeError::Internal("audit sink mutex poisoned".into()))
    }
}

#[async_trait]
impl IngestionAuditSink for RecordingAuditSink {
    async fn record(&self, event: IngestionAuditEvent) -> Result<(), RuntimeError> {
        self.inner
            .lock()
            .map(|mut g| g.push(event))
            .map_err(|_| RuntimeError::Internal("audit sink mutex poisoned".into()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn null_sink_accepts_every_event() {
        let sink = NullAuditSink;
        let ev = IngestionAuditEvent::new("t1", 1, 1, 0, AuditOutcome::Accepted, None);
        sink.record(ev).await.unwrap();
    }

    #[tokio::test]
    async fn recording_sink_collects_events() {
        let sink = RecordingAuditSink::new();
        let ev1 = IngestionAuditEvent::new("t1", 1, 1, 0, AuditOutcome::Accepted, None);
        let ev2 =
            IngestionAuditEvent::new("t1", 2, 0, 2, AuditOutcome::Rejected, Some("bad".into()));
        sink.record(ev1).await.unwrap();
        sink.record(ev2.clone()).await.unwrap();
        let snap = sink.snapshot().unwrap();
        assert_eq!(snap.len(), 2);
        assert_eq!(
            snap.get(1).expect("event 1").outcome,
            AuditOutcome::Rejected
        );
    }

    #[test]
    fn outcome_labels_are_canonical() {
        assert_eq!(AuditOutcome::Accepted.as_str(), "accepted");
        assert_eq!(AuditOutcome::Partial.as_str(), "partial");
        assert_eq!(AuditOutcome::Rejected.as_str(), "rejected");
    }
}
