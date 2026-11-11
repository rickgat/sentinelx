//! Audit sink for bug-bounty outbound pushes and inbound ingests.
//!
//! Every push attempt and every inbound webhook ingest emits a single
//! [`BugBountyAuditEvent`]. The [`BugBountyAuditSink`] trait abstracts
//! over the persistence layer: the monolith wires it to the audit-query
//! adapter, while tests use [`RecordingAuditSink`] to inspect the trail.
//!
//! ## Privacy
//!
//! The event intentionally records only the *kind* of operation, the
//! source identifier `SentinelX` minted (or the upstream report id for
//! inbound), the connector kind, and the outcome shape. It never carries
//! the API token, the Basic-auth header, the webhook HMAC secret, the
//! upstream URL when it could carry a session cookie, or the raw
//! request/response body.

use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::connector::BugBountyKind;

/// What kind of operation produced an audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BugBountyAuditOp {
    /// Outbound push of a triaged finding to the program as an internal
    /// draft note.
    Push,
    /// Inbound webhook ingest from a researcher report.
    Ingest,
}

impl BugBountyAuditOp {
    /// Stable wire string.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::Ingest => "ingest",
        }
    }
}

/// Outcome of a single push / ingest attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BugBountyAuditOutcome {
    /// Operation succeeded.
    Success,
    /// Inbound report was identified as a duplicate of an existing
    /// finding; no new finding was minted.
    Deduplicated,
    /// Operation rejected at the auth layer (push only — bad token or
    /// signature mismatch on ingest).
    Rejected,
    /// Operation failed for any other reason (transport, format, rate
    /// limit, schema, …).
    Failed,
}

impl BugBountyAuditOutcome {
    /// Stable wire string.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Deduplicated => "deduplicated",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
        }
    }
}

/// A single audit event emitted on push / ingest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BugBountyAuditEvent {
    /// Tenant uuid the operation was scoped to.
    pub tenant_id: String,
    /// Connector kind.
    pub kind: BugBountyKind,
    /// Program handle the operation targeted.
    pub program_handle: String,
    /// What kind of operation produced the event.
    pub op: BugBountyAuditOp,
    /// Outcome of the operation.
    pub outcome: BugBountyAuditOutcome,
    /// Source identifier:
    /// * `Push` — the SentinelX finding uuid being pushed.
    /// * `Ingest` — the upstream report id.
    pub source_ref: String,
    /// Optional upstream identifier returned by the platform on success
    /// (e.g. internal-note id).
    pub upstream_id: Option<String>,
    /// Optional canonical source tag minted for an ingested report
    /// (`bugbounty.<platform>.researcher_<id>`).
    pub canonical_source: Option<String>,
    /// Optional id of the existing finding the candidate deduplicated
    /// against. Only set when `outcome == Deduplicated`.
    pub dedup_existing_id: Option<String>,
    /// Optional error code surfaced by the connector / webhook layer
    /// (e.g. `"transport"`, `"unauthorized"`, `"signature_mismatch"`).
    pub error_code: Option<String>,
    /// RFC 3339 timestamp the event was emitted.
    pub emitted_at: String,
}

/// Append-only audit sink for bug-bounty operations.
#[async_trait]
pub trait BugBountyAuditSink: Send + Sync + std::fmt::Debug {
    /// Record `event`. Implementations must be idempotent under
    /// retransmission but the caller emits each event exactly once.
    async fn record(&self, event: BugBountyAuditEvent);
}

/// Drop-everything audit sink used as the default when the monolith has
/// no audit-query wiring registered.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAuditSink;

#[async_trait]
impl BugBountyAuditSink for NoopAuditSink {
    async fn record(&self, _event: BugBountyAuditEvent) {}
}

/// In-memory audit sink used by tests to assert on the audit trail.
#[derive(Default, Clone)]
pub struct RecordingAuditSink {
    inner: Arc<Mutex<Vec<BugBountyAuditEvent>>>,
}

impl std::fmt::Debug for RecordingAuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingAuditSink")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl RecordingAuditSink {
    /// Construct an empty recording sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of recorded events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or_default()
    }

    /// Whether the recorder is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Snapshot of every recorded event.
    #[must_use]
    pub fn snapshot(&self) -> Vec<BugBountyAuditEvent> {
        self.inner.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

#[async_trait]
impl BugBountyAuditSink for RecordingAuditSink {
    async fn record(&self, event: BugBountyAuditEvent) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.push(event);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn event() -> BugBountyAuditEvent {
        BugBountyAuditEvent {
            tenant_id: "t-1".into(),
            kind: BugBountyKind::HackerOne,
            program_handle: "acme".into(),
            op: BugBountyAuditOp::Push,
            outcome: BugBountyAuditOutcome::Success,
            source_ref: "f-7".into(),
            upstream_id: Some("1000042".into()),
            canonical_source: None,
            dedup_existing_id: None,
            error_code: None,
            emitted_at: "2027-01-01T00:00:00Z".into(),
        }
    }

    #[tokio::test]
    async fn recording_sink_collects_events() {
        let sink = RecordingAuditSink::new();
        assert!(sink.is_empty());
        sink.record(event()).await;
        sink.record(event()).await;
        assert_eq!(sink.len(), 2);
        let snap = sink.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].outcome, BugBountyAuditOutcome::Success);
    }

    #[tokio::test]
    async fn noop_sink_does_not_panic() {
        let sink = NoopAuditSink;
        sink.record(event()).await;
    }

    #[test]
    fn op_wire_is_stable() {
        assert_eq!(BugBountyAuditOp::Push.as_wire(), "push");
        assert_eq!(BugBountyAuditOp::Ingest.as_wire(), "ingest");
    }

    #[test]
    fn outcome_wire_is_stable() {
        assert_eq!(BugBountyAuditOutcome::Success.as_wire(), "success");
        assert_eq!(
            BugBountyAuditOutcome::Deduplicated.as_wire(),
            "deduplicated"
        );
        assert_eq!(BugBountyAuditOutcome::Rejected.as_wire(), "rejected");
        assert_eq!(BugBountyAuditOutcome::Failed.as_wire(), "failed");
    }
}
