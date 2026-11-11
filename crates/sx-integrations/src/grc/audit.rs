//! Audit sink for GRC outbound pushes.
//!
//! Every push attempt — successful, failed, dead-lettered — emits a
//! single [`GrcAuditEvent`]. The [`GrcAuditSink`] trait abstracts over
//! the persistence layer: the monolith wires it to the audit-query
//! adapter, while tests use [`RecordingAuditSink`] to inspect the trail.
//!
//! ## Multi-tenant safety
//!
//! Every event carries `tenant_id` so the downstream store can isolate
//! by tenant. The sink is *append-only*: it never mutates an existing
//! event, which keeps the audit trail tamper-evident at the API layer.
//!
//! ## Privacy
//!
//! The event intentionally records only the *kind* of resource pushed
//! (`evidence` / `finding`), the source identifier the `SentinelX` side
//! minted, the connector kind, and the outcome shape. It never carries
//! the bearer token, the basic-auth header, the upstream URL when it
//! could carry a session cookie, or the raw response body.

use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::connector::GrcKind;

/// What kind of resource a push attempt carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GrcAuditResource {
    /// A [`super::connector::ComplianceEvidence`] record.
    Evidence,
    /// A [`super::connector::FindingState`] record.
    Finding,
}

impl GrcAuditResource {
    /// Stable wire string.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Evidence => "evidence",
            Self::Finding => "finding",
        }
    }
}

/// Outcome of a single push attempt as observed by the dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrcAuditOutcome {
    /// The push succeeded on the first attempt or after one or more
    /// retries.
    Success,
    /// The push failed with a retryable error and was queued for retry.
    Retry,
    /// The push exhausted the retry budget (or hit a permanent error)
    /// and landed on the dead-letter queue.
    DeadLetter,
    /// The push failed with a permanent error (e.g. `401`) and was
    /// short-circuited to the dead-letter queue.
    Permanent,
}

impl GrcAuditOutcome {
    /// Stable wire string.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Retry => "retry",
            Self::DeadLetter => "dead_letter",
            Self::Permanent => "permanent",
        }
    }
}

/// A single audit event emitted by [`super::dispatcher::GrcDispatcher`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrcAuditEvent {
    /// Tenant uuid the push was scoped to.
    pub tenant_id: String,
    /// Connector kind the push targeted.
    pub kind: GrcKind,
    /// Resource kind that was pushed.
    pub resource: GrcAuditResource,
    /// SentinelX-side identifier (evidence id or finding id) the push
    /// referenced. Used as the upsert key on the GRC side.
    pub source_ref: String,
    /// Outcome of the push attempt.
    pub outcome: GrcAuditOutcome,
    /// How many attempts the dispatcher made before settling on
    /// `outcome`. `1` for a first-attempt success or a permanent error.
    pub attempts: u32,
    /// Optional upstream identifier the GRC platform minted. Only set
    /// when `outcome` is [`GrcAuditOutcome::Success`].
    pub upstream_id: Option<String>,
    /// Optional error code surfaced by the connector. Captures the
    /// `ConnectorError` variant tag (e.g. `"transport"`,
    /// `"rate_limited"`, `"unauthorized"`).
    pub error_code: Option<String>,
    /// RFC 3339 timestamp the dispatcher emitted the event.
    pub emitted_at: String,
}

/// Append-only audit sink for GRC outbound pushes.
#[async_trait]
pub trait GrcAuditSink: Send + Sync + std::fmt::Debug {
    /// Record `event`. Implementations must be idempotent under
    /// retransmission but the dispatcher emits each event exactly once.
    async fn record(&self, event: GrcAuditEvent);
}

/// Drop-everything audit sink used as the default when the monolith
/// has no audit-query wiring registered for GRC.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAuditSink;

#[async_trait]
impl GrcAuditSink for NoopAuditSink {
    async fn record(&self, _event: GrcAuditEvent) {}
}

/// In-memory audit sink used by tests to assert on the audit trail.
#[derive(Default, Clone)]
pub struct RecordingAuditSink {
    inner: Arc<Mutex<Vec<GrcAuditEvent>>>,
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
    pub fn snapshot(&self) -> Vec<GrcAuditEvent> {
        self.inner.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

#[async_trait]
impl GrcAuditSink for RecordingAuditSink {
    async fn record(&self, event: GrcAuditEvent) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.push(event);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn event() -> GrcAuditEvent {
        GrcAuditEvent {
            tenant_id: "t-1".into(),
            kind: GrcKind::Vanta,
            resource: GrcAuditResource::Evidence,
            source_ref: "ev-1".into(),
            outcome: GrcAuditOutcome::Success,
            attempts: 1,
            upstream_id: Some("up-1".into()),
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
        assert_eq!(snap[0].outcome, GrcAuditOutcome::Success);
    }

    #[tokio::test]
    async fn noop_sink_does_not_panic() {
        let sink = NoopAuditSink;
        sink.record(event()).await;
    }

    #[test]
    fn outcome_wire_is_stable() {
        assert_eq!(GrcAuditOutcome::Success.as_wire(), "success");
        assert_eq!(GrcAuditOutcome::Retry.as_wire(), "retry");
        assert_eq!(GrcAuditOutcome::DeadLetter.as_wire(), "dead_letter");
        assert_eq!(GrcAuditOutcome::Permanent.as_wire(), "permanent");
    }

    #[test]
    fn resource_wire_is_stable() {
        assert_eq!(GrcAuditResource::Evidence.as_wire(), "evidence");
        assert_eq!(GrcAuditResource::Finding.as_wire(), "finding");
    }
}
