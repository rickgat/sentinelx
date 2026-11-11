//! Audit sink for chat-ops events.
//!
//! Every outbound dispatch (success / coalesced / rate-limited / failed)
//! and every inbound slash command (verified / rejected) emits a single
//! [`ChatAuditEvent`]. The [`ChatAuditSink`] trait abstracts over the
//! persistence layer: the monolith wires it to the audit-query adapter
//! while tests use [`RecordingChatAuditSink`] to inspect the trail.
//!
//! ## Privacy
//!
//! The event intentionally records only the *kind* of operation
//! (`outbound_dispatch` / `inbound_command`), the channel identifier the
//! event targeted, the verb (slack/teams), and the outcome shape. It
//! never carries the webhook URL, the signing secret, the request body,
//! or any other sensitive value.

use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Direction of the chat-ops event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ChatAuditDirection {
    /// `SentinelX` posted an alert to Slack / Teams.
    Outbound,
    /// A user posted a slash command into Slack and we received it.
    Inbound,
}

impl ChatAuditDirection {
    /// Stable wire string.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Outbound => "outbound",
            Self::Inbound => "inbound",
        }
    }
}

/// Outcome of a single chat-ops event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChatAuditOutcome {
    /// Dispatch posted successfully to the remote, or an inbound command
    /// passed signature verification.
    Success,
    /// The outbound dispatch was suppressed because an identical alert
    /// had already been posted within the coalescing window.
    Coalesced,
    /// The outbound dispatch was deferred because the per-channel
    /// 1 msg/sec rate limit was hit.
    RateLimited,
    /// Inbound: the request failed signature verification (HMAC mismatch,
    /// stale timestamp, malformed header).
    Rejected,
    /// Dispatch hit a transport / format / unauthorized error.
    Failed,
}

impl ChatAuditOutcome {
    /// Stable wire string.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Coalesced => "coalesced",
            Self::RateLimited => "rate_limited",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
        }
    }
}

/// Provider an audit event targeted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChatAuditProvider {
    /// Slack incoming webhooks + slash commands.
    Slack,
    /// Microsoft Teams power-automate webhooks.
    Teams,
}

impl ChatAuditProvider {
    /// Stable wire string.
    #[must_use]
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::Slack => "slack",
            Self::Teams => "teams",
        }
    }
}

/// A single audit event emitted by the chat-ops dispatcher / inbound
/// handler.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatAuditEvent {
    /// Tenant uuid the operation was scoped to.
    pub tenant_id: String,
    /// Direction (outbound dispatch vs inbound command).
    pub direction: ChatAuditDirection,
    /// Provider the event targeted.
    pub provider: ChatAuditProvider,
    /// Stable channel identifier (e.g. tenant-local channel name or
    /// hashed webhook id). Never the raw webhook URL.
    pub channel: String,
    /// Outcome of the event.
    pub outcome: ChatAuditOutcome,
    /// For outbound: the alert title; for inbound: the slash command verb
    /// (`ack` / `assign` / `mute`). Never the raw signing secret or
    /// timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Optional finding identifier the operation referenced. Set on
    /// inbound commands and on outbound alerts that carry a finding id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    /// Optional human-supplied actor id (slack user id) — set on inbound
    /// commands only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Optional error code surfaced by the dispatcher. Captures the
    /// `ChatError` variant tag (e.g. `"transport"`, `"rate_limited"`,
    /// `"unauthorized"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// RFC 3339 timestamp the dispatcher emitted the event.
    pub emitted_at: String,
}

/// Append-only audit sink for chat-ops events.
#[async_trait]
pub trait ChatAuditSink: Send + Sync + std::fmt::Debug {
    /// Record `event`. Implementations must be idempotent under
    /// retransmission but the dispatcher emits each event exactly once.
    async fn record(&self, event: ChatAuditEvent);
}

/// Drop-everything sink used as the default when the monolith has no
/// audit-query wiring registered for chat-ops.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopChatAuditSink;

#[async_trait]
impl ChatAuditSink for NoopChatAuditSink {
    async fn record(&self, _event: ChatAuditEvent) {}
}

/// In-memory sink used by tests to assert on the audit trail.
#[derive(Default, Clone)]
pub struct RecordingChatAuditSink {
    inner: Arc<Mutex<Vec<ChatAuditEvent>>>,
}

impl std::fmt::Debug for RecordingChatAuditSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingChatAuditSink")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl RecordingChatAuditSink {
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
    pub fn snapshot(&self) -> Vec<ChatAuditEvent> {
        self.inner.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

#[async_trait]
impl ChatAuditSink for RecordingChatAuditSink {
    async fn record(&self, event: ChatAuditEvent) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.push(event);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    fn event() -> ChatAuditEvent {
        ChatAuditEvent {
            tenant_id: "t-1".into(),
            direction: ChatAuditDirection::Outbound,
            provider: ChatAuditProvider::Slack,
            channel: "secops".into(),
            outcome: ChatAuditOutcome::Success,
            subject: Some("Suspicious login".into()),
            finding_id: Some("f-42".into()),
            actor: None,
            error_code: None,
            emitted_at: "2027-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn wire_strings_are_stable() {
        assert_eq!(ChatAuditDirection::Outbound.as_wire(), "outbound");
        assert_eq!(ChatAuditDirection::Inbound.as_wire(), "inbound");
        assert_eq!(ChatAuditProvider::Slack.as_wire(), "slack");
        assert_eq!(ChatAuditProvider::Teams.as_wire(), "teams");
        assert_eq!(ChatAuditOutcome::Success.as_wire(), "success");
        assert_eq!(ChatAuditOutcome::Coalesced.as_wire(), "coalesced");
        assert_eq!(ChatAuditOutcome::RateLimited.as_wire(), "rate_limited");
        assert_eq!(ChatAuditOutcome::Rejected.as_wire(), "rejected");
        assert_eq!(ChatAuditOutcome::Failed.as_wire(), "failed");
    }

    #[tokio::test]
    async fn recording_sink_captures_events_in_order() {
        let sink = RecordingChatAuditSink::new();
        assert!(sink.is_empty());

        let mut e1 = event();
        e1.subject = Some("first".into());
        let mut e2 = event();
        e2.subject = Some("second".into());

        sink.record(e1).await;
        sink.record(e2).await;
        assert_eq!(sink.len(), 2);
        let snap = sink.snapshot();
        assert_eq!(snap[0].subject.as_deref(), Some("first"));
        assert_eq!(snap[1].subject.as_deref(), Some("second"));
    }

    #[tokio::test]
    async fn noop_sink_swallows_events() {
        let sink = NoopChatAuditSink;
        sink.record(event()).await;
    }

    #[test]
    fn debug_impl_does_not_leak_event_contents() {
        let sink = RecordingChatAuditSink::new();
        let dbg = format!("{sink:?}");
        assert!(dbg.contains("RecordingChatAuditSink"));
    }
}
