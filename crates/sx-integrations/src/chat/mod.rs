//! Chat notifiers.
//!
//! Outbound adapters that post `SentinelX` alerts into team chat
//! platforms. Two transports are implemented today:
//!
//! * [`slack`] — Slack Incoming Webhooks, Block Kit JSON payload.
//! * [`teams`] — Microsoft Teams Incoming Webhooks, Adaptive Card JSON
//!   payload.
//!
//! Both implementations share the [`ChatNotifier`] trait so the caller
//! can pick a provider at runtime without leaking provider-specific
//! types into the audit / alerting pipeline.
//!
//! For tests and dry-run scenarios this module also exposes:
//!
//! * [`NoopNotifier`] — accepts every alert and returns `Ok(())` without
//!   making any network call.
//! * [`RecordingNotifier`] — captures every posted alert into an inner
//!   `Mutex<Vec<ChatAlert>>` so unit tests can assert on what *would*
//!   have been sent.
//!
//! ## Quality & safety
//!
//! * `#![forbid(unsafe_code)]` is inherited from the crate root.
//! * Webhook URLs are held as [`secrecy::SecretString`] and the per-type
//!   `Debug` impls redact them. The URL is sensitive because anyone who
//!   holds it can post arbitrary content into the channel.
//! * No `unwrap`/`expect`/`panic` outside tests — all errors flow
//!   through [`ChatError`].

pub mod audit;
pub mod config;
pub mod dispatcher;
pub mod inbound;
pub mod slack;
pub mod teams;

pub use audit::{
    ChatAuditDirection, ChatAuditEvent, ChatAuditOutcome, ChatAuditProvider, ChatAuditSink,
    NoopChatAuditSink, RecordingChatAuditSink,
};
pub use config::{
    load_signing_secret, load_webhook_url, ChatChannelConfig, ChatConfigError, ChatConfigStore,
    InMemoryChatConfigStore,
};
pub use dispatcher::{
    ChatDispatcher, Clock as DispatcherClock, DispatchOutcome, DispatcherConfig,
    FixedClock as DispatcherFixedClock, SystemClock as DispatcherSystemClock,
    DEFAULT_COALESCE_WINDOW_SECS, DEFAULT_MIN_INTERVAL_SECS,
};
pub use inbound::{
    compute_slack_signature_hex, parse_slash_command, verify_slack_signature, InboundError,
    SlackCommand, SIGNATURE_REPLAY_WINDOW_SECS,
};

use std::fmt;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Severity scale used by chat notifiers.
///
/// Intentionally a small, hand-rolled mirror of [`crate::siem::Severity`]
/// so the chat module stays decoupled from the SIEM forwarder shapes.
/// A `From<crate::siem::Severity>` impl below makes conversion trivial
/// for callers that already deal with the SIEM severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum ChatSeverity {
    /// Informational, no action required.
    Info,
    /// Low — worth knowing about.
    Low,
    /// Medium — investigate during business hours.
    Medium,
    /// High — investigate now.
    High,
    /// Critical — page on-call.
    Critical,
}

impl ChatSeverity {
    /// Short machine-readable label (lowercase).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Single-character emoji that callers can prepend to the alert
    /// title. Chosen for high-contrast visibility in dense channels.
    #[must_use]
    pub const fn emoji(self) -> &'static str {
        match self {
            Self::Critical => "\u{1f6a8}",    // 🚨
            Self::High => "\u{26a0}\u{fe0f}", // ⚠️
            Self::Medium => "\u{1f7e1}",      // 🟡
            Self::Low => "\u{1f535}",         // 🔵
            Self::Info => "\u{26aa}",         // ⚪
        }
    }

    /// Hex color (without the leading `#`) used as the Slack attachment
    /// `color` and the Teams `themeColor` fields. The exact values are
    /// load-bearing because dashboards and screenshots key off them.
    #[must_use]
    pub const fn hex_color(self) -> &'static str {
        match self {
            Self::Critical => "DD2222",
            Self::High => "DD8800",
            Self::Medium => "DDDD22",
            Self::Low => "2288DD",
            Self::Info => "888888",
        }
    }
}

impl From<crate::siem::Severity> for ChatSeverity {
    fn from(sev: crate::siem::Severity) -> Self {
        match sev {
            crate::siem::Severity::Info => Self::Info,
            crate::siem::Severity::Low => Self::Low,
            crate::siem::Severity::Medium => Self::Medium,
            crate::siem::Severity::High => Self::High,
            crate::siem::Severity::Critical => Self::Critical,
        }
    }
}

/// An alert ready to be posted into a chat channel.
///
/// The shape is intentionally provider-neutral. Each [`ChatNotifier`]
/// implementation is responsible for shaping it into Block Kit / Adaptive
/// Card / etc. on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChatAlert {
    /// Severity drives the icon and color.
    pub severity: ChatSeverity,
    /// Short, human-readable title (will be rendered as the alert heading).
    pub title: String,
    /// Longer-form summary (body paragraph).
    pub summary: String,
    /// Optional deep link back into `SentinelX` (e.g. the finding URL).
    /// Rendered as a clickable "Open in `SentinelX`" button when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deep_link_url: Option<String>,
    /// Additional key/value fields rendered as a definition list.
    ///
    /// Order is preserved on the wire so callers can put the most
    /// important context first.
    #[serde(default)]
    pub fields: Vec<(String, String)>,
}

impl ChatAlert {
    /// Construct a minimal alert with no extra fields and no deep link.
    #[must_use]
    pub fn new(
        severity: ChatSeverity,
        title: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            title: title.into(),
            summary: summary.into(),
            deep_link_url: None,
            fields: Vec::new(),
        }
    }

    /// Builder: attach a deep link.
    #[must_use]
    pub fn with_deep_link(mut self, url: impl Into<String>) -> Self {
        self.deep_link_url = Some(url.into());
        self
    }

    /// Builder: append a key/value field.
    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.push((key.into(), value.into()));
        self
    }
}

/// Errors surfaced by chat notifiers.
///
/// Modeled after [`crate::IntegrationError`] but kept distinct because
/// the chat surface needs `InvalidConfig` for malformed webhook URLs and
/// the SIEM/Jira surface does not.
#[derive(Debug, Error)]
pub enum ChatError {
    /// Network or TLS failure talking to the webhook host.
    #[error("chat transport error: {0}")]
    Transport(String),

    /// The local payload could not be serialized, or the remote returned
    /// a body that could not be parsed.
    #[error("chat format error: {0}")]
    Format(String),

    /// The remote rejected the request (HTTP `401`/`403`/`404` — for
    /// webhooks a `404` usually means the webhook has been revoked or
    /// rotated, which is an auth-class failure from the caller's POV).
    #[error("chat unauthorized: webhook rejected the request")]
    Unauthorized,

    /// HTTP `429 Too Many Requests`. `retry_after_secs` carries the
    /// parsed `Retry-After` header value when present.
    #[error("chat rate limited (retry after {retry_after_secs:?}s)")]
    RateLimited {
        /// Parsed value of the `Retry-After` header, in seconds.
        retry_after_secs: Option<u64>,
    },

    /// The configured webhook URL is missing, empty, or not a valid URL.
    #[error("chat invalid config: {0}")]
    InvalidConfig(String),
}

impl ChatError {
    /// Convenience constructor for transport errors.
    pub(crate) fn transport<E: fmt::Display>(err: E) -> Self {
        Self::Transport(err.to_string())
    }

    /// Convenience constructor for format errors.
    pub(crate) fn format<E: fmt::Display>(err: E) -> Self {
        Self::Format(err.to_string())
    }
}

impl From<reqwest::Error> for ChatError {
    fn from(err: reqwest::Error) -> Self {
        Self::transport(err)
    }
}

impl From<serde_json::Error> for ChatError {
    fn from(err: serde_json::Error) -> Self {
        Self::format(err)
    }
}

/// Outbound chat notifier.
///
/// Implementations may make network calls (Slack/Teams webhooks) or be
/// purely in-memory (noop/recording for tests). The trait is
/// [`Send`] + [`Sync`] so notifiers can be shared across tasks behind an
/// `Arc`.
#[async_trait]
pub trait ChatNotifier: Send + Sync {
    /// Stable, human-readable identifier of the underlying provider
    /// (`"slack"`, `"teams"`, `"noop"`, ...). Useful for tracing,
    /// metrics labels, and audit rows.
    fn provider(&self) -> &'static str;

    /// Post an alert. Implementations MUST NOT log webhook URLs or any
    /// other secret material.
    async fn post_alert(&self, alert: ChatAlert) -> Result<(), ChatError>;
}

/// A no-op notifier that accepts every alert without making a network
/// call. Useful for tests, dry-run modes, and "chat disabled" config.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopNotifier;

#[async_trait]
impl ChatNotifier for NoopNotifier {
    fn provider(&self) -> &'static str {
        "noop"
    }

    async fn post_alert(&self, _alert: ChatAlert) -> Result<(), ChatError> {
        Ok(())
    }
}

/// In-memory notifier that records every posted alert into a
/// `Mutex<Vec<ChatAlert>>`. Unit tests can drain the buffer and assert
/// on what *would* have been sent without standing up a wiremock server.
#[derive(Debug, Default)]
pub struct RecordingNotifier {
    inner: Mutex<Vec<ChatAlert>>,
}

impl RecordingNotifier {
    /// Construct a fresh recorder with an empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drain and return every alert posted so far. Subsequent calls
    /// start from an empty buffer.
    ///
    /// # Panics
    ///
    /// Panics only if the inner mutex was poisoned, which can only
    /// happen if another thread panicked while holding the lock — a
    /// bug the caller should surface immediately.
    #[must_use]
    pub fn take(&self) -> Vec<ChatAlert> {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        std::mem::take(&mut *guard)
    }

    /// Number of alerts recorded so far without draining.
    #[must_use]
    pub fn len(&self) -> usize {
        let guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.len()
    }

    /// `true` when no alerts have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl ChatNotifier for RecordingNotifier {
    fn provider(&self) -> &'static str {
        "recording"
    }

    async fn post_alert(&self, alert: ChatAlert) -> Result<(), ChatError> {
        {
            let mut guard = match self.inner.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.push(alert);
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn severity_emoji_and_color_table_is_stable() {
        // Critical
        assert_eq!(ChatSeverity::Critical.hex_color(), "DD2222");
        assert_eq!(ChatSeverity::Critical.emoji(), "\u{1f6a8}");
        // High
        assert_eq!(ChatSeverity::High.hex_color(), "DD8800");
        assert_eq!(ChatSeverity::High.emoji(), "\u{26a0}\u{fe0f}");
        // Medium
        assert_eq!(ChatSeverity::Medium.hex_color(), "DDDD22");
        assert_eq!(ChatSeverity::Medium.emoji(), "\u{1f7e1}");
        // Low
        assert_eq!(ChatSeverity::Low.hex_color(), "2288DD");
        assert_eq!(ChatSeverity::Low.emoji(), "\u{1f535}");
        // Info
        assert_eq!(ChatSeverity::Info.hex_color(), "888888");
        assert_eq!(ChatSeverity::Info.emoji(), "\u{26aa}");
    }

    #[test]
    fn severity_label_matches_lowercase_variant_name() {
        assert_eq!(ChatSeverity::Info.label(), "info");
        assert_eq!(ChatSeverity::Low.label(), "low");
        assert_eq!(ChatSeverity::Medium.label(), "medium");
        assert_eq!(ChatSeverity::High.label(), "high");
        assert_eq!(ChatSeverity::Critical.label(), "critical");
    }

    #[test]
    fn from_siem_severity_round_trips() {
        use crate::siem::Severity;
        assert_eq!(ChatSeverity::from(Severity::Info), ChatSeverity::Info);
        assert_eq!(ChatSeverity::from(Severity::Low), ChatSeverity::Low);
        assert_eq!(ChatSeverity::from(Severity::Medium), ChatSeverity::Medium);
        assert_eq!(ChatSeverity::from(Severity::High), ChatSeverity::High);
        assert_eq!(
            ChatSeverity::from(Severity::Critical),
            ChatSeverity::Critical
        );
    }

    #[test]
    fn chat_alert_builder_preserves_field_order() {
        let alert = ChatAlert::new(ChatSeverity::High, "Title", "Body")
            .with_field("env", "prod")
            .with_field("region", "us-east-1")
            .with_deep_link("https://sentinelx.example/f/123");

        assert_eq!(alert.title, "Title");
        assert_eq!(alert.summary, "Body");
        assert_eq!(
            alert.deep_link_url.as_deref(),
            Some("https://sentinelx.example/f/123")
        );
        assert_eq!(alert.fields.len(), 2);
        assert_eq!(alert.fields[0].0, "env");
        assert_eq!(alert.fields[1].0, "region");
    }

    #[tokio::test]
    async fn noop_notifier_accepts_alert() {
        let n = NoopNotifier;
        assert_eq!(n.provider(), "noop");
        let alert = ChatAlert::new(ChatSeverity::Info, "t", "s");
        n.post_alert(alert).await.unwrap();
    }

    #[tokio::test]
    async fn recording_notifier_captures_in_order() {
        let r = RecordingNotifier::new();
        assert!(r.is_empty());
        assert_eq!(r.provider(), "recording");

        r.post_alert(ChatAlert::new(ChatSeverity::Info, "a", "1"))
            .await
            .unwrap();
        r.post_alert(ChatAlert::new(ChatSeverity::High, "b", "2"))
            .await
            .unwrap();
        assert_eq!(r.len(), 2);

        let drained = r.take();
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].title, "a");
        assert_eq!(drained[1].title, "b");
        // After draining the buffer is empty again.
        assert!(r.is_empty());
    }
}
