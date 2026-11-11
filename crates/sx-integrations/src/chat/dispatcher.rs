//! Chat-ops outbound dispatcher.
//!
//! Wraps any [`ChatNotifier`] with two pieces of policy the raw notifier
//! doesn't enforce on its own:
//!
//! 1. **Rate limit** — at most one post per channel per
//!    [`DispatcherConfig::min_interval`] interval (default: 1s). When a
//!    second post lands inside the window the dispatcher returns
//!    `DispatchOutcome::RateLimited` and emits a `rate_limited` audit
//!    event instead of forwarding. We do not queue — chat-ops is a
//!    best-effort surface and queueing duplicate alerts is worse UX than
//!    dropping them.
//! 2. **Duplicate coalesce** — when a payload identical to a recent post
//!    (within [`DispatcherConfig::coalesce_window`], default 60s) lands,
//!    the dispatcher returns `DispatchOutcome::Coalesced` and emits a
//!    `coalesced` audit row instead of forwarding.
//!
//! "Identity" is computed as a stable SHA-256 over `(channel, title,
//! summary, deep_link, fields)`. Severity is intentionally excluded —
//! the same finding escalating from `Medium` to `Critical` is *not*
//! a duplicate and must be forwarded.
//!
//! ## Audit emission
//!
//! Every dispatch attempt emits exactly one [`ChatAuditEvent`] regardless
//! of outcome. The dispatcher is the single source of truth for the
//! chat-ops audit trail — callers MUST NOT also emit events from their
//! pipelines.

use std::collections::HashMap;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use super::audit::{
    ChatAuditDirection, ChatAuditEvent, ChatAuditOutcome, ChatAuditProvider, ChatAuditSink,
};
use super::{ChatAlert, ChatError, ChatNotifier};

/// Default minimum interval between two posts on the same channel.
pub const DEFAULT_MIN_INTERVAL_SECS: u64 = 1;

/// Default duplicate-coalesce window.
pub const DEFAULT_COALESCE_WINDOW_SECS: u64 = 60;

/// Dispatcher tuning knobs.
#[derive(Debug, Clone, Copy)]
pub struct DispatcherConfig {
    /// Minimum interval between two posts on the same channel.
    pub min_interval_secs: u64,
    /// Window during which identical payloads are coalesced.
    pub coalesce_window_secs: u64,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            min_interval_secs: DEFAULT_MIN_INTERVAL_SECS,
            coalesce_window_secs: DEFAULT_COALESCE_WINDOW_SECS,
        }
    }
}

/// Outcome of a single [`ChatDispatcher::dispatch`] call.
#[derive(Debug)]
pub enum DispatchOutcome {
    /// The alert was posted to the remote successfully.
    Posted,
    /// The alert was suppressed because an identical one had been posted
    /// to the same channel within the coalesce window.
    Coalesced,
    /// The alert was suppressed because the channel's rate limit was hit.
    RateLimited,
    /// The notifier returned an error. The error is surfaced verbatim so
    /// the caller can decide whether to retry; the dispatcher does not
    /// retry on its own.
    Failed(ChatError),
}

impl DispatchOutcome {
    /// Maps the outcome onto the matching [`ChatAuditOutcome`].
    #[must_use]
    pub const fn as_audit_outcome(&self) -> ChatAuditOutcome {
        match self {
            Self::Posted => ChatAuditOutcome::Success,
            Self::Coalesced => ChatAuditOutcome::Coalesced,
            Self::RateLimited => ChatAuditOutcome::RateLimited,
            Self::Failed(_) => ChatAuditOutcome::Failed,
        }
    }
}

/// Abstract wall clock the dispatcher reads.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Epoch-seconds reading.
    fn now_unix(&self) -> i64;
}

/// Process wall clock backed by [`std::time::SystemTime`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    }
}

/// Pin-to-a-value clock used by tests.
#[derive(Debug, Clone)]
pub struct FixedClock {
    inner: Arc<std::sync::Mutex<i64>>,
}

impl FixedClock {
    /// Pin to `secs`.
    #[must_use]
    pub fn new(secs: i64) -> Self {
        Self {
            inner: Arc::new(std::sync::Mutex::new(secs)),
        }
    }

    /// Advance by `delta` seconds.
    pub fn advance(&self, delta: i64) {
        if let Ok(mut g) = self.inner.lock() {
            *g = g.saturating_add(delta);
        }
    }
}

impl Clock for FixedClock {
    fn now_unix(&self) -> i64 {
        self.inner.lock().map(|g| *g).unwrap_or_default()
    }
}

/// Per-channel state the dispatcher keeps to enforce the two policies.
#[derive(Debug, Clone)]
struct ChannelState {
    /// Epoch-seconds of the last successful post.
    last_post_unix: i64,
    /// Recent payload digests with their post-time, capped to the most
    /// recent entries that fall inside the coalesce window.
    recent_digests: Vec<(i64, [u8; 32])>,
}

impl Default for ChannelState {
    fn default() -> Self {
        Self {
            last_post_unix: i64::MIN,
            recent_digests: Vec::new(),
        }
    }
}

/// Outbound dispatcher.
///
/// Owns the [`ChatNotifier`] reference, the audit sink, and the
/// per-channel state map keyed on `(tenant_id, provider, channel)`. The
/// state is held behind a [`tokio::sync::Mutex`] so a multi-task
/// dispatch sequence stays serialised — the chat surface is low-volume
/// and not worth sharding.
pub struct ChatDispatcher {
    notifier: Arc<dyn ChatNotifier>,
    audit: Arc<dyn ChatAuditSink>,
    clock: Arc<dyn Clock>,
    cfg: DispatcherConfig,
    state: Mutex<HashMap<ChannelKey, ChannelState>>,
}

impl std::fmt::Debug for ChatDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatDispatcher")
            .field("provider", &self.notifier.provider())
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

/// Identity of a (tenant, provider, channel) triple.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ChannelKey {
    tenant_id: String,
    provider: ChatAuditProvider,
    channel: String,
}

impl ChatDispatcher {
    /// Construct a dispatcher with the default [`DispatcherConfig`].
    #[must_use]
    pub fn new(
        notifier: Arc<dyn ChatNotifier>,
        audit: Arc<dyn ChatAuditSink>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self::with_config(notifier, audit, clock, DispatcherConfig::default())
    }

    /// Construct a dispatcher with a custom config.
    #[must_use]
    pub fn with_config(
        notifier: Arc<dyn ChatNotifier>,
        audit: Arc<dyn ChatAuditSink>,
        clock: Arc<dyn Clock>,
        cfg: DispatcherConfig,
    ) -> Self {
        Self {
            notifier,
            audit,
            clock,
            cfg,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Dispatch `alert` for `tenant_id` to `channel`.
    ///
    /// Returns the [`DispatchOutcome`] the caller can map onto an HTTP
    /// status / retry decision. An audit row is emitted before this
    /// function returns.
    ///
    /// `finding_id` is recorded in the audit row when present — it does
    /// not affect the dispatch path.
    pub async fn dispatch(
        &self,
        tenant_id: &str,
        provider: ChatAuditProvider,
        channel: &str,
        alert: ChatAlert,
        finding_id: Option<&str>,
    ) -> DispatchOutcome {
        let key = ChannelKey {
            tenant_id: tenant_id.to_owned(),
            provider,
            channel: channel.to_owned(),
        };
        let now = self.clock.now_unix();
        let digest = payload_digest(&key, &alert);

        // Phase 1: decide the outcome under the lock.
        let decision = self.decide(&key, &digest, now).await;

        // Phase 2: execute outside the lock for IO, then commit the
        // state change atomically.
        let outcome = self
            .execute(
                decision, tenant_id, provider, channel, &alert, &key, digest, now,
            )
            .await;

        // Phase 3: audit.
        let event = ChatAuditEvent {
            tenant_id: tenant_id.to_owned(),
            direction: ChatAuditDirection::Outbound,
            provider,
            channel: channel.to_owned(),
            outcome: outcome.as_audit_outcome(),
            subject: Some(alert_subject(&alert)),
            finding_id: finding_id.map(str::to_owned),
            actor: None,
            error_code: match &outcome {
                DispatchOutcome::Failed(e) => Some(chat_error_code(e).to_owned()),
                _ => None,
            },
            emitted_at: rfc3339_from_unix(now),
        };
        self.audit.record(event).await;

        outcome
    }

    /// Phase 1: pick a [`Dispatch`] action under the per-channel lock.
    async fn decide(&self, key: &ChannelKey, digest: &[u8; 32], now: i64) -> Dispatch {
        let mut state = self.state.lock().await;
        let decision = {
            let entry = state.entry(key.clone()).or_default();
            // Drop digests that have aged out of the coalesce window.
            let window = i64::try_from(self.cfg.coalesce_window_secs).unwrap_or(i64::MAX);
            entry
                .recent_digests
                .retain(|(ts, _)| now.saturating_sub(*ts) <= window);

            // Coalesce check first: a duplicate inside the window is a
            // suppress, not a rate-limit, so we want it to dominate.
            if entry.recent_digests.iter().any(|(_, d)| d == digest) {
                Dispatch::Coalesce
            } else {
                let min_interval = i64::try_from(self.cfg.min_interval_secs).unwrap_or(i64::MAX);
                let elapsed = now.saturating_sub(entry.last_post_unix);
                if entry.last_post_unix != i64::MIN && elapsed < min_interval {
                    Dispatch::RateLimit
                } else {
                    // Tentatively reserve the slot. We only actually
                    // record the digest + bump last_post_unix when the
                    // notifier succeeds.
                    Dispatch::Forward
                }
            }
        };
        drop(state);
        decision
    }

    /// Phase 2: execute the decision. For [`Dispatch::Forward`] this
    /// posts to the wire and (on success) commits the new state.
    #[allow(clippy::too_many_arguments)]
    async fn execute(
        &self,
        decision: Dispatch,
        tenant_id: &str,
        provider: ChatAuditProvider,
        channel: &str,
        alert: &ChatAlert,
        key: &ChannelKey,
        digest: [u8; 32],
        now: i64,
    ) -> DispatchOutcome {
        match decision {
            Dispatch::Coalesce => {
                debug!(
                    target: "sx_integrations::chat::dispatcher",
                    tenant = tenant_id,
                    provider = provider.as_wire(),
                    channel,
                    "alert coalesced as duplicate"
                );
                DispatchOutcome::Coalesced
            }
            Dispatch::RateLimit => {
                warn!(
                    target: "sx_integrations::chat::dispatcher",
                    tenant = tenant_id,
                    provider = provider.as_wire(),
                    channel,
                    "alert rate limited"
                );
                DispatchOutcome::RateLimited
            }
            Dispatch::Forward => {
                self.forward(tenant_id, provider, channel, alert, key, digest, now)
                    .await
            }
        }
    }

    /// Post to the wire and, on success, commit the new state. Wraps
    /// the notifier error path so `execute` stays under the cognitive
    /// complexity ceiling.
    #[allow(clippy::too_many_arguments)]
    async fn forward(
        &self,
        tenant_id: &str,
        provider: ChatAuditProvider,
        channel: &str,
        alert: &ChatAlert,
        key: &ChannelKey,
        digest: [u8; 32],
        now: i64,
    ) -> DispatchOutcome {
        match self.notifier.post_alert(alert.clone()).await {
            Ok(()) => {
                self.commit_post(key.clone(), digest, now).await;
                DispatchOutcome::Posted
            }
            Err(err) => {
                warn!(
                    target: "sx_integrations::chat::dispatcher",
                    tenant = tenant_id,
                    provider = provider.as_wire(),
                    channel,
                    error = %err,
                    "alert dispatch failed"
                );
                DispatchOutcome::Failed(err)
            }
        }
    }

    /// Commit a successful post into the channel state map.
    async fn commit_post(&self, key: ChannelKey, digest: [u8; 32], now: i64) {
        let mut state = self.state.lock().await;
        {
            let entry = state.entry(key).or_default();
            entry.last_post_unix = now;
            entry.recent_digests.push((now, digest));
            // Trim to keep the vec bounded — at our rate (1/s) the
            // window can hold ~60 entries; we cap at 128 as a hard
            // safety bound.
            if entry.recent_digests.len() > 128 {
                let drop_count = entry.recent_digests.len() - 128;
                entry.recent_digests.drain(..drop_count);
            }
        }
        drop(state);
    }

    /// Record an inbound slash-command audit event.
    ///
    /// `outcome` is typically [`ChatAuditOutcome::Success`] for a verified
    /// command or [`ChatAuditOutcome::Rejected`] when signature
    /// verification failed.
    pub async fn audit_inbound(
        &self,
        tenant_id: &str,
        outcome: ChatAuditOutcome,
        subject: Option<&str>,
        finding_id: Option<&str>,
        actor: Option<&str>,
        error_code: Option<&str>,
    ) {
        let now = self.clock.now_unix();
        let event = ChatAuditEvent {
            tenant_id: tenant_id.to_owned(),
            direction: ChatAuditDirection::Inbound,
            provider: ChatAuditProvider::Slack,
            channel: "slash_command".to_owned(),
            outcome,
            subject: subject.map(str::to_owned),
            finding_id: finding_id.map(str::to_owned),
            actor: actor.map(str::to_owned),
            error_code: error_code.map(str::to_owned),
            emitted_at: rfc3339_from_unix(now),
        };
        self.audit.record(event).await;
    }
}

enum Dispatch {
    Coalesce,
    RateLimit,
    Forward,
}

fn payload_digest(key: &ChannelKey, alert: &ChatAlert) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(key.tenant_id.as_bytes());
    h.update([0u8]);
    h.update(key.provider.as_wire().as_bytes());
    h.update([0u8]);
    h.update(key.channel.as_bytes());
    h.update([0u8]);
    h.update(alert.title.as_bytes());
    h.update([0u8]);
    h.update(alert.summary.as_bytes());
    h.update([0u8]);
    if let Some(link) = alert.deep_link_url.as_ref() {
        h.update(link.as_bytes());
    }
    h.update([0u8]);
    for (k, v) in &alert.fields {
        h.update(k.as_bytes());
        h.update([0u8]);
        h.update(v.as_bytes());
        h.update([0u8]);
    }
    h.finalize().into()
}

fn alert_subject(alert: &ChatAlert) -> String {
    alert.title.clone()
}

const fn chat_error_code(err: &ChatError) -> &'static str {
    match err {
        ChatError::Transport(_) => "transport",
        ChatError::Format(_) => "format",
        ChatError::Unauthorized => "unauthorized",
        ChatError::RateLimited { .. } => "rate_limited",
        ChatError::InvalidConfig(_) => "invalid_config",
    }
}

fn rfc3339_from_unix(secs: i64) -> String {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    let Ok(dt) = OffsetDateTime::from_unix_timestamp(secs) else {
        return String::from("1970-01-01T00:00:00Z");
    };
    dt.format(&Rfc3339)
        .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::chat::audit::RecordingChatAuditSink;
    use crate::chat::{ChatSeverity, RecordingNotifier};
    use async_trait::async_trait;

    fn alert() -> ChatAlert {
        ChatAlert::new(
            ChatSeverity::High,
            "Suspicious login from new geo",
            "Multiple failed MFA prompts in 30s",
        )
        .with_field("actor", "u-42")
    }

    fn dispatcher_with(
        recorder: Arc<RecordingNotifier>,
        clock: FixedClock,
    ) -> (ChatDispatcher, Arc<RecordingChatAuditSink>) {
        let audit = Arc::new(RecordingChatAuditSink::new());
        let notifier: Arc<dyn ChatNotifier> = recorder;
        let d = ChatDispatcher::with_config(
            notifier,
            audit.clone(),
            Arc::new(clock),
            DispatcherConfig {
                min_interval_secs: 1,
                coalesce_window_secs: 60,
            },
        );
        (d, audit)
    }

    /// Failing notifier for the error-path test.
    #[derive(Debug)]
    struct FailingNotifier;

    #[async_trait]
    impl ChatNotifier for FailingNotifier {
        fn provider(&self) -> &'static str {
            "failing"
        }
        async fn post_alert(&self, _: ChatAlert) -> Result<(), ChatError> {
            Err(ChatError::Unauthorized)
        }
    }

    #[tokio::test]
    async fn first_post_succeeds_and_is_audited() {
        let clock = FixedClock::new(1_700_000_000);
        let recorded = Arc::new(RecordingNotifier::new());
        let (d, audit) = dispatcher_with(recorded.clone(), clock);

        let outcome = d
            .dispatch(
                "t-1",
                ChatAuditProvider::Slack,
                "secops",
                alert(),
                Some("f-42"),
            )
            .await;
        assert!(matches!(outcome, DispatchOutcome::Posted));
        assert_eq!(recorded.len(), 1);
        let trail = audit.snapshot();
        assert_eq!(trail.len(), 1);
        assert_eq!(trail[0].outcome, ChatAuditOutcome::Success);
        assert_eq!(trail[0].finding_id.as_deref(), Some("f-42"));
        assert_eq!(
            trail[0].subject.as_deref(),
            Some("Suspicious login from new geo")
        );
    }

    #[tokio::test]
    async fn second_post_within_one_second_is_rate_limited() {
        let clock = FixedClock::new(1_700_000_000);
        let recorded = Arc::new(RecordingNotifier::new());
        let (d, audit) = dispatcher_with(recorded.clone(), clock);

        let mut a = alert();
        a.title = "first".into();
        let o1 = d
            .dispatch("t-1", ChatAuditProvider::Slack, "secops", a, None)
            .await;
        assert!(matches!(o1, DispatchOutcome::Posted));

        // Different payload, same channel, same second — rate limited.
        let mut a = alert();
        a.title = "second".into();
        let o2 = d
            .dispatch("t-1", ChatAuditProvider::Slack, "secops", a, None)
            .await;
        assert!(matches!(o2, DispatchOutcome::RateLimited));

        // Only the first hit the wire.
        assert_eq!(recorded.len(), 1);

        // Audit captured both, with the right outcomes.
        let trail = audit.snapshot();
        assert_eq!(trail.len(), 2);
        assert_eq!(trail[0].outcome, ChatAuditOutcome::Success);
        assert_eq!(trail[1].outcome, ChatAuditOutcome::RateLimited);
    }

    #[tokio::test]
    async fn rate_limit_clears_after_min_interval() {
        let clock = FixedClock::new(1_700_000_000);
        let recorded = Arc::new(RecordingNotifier::new());
        let (d, _audit) = dispatcher_with(recorded.clone(), clock.clone());

        let mut a = alert();
        a.title = "first".into();
        d.dispatch("t-1", ChatAuditProvider::Slack, "secops", a, None)
            .await;

        // Advance two seconds. Different payload to bypass coalesce.
        clock.advance(2);
        let mut a = alert();
        a.title = "second".into();
        let o = d
            .dispatch("t-1", ChatAuditProvider::Slack, "secops", a, None)
            .await;
        assert!(matches!(o, DispatchOutcome::Posted));
        assert_eq!(recorded.len(), 2);
    }

    #[tokio::test]
    async fn duplicate_payload_inside_60s_is_coalesced() {
        let clock = FixedClock::new(1_700_000_000);
        let recorded = Arc::new(RecordingNotifier::new());
        let (d, audit) = dispatcher_with(recorded.clone(), clock.clone());

        let o1 = d
            .dispatch("t-1", ChatAuditProvider::Slack, "secops", alert(), None)
            .await;
        assert!(matches!(o1, DispatchOutcome::Posted));

        // Even after we wait past the rate limit, the identical payload
        // must be coalesced because we are still inside the 60s window.
        clock.advance(30);
        let o2 = d
            .dispatch("t-1", ChatAuditProvider::Slack, "secops", alert(), None)
            .await;
        assert!(matches!(o2, DispatchOutcome::Coalesced));
        assert_eq!(recorded.len(), 1);

        // Audit shows success + coalesced.
        let trail = audit.snapshot();
        assert_eq!(trail.len(), 2);
        assert_eq!(trail[0].outcome, ChatAuditOutcome::Success);
        assert_eq!(trail[1].outcome, ChatAuditOutcome::Coalesced);
    }

    #[tokio::test]
    async fn duplicate_past_60s_is_posted_again() {
        let clock = FixedClock::new(1_700_000_000);
        let recorded = Arc::new(RecordingNotifier::new());
        let (d, _audit) = dispatcher_with(recorded.clone(), clock.clone());

        d.dispatch("t-1", ChatAuditProvider::Slack, "secops", alert(), None)
            .await;

        clock.advance(61);
        let o = d
            .dispatch("t-1", ChatAuditProvider::Slack, "secops", alert(), None)
            .await;
        assert!(matches!(o, DispatchOutcome::Posted));
        assert_eq!(recorded.len(), 2);
    }

    #[tokio::test]
    async fn coalesce_dominates_rate_limit_when_both_would_fire() {
        let clock = FixedClock::new(1_700_000_000);
        let recorded = Arc::new(RecordingNotifier::new());
        let (d, audit) = dispatcher_with(recorded, clock);

        d.dispatch("t-1", ChatAuditProvider::Slack, "secops", alert(), None)
            .await;

        // Same second, identical payload — both gates would fire. The
        // dispatcher reports `Coalesced` (the "no signal" outcome) rather
        // than `RateLimited` to avoid blaming volume for a bug-class
        // duplicate.
        let o = d
            .dispatch("t-1", ChatAuditProvider::Slack, "secops", alert(), None)
            .await;
        assert!(matches!(o, DispatchOutcome::Coalesced));

        let trail = audit.snapshot();
        assert_eq!(trail[1].outcome, ChatAuditOutcome::Coalesced);
    }

    #[tokio::test]
    async fn separate_channels_have_independent_state() {
        let clock = FixedClock::new(1_700_000_000);
        let recorded = Arc::new(RecordingNotifier::new());
        let (d, _audit) = dispatcher_with(recorded.clone(), clock);

        let o1 = d
            .dispatch("t-1", ChatAuditProvider::Slack, "secops", alert(), None)
            .await;
        let o2 = d
            .dispatch("t-1", ChatAuditProvider::Slack, "alerts", alert(), None)
            .await;
        let o3 = d
            .dispatch("t-1", ChatAuditProvider::Teams, "secops", alert(), None)
            .await;
        let o4 = d
            .dispatch("t-2", ChatAuditProvider::Slack, "secops", alert(), None)
            .await;

        // None of these collide; all four are posted.
        assert!(matches!(o1, DispatchOutcome::Posted));
        assert!(matches!(o2, DispatchOutcome::Posted));
        assert!(matches!(o3, DispatchOutcome::Posted));
        assert!(matches!(o4, DispatchOutcome::Posted));
        assert_eq!(recorded.len(), 4);
    }

    #[tokio::test]
    async fn notifier_error_surfaces_as_failed_and_is_audited() {
        let clock = FixedClock::new(1_700_000_000);
        let notifier: Arc<dyn ChatNotifier> = Arc::new(FailingNotifier);
        let audit = Arc::new(RecordingChatAuditSink::new());
        let d = ChatDispatcher::new(notifier, audit.clone(), Arc::new(clock));

        let o = d
            .dispatch("t-1", ChatAuditProvider::Slack, "secops", alert(), None)
            .await;
        assert!(matches!(
            o,
            DispatchOutcome::Failed(ChatError::Unauthorized)
        ));

        let trail = audit.snapshot();
        assert_eq!(trail.len(), 1);
        assert_eq!(trail[0].outcome, ChatAuditOutcome::Failed);
        assert_eq!(trail[0].error_code.as_deref(), Some("unauthorized"));
    }

    #[tokio::test]
    async fn inbound_audit_records_actor_and_finding() {
        let clock = FixedClock::new(1_700_000_000);
        let notifier: Arc<dyn ChatNotifier> = Arc::new(RecordingNotifier::new());
        let audit = Arc::new(RecordingChatAuditSink::new());
        let d = ChatDispatcher::new(notifier, audit.clone(), Arc::new(clock));

        d.audit_inbound(
            "t-1",
            ChatAuditOutcome::Success,
            Some("ack"),
            Some("f-42"),
            Some("U0RICK"),
            None,
        )
        .await;
        let trail = audit.snapshot();
        assert_eq!(trail.len(), 1);
        assert_eq!(trail[0].direction, ChatAuditDirection::Inbound);
        assert_eq!(trail[0].provider, ChatAuditProvider::Slack);
        assert_eq!(trail[0].channel, "slash_command");
        assert_eq!(trail[0].subject.as_deref(), Some("ack"));
        assert_eq!(trail[0].finding_id.as_deref(), Some("f-42"));
        assert_eq!(trail[0].actor.as_deref(), Some("U0RICK"));
    }

    #[tokio::test]
    async fn debug_impl_does_not_panic_or_leak() {
        let clock = FixedClock::new(0);
        let notifier: Arc<dyn ChatNotifier> = Arc::new(RecordingNotifier::new());
        let audit = Arc::new(RecordingChatAuditSink::new());
        let d = ChatDispatcher::new(notifier, audit, Arc::new(clock));
        let dbg = format!("{d:?}");
        assert!(dbg.contains("ChatDispatcher"));
        assert!(dbg.contains("recording"));
    }
}
