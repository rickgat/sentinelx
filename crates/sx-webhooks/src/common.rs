//! Provider-agnostic event projection and handler trait.
//!
//! All provider modules ([`crate::github`], [`crate::slack`],
//! [`crate::jira`]) ultimately project verified payloads into a
//! [`WebhookEvent`]. Application code is expected to implement
//! [`WebhookHandler`] to fan these out to downstream pipelines.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::WebhookError;

/// A signature-verified, structurally validated webhook event.
///
/// Carries the *original* JSON payload so downstream consumers can
/// project provider-specific fields they care about without re-parsing
/// raw bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    /// Logical source provider, e.g. `"github"`, `"slack"`, `"jira"`.
    pub provider: String,

    /// Dotted event kind, e.g. `"pull_request.opened"`,
    /// `"message.channels"`, `"jira:issue_created"`.
    pub kind: String,

    /// Verified JSON payload as received. Never logged at any
    /// `tracing` level by this crate.
    pub payload: serde_json::Value,

    /// Wall-clock timestamp at which the verifying handler accepted
    /// the event.
    #[serde(with = "time::serde::rfc3339")]
    pub received_at: OffsetDateTime,
}

impl WebhookEvent {
    /// Construct a new [`WebhookEvent`] stamped with `OffsetDateTime::now_utc`.
    #[must_use]
    pub fn new(provider: &str, kind: &str, payload: serde_json::Value) -> Self {
        Self {
            provider: provider.to_owned(),
            kind: kind.to_owned(),
            payload,
            received_at: OffsetDateTime::now_utc(),
        }
    }
}

/// Async sink for verified webhook events.
///
/// Implementations should be cheap to clone and idempotent — providers
/// may legitimately re-deliver events on transient failures.
#[async_trait]
pub trait WebhookHandler: Send + Sync {
    /// Persist, route, or otherwise act on a verified event.
    async fn handle(&self, event: WebhookEvent) -> Result<(), WebhookError>;
}
