//! Slack Incoming Webhooks notifier.
//!
//! Posts a Block Kit payload to a Slack webhook URL. The webhook URL is
//! held in a [`SecretString`] because possession of it grants the holder
//! the ability to post to the bound channel.
//!
//! ## Payload shape
//!
//! Slack accepts both top-level Block Kit (`blocks: [...]`) and the
//! older "attachments" envelope. We use the latter as the outer
//! envelope (so we can carry the severity `color` bar Slack renders
//! down the left edge of the message) and nest Block Kit blocks
//! inside. This is the recommended shape for severity-coded alerts —
//! plain Block Kit has no color affordance.
//!
//! The rendered message has three parts:
//!
//! 1. **Header**: `{emoji} {SEVERITY}: {title}` — `section` block with
//!    markdown text.
//! 2. **Summary**: free-form body text.
//! 3. **Fields**: a single `section` block with up to ten `mrkdwn`
//!    field pairs (Slack hard-caps fields per block at 10). Excess
//!    fields are dropped silently rather than failing the post.
//! 4. **Actions** *(when `deep_link_url` is set)*: a single
//!    `actions` block with an "Open in `SentinelX`" button.

use std::fmt;

use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{json, Value};
use tracing::{debug, warn};

use crate::chat::{ChatAlert, ChatError, ChatNotifier};
use async_trait::async_trait;

/// Slack hard-cap on `fields` per `section` block.
const SLACK_FIELDS_PER_BLOCK: usize = 10;

/// Configuration for a Slack webhook notifier.
///
/// `webhook_url` is the full `https://hooks.slack.com/services/...` URL
/// — sensitive, held as a [`SecretString`], redacted from `Debug`.
pub struct SlackWebhookConfig {
    /// Slack incoming webhook URL.
    pub webhook_url: SecretString,
}

impl fmt::Debug for SlackWebhookConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlackWebhookConfig")
            .field("webhook_url", &"<redacted>")
            .finish()
    }
}

impl SlackWebhookConfig {
    /// Construct a config from a raw URL string.
    #[must_use]
    pub fn new(webhook_url: impl Into<String>) -> Self {
        Self {
            webhook_url: SecretString::new(webhook_url.into().into_boxed_str()),
        }
    }
}

/// Slack incoming-webhook notifier.
pub struct SlackWebhookNotifier {
    http: Client,
    config: SlackWebhookConfig,
}

impl fmt::Debug for SlackWebhookNotifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlackWebhookNotifier")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl SlackWebhookNotifier {
    /// Construct a notifier with a caller-supplied [`Client`].
    ///
    /// The webhook URL inside `config` is validated (non-empty, parses
    /// as a URL) and rejected with [`ChatError::InvalidConfig`] otherwise.
    pub fn new(http: Client, config: SlackWebhookConfig) -> Result<Self, ChatError> {
        let raw = config.webhook_url.expose_secret();
        if raw.trim().is_empty() {
            return Err(ChatError::InvalidConfig(
                "slack webhook url is empty".to_owned(),
            ));
        }
        Url::parse(raw)
            .map_err(|e| ChatError::InvalidConfig(format!("slack webhook url invalid: {e}")))?;
        Ok(Self { http, config })
    }

    /// Build the Slack JSON payload for a given alert. Exposed for tests
    /// so we can assert on the wire shape without standing up wiremock.
    fn build_payload(alert: &ChatAlert) -> Value {
        let mut blocks: Vec<Value> = Vec::new();

        // Header block: emoji + SEVERITY + title.
        let header_text = format!(
            "{emoji} *{sev}*: {title}",
            emoji = alert.severity.emoji(),
            sev = alert.severity.label().to_uppercase(),
            title = alert.title,
        );
        blocks.push(json!({
            "type": "section",
            "text": { "type": "mrkdwn", "text": header_text }
        }));

        // Summary block.
        if !alert.summary.is_empty() {
            blocks.push(json!({
                "type": "section",
                "text": { "type": "mrkdwn", "text": alert.summary }
            }));
        }

        // Fields block — Slack caps `fields` at 10 per section.
        if !alert.fields.is_empty() {
            let field_values: Vec<Value> = alert
                .fields
                .iter()
                .take(SLACK_FIELDS_PER_BLOCK)
                .map(|(k, v)| json!({ "type": "mrkdwn", "text": format!("*{k}*\n{v}") }))
                .collect();
            blocks.push(json!({
                "type": "section",
                "fields": field_values
            }));
        }

        // Deep-link button.
        if let Some(url) = &alert.deep_link_url {
            blocks.push(json!({
                "type": "actions",
                "elements": [{
                    "type": "button",
                    "text": { "type": "plain_text", "text": "Open in SentinelX" },
                    "url": url,
                    "style": "primary"
                }]
            }));
        }

        // Outer attachment carries the color bar.
        json!({
            "attachments": [{
                "color": format!("#{}", alert.severity.hex_color()),
                "blocks": blocks
            }]
        })
    }
}

#[async_trait]
impl ChatNotifier for SlackWebhookNotifier {
    fn provider(&self) -> &'static str {
        "slack"
    }

    async fn post_alert(&self, alert: ChatAlert) -> Result<(), ChatError> {
        let payload = Self::build_payload(&alert);

        debug!(
            target: "sx_integrations::chat::slack",
            severity = alert.severity.label(),
            field_count = alert.fields.len(),
            has_deep_link = alert.deep_link_url.is_some(),
            "posting alert to slack webhook"
        );

        let resp = self
            .http
            .post(self.config.webhook_url.expose_secret())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&payload)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }

        if matches!(
            status,
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND
        ) {
            warn!(
                target: "sx_integrations::chat::slack",
                %status,
                "slack webhook rejected request"
            );
            return Err(ChatError::Unauthorized);
        }

        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after_secs = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<u64>().ok());
            warn!(
                target: "sx_integrations::chat::slack",
                retry_after = ?retry_after_secs,
                "slack webhook rate limited"
            );
            return Err(ChatError::RateLimited { retry_after_secs });
        }

        Err(ChatError::Transport(format!(
            "slack webhook returned non-2xx status {status}"
        )))
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
    use crate::chat::ChatSeverity;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    fn alert() -> ChatAlert {
        ChatAlert::new(
            ChatSeverity::High,
            "Suspicious login from new geo",
            "Multiple failed MFA prompts in 30s",
        )
        .with_field("actor", "u-42")
        .with_field("ip", "10.0.0.7")
        .with_deep_link("https://sentinelx.example/f/abc")
    }

    fn notifier_for(server: &MockServer) -> SlackWebhookNotifier {
        let url = format!("{}/hooks/abc", server.uri());
        SlackWebhookNotifier::new(reqwest::Client::new(), SlackWebhookConfig::new(url)).unwrap()
    }

    #[test]
    fn build_payload_renders_header_summary_fields_and_button() {
        let payload = SlackWebhookNotifier::build_payload(&alert());
        // Outer envelope: one attachment with the severity color.
        let att = &payload["attachments"][0];
        assert_eq!(att["color"], "#DD8800");
        let blocks = att["blocks"].as_array().unwrap();
        // Header + summary + fields + actions = 4 blocks.
        assert_eq!(blocks.len(), 4);

        // Header block has SEVERITY + title in uppercase.
        let header_text = blocks[0]["text"]["text"].as_str().unwrap();
        assert!(header_text.contains("HIGH"), "{header_text}");
        assert!(header_text.contains("Suspicious login"));

        // Summary is the second block.
        let summary = blocks[1]["text"]["text"].as_str().unwrap();
        assert!(summary.contains("Multiple failed MFA"));

        // Fields block carries both kv pairs.
        let fields = blocks[2]["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 2);
        assert!(fields[0]["text"].as_str().unwrap().contains("actor"));
        assert!(fields[0]["text"].as_str().unwrap().contains("u-42"));

        // Actions block has the deep-link button.
        let actions = blocks[3]["elements"].as_array().unwrap();
        assert_eq!(actions[0]["url"], "https://sentinelx.example/f/abc");
    }

    #[test]
    fn build_payload_omits_summary_block_when_empty() {
        let alert = ChatAlert::new(ChatSeverity::Info, "Hello", "");
        let payload = SlackWebhookNotifier::build_payload(&alert);
        let blocks = payload["attachments"][0]["blocks"].as_array().unwrap();
        // Only the header block — no summary, no fields, no actions.
        assert_eq!(blocks.len(), 1);
    }

    #[test]
    fn build_payload_caps_fields_at_ten() {
        let mut alert = ChatAlert::new(ChatSeverity::Low, "T", "S");
        for i in 0..15 {
            alert = alert.with_field(format!("k{i}"), format!("v{i}"));
        }
        let payload = SlackWebhookNotifier::build_payload(&alert);
        let blocks = payload["attachments"][0]["blocks"].as_array().unwrap();
        // Header + summary + fields (capped) = 3.
        let fields = blocks[2]["fields"].as_array().unwrap();
        assert_eq!(fields.len(), SLACK_FIELDS_PER_BLOCK);
    }

    #[test]
    fn severity_color_maps_correctly_for_each_level() {
        for (sev, expected) in [
            (ChatSeverity::Critical, "#DD2222"),
            (ChatSeverity::High, "#DD8800"),
            (ChatSeverity::Medium, "#DDDD22"),
            (ChatSeverity::Low, "#2288DD"),
            (ChatSeverity::Info, "#888888"),
        ] {
            let alert = ChatAlert::new(sev, "t", "s");
            let payload = SlackWebhookNotifier::build_payload(&alert);
            assert_eq!(payload["attachments"][0]["color"], expected);
        }
    }

    #[tokio::test]
    async fn post_alert_hits_configured_webhook_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hooks/abc"))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let n = notifier_for(&server);
        n.post_alert(alert()).await.unwrap();
    }

    #[tokio::test]
    async fn post_alert_payload_carries_severity_color_and_fields() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hooks/abc"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let n = notifier_for(&server);
        n.post_alert(alert()).await.unwrap();

        let received: Vec<Request> = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        let body: Value = serde_json::from_slice(&received[0].body).unwrap();
        assert_eq!(body["attachments"][0]["color"], "#DD8800");
        let blocks = body["attachments"][0]["blocks"].as_array().unwrap();
        // Fields block is at index 2.
        let field_text = blocks[2]["fields"][0]["text"].as_str().unwrap();
        assert!(field_text.contains("actor"));
        assert!(field_text.contains("u-42"));
    }

    #[tokio::test]
    async fn post_alert_429_surfaces_as_rate_limited_with_retry_after() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hooks/abc"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "12"))
            .mount(&server)
            .await;

        let n = notifier_for(&server);
        let err = n.post_alert(alert()).await.unwrap_err();
        match err {
            ChatError::RateLimited { retry_after_secs } => {
                assert_eq!(retry_after_secs, Some(12));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn post_alert_404_maps_to_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hooks/abc"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let n = notifier_for(&server);
        let err = n.post_alert(alert()).await.unwrap_err();
        assert!(matches!(err, ChatError::Unauthorized));
    }

    #[tokio::test]
    async fn post_alert_500_maps_to_transport() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hooks/abc"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let n = notifier_for(&server);
        let err = n.post_alert(alert()).await.unwrap_err();
        assert!(matches!(err, ChatError::Transport(_)));
    }

    #[test]
    fn new_rejects_empty_or_malformed_webhook_url() {
        let err = SlackWebhookNotifier::new(reqwest::Client::new(), SlackWebhookConfig::new("   "))
            .unwrap_err();
        assert!(matches!(err, ChatError::InvalidConfig(_)));

        let err =
            SlackWebhookNotifier::new(reqwest::Client::new(), SlackWebhookConfig::new("not-a-url"))
                .unwrap_err();
        assert!(matches!(err, ChatError::InvalidConfig(_)));
    }

    #[test]
    fn debug_impl_redacts_webhook_url() {
        let secret = "https://hooks.slack.com/services/T0/B0/SUPER_SECRET_TOKEN_VALUE";
        let n = SlackWebhookNotifier::new(reqwest::Client::new(), SlackWebhookConfig::new(secret))
            .unwrap();
        let dbg = format!("{n:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(
            !dbg.contains("SUPER_SECRET_TOKEN_VALUE"),
            "webhook leaked in debug: {dbg}"
        );
        // The config struct's own Debug impl must also redact.
        let cfg_dbg = format!("{:?}", SlackWebhookConfig::new(secret));
        assert!(!cfg_dbg.contains("SUPER_SECRET_TOKEN_VALUE"));
    }
}
