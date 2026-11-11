//! Microsoft Teams Incoming Webhook notifier.
//!
//! Posts a Microsoft Teams **Adaptive Card** (schema 1.4) wrapped in an
//! `attachments` envelope (the shape Teams Incoming Webhooks accept).
//! The webhook URL is held in a [`SecretString`] because possession
//! grants the holder the ability to post to the bound channel.
//!
//! ## Payload shape
//!
//! The card has four parts:
//!
//! 1. **Header** `TextBlock` — bold, large, emoji-prefixed, color-coded
//!    via the Adaptive Card `color` token (`Attention`/`Warning`/...).
//! 2. **Summary** `TextBlock` — wrapped body text.
//! 3. **`FactSet`** — key/value rendering of the `fields` slice.
//! 4. **Actions** — single `Action.OpenUrl` button when `deep_link_url`
//!    is set.
//!
//! ### Why not `MessageCard` ("Office 365 connector card")?
//!
//! Microsoft has formally deprecated `MessageCard` (also known as
//! the "Office 365 connector card"). New integrations should use
//! Adaptive Cards via the Incoming Webhook connector with the
//! `attachments` wrapper, which is what we emit here.

use std::fmt;

use reqwest::{Client, StatusCode, Url};
use secrecy::{ExposeSecret, SecretString};
use serde_json::{json, Value};
use tracing::{debug, warn};

use crate::chat::{ChatAlert, ChatError, ChatNotifier, ChatSeverity};
use async_trait::async_trait;

/// Adaptive Card schema version we emit.
const ADAPTIVE_CARD_SCHEMA_VERSION: &str = "1.4";

/// Configuration for a Teams webhook notifier.
///
/// `webhook_url` is the full
/// `https://{tenant}.webhook.office.com/...` URL — sensitive, held as a
/// [`SecretString`], redacted from `Debug`.
pub struct TeamsWebhookConfig {
    /// Teams incoming webhook URL.
    pub webhook_url: SecretString,
}

impl fmt::Debug for TeamsWebhookConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TeamsWebhookConfig")
            .field("webhook_url", &"<redacted>")
            .finish()
    }
}

impl TeamsWebhookConfig {
    /// Construct a config from a raw URL string.
    #[must_use]
    pub fn new(webhook_url: impl Into<String>) -> Self {
        Self {
            webhook_url: SecretString::new(webhook_url.into().into_boxed_str()),
        }
    }
}

/// Teams incoming-webhook notifier emitting Adaptive Card payloads.
pub struct TeamsAdaptiveCardNotifier {
    http: Client,
    config: TeamsWebhookConfig,
}

impl fmt::Debug for TeamsAdaptiveCardNotifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TeamsAdaptiveCardNotifier")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl TeamsAdaptiveCardNotifier {
    /// Construct a notifier with a caller-supplied [`Client`].
    ///
    /// The webhook URL inside `config` is validated (non-empty, parses
    /// as a URL) and rejected with [`ChatError::InvalidConfig`] otherwise.
    pub fn new(http: Client, config: TeamsWebhookConfig) -> Result<Self, ChatError> {
        let raw = config.webhook_url.expose_secret();
        if raw.trim().is_empty() {
            return Err(ChatError::InvalidConfig(
                "teams webhook url is empty".to_owned(),
            ));
        }
        Url::parse(raw)
            .map_err(|e| ChatError::InvalidConfig(format!("teams webhook url invalid: {e}")))?;
        Ok(Self { http, config })
    }

    /// Map `SentinelX` severity onto an Adaptive Card text-color token.
    ///
    /// Adaptive Cards do not accept arbitrary hex colors on `TextBlock`s
    /// — they expose a small set of semantic tokens. We pick the one
    /// that best matches each severity. The exact `hex_color` value
    /// still lands in `themeColor` on the outer envelope so Teams
    /// renders the same color bar Slack does.
    const fn severity_text_color(sev: ChatSeverity) -> &'static str {
        match sev {
            ChatSeverity::Critical | ChatSeverity::High => "Attention",
            ChatSeverity::Medium => "Warning",
            ChatSeverity::Low => "Accent",
            ChatSeverity::Info => "Default",
        }
    }

    /// Build the Teams JSON payload for a given alert. Exposed for
    /// tests so we can assert on the wire shape without standing up
    /// wiremock.
    fn build_payload(alert: &ChatAlert) -> Value {
        let mut body: Vec<Value> = Vec::new();

        // Header TextBlock.
        let header_text = format!(
            "{emoji} {sev}: {title}",
            emoji = alert.severity.emoji(),
            sev = alert.severity.label().to_uppercase(),
            title = alert.title,
        );
        body.push(json!({
            "type": "TextBlock",
            "text": header_text,
            "weight": "Bolder",
            "size": "Large",
            "color": Self::severity_text_color(alert.severity),
            "wrap": true
        }));

        // Summary TextBlock.
        if !alert.summary.is_empty() {
            body.push(json!({
                "type": "TextBlock",
                "text": alert.summary,
                "wrap": true,
                "spacing": "Medium"
            }));
        }

        // FactSet for fields.
        if !alert.fields.is_empty() {
            let facts: Vec<Value> = alert
                .fields
                .iter()
                .map(|(k, v)| json!({ "title": k, "value": v }))
                .collect();
            body.push(json!({
                "type": "FactSet",
                "facts": facts
            }));
        }

        let mut card = json!({
            "type": "AdaptiveCard",
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "version": ADAPTIVE_CARD_SCHEMA_VERSION,
            "body": body
        });

        if let Some(url) = &alert.deep_link_url {
            if let Some(obj) = card.as_object_mut() {
                obj.insert(
                    "actions".to_owned(),
                    json!([{
                        "type": "Action.OpenUrl",
                        "title": "Open in SentinelX",
                        "url": url
                    }]),
                );
            }
        }

        // Outer envelope: Teams Incoming Webhooks accept the
        // `attachments` wrapper with `contentType` set to the Adaptive
        // Card MIME. `themeColor` on the envelope drives the color bar.
        json!({
            "type": "message",
            "themeColor": alert.severity.hex_color(),
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": null,
                "content": card
            }]
        })
    }
}

#[async_trait]
impl ChatNotifier for TeamsAdaptiveCardNotifier {
    fn provider(&self) -> &'static str {
        "teams"
    }

    async fn post_alert(&self, alert: ChatAlert) -> Result<(), ChatError> {
        let payload = Self::build_payload(&alert);

        debug!(
            target: "sx_integrations::chat::teams",
            severity = alert.severity.label(),
            field_count = alert.fields.len(),
            has_deep_link = alert.deep_link_url.is_some(),
            "posting alert to teams webhook"
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
                target: "sx_integrations::chat::teams",
                %status,
                "teams webhook rejected request"
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
                target: "sx_integrations::chat::teams",
                retry_after = ?retry_after_secs,
                "teams webhook rate limited"
            );
            return Err(ChatError::RateLimited { retry_after_secs });
        }

        Err(ChatError::Transport(format!(
            "teams webhook returned non-2xx status {status}"
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
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    fn alert() -> ChatAlert {
        ChatAlert::new(
            ChatSeverity::Critical,
            "Privilege escalation detected",
            "User u-42 gained admin via stale role binding",
        )
        .with_field("actor", "u-42")
        .with_field("role", "cluster-admin")
        .with_deep_link("https://sentinelx.example/f/xyz")
    }

    fn notifier_for(server: &MockServer) -> TeamsAdaptiveCardNotifier {
        let url = format!("{}/webhook/abc", server.uri());
        TeamsAdaptiveCardNotifier::new(reqwest::Client::new(), TeamsWebhookConfig::new(url))
            .unwrap()
    }

    #[test]
    fn build_payload_emits_adaptive_card_envelope() {
        let payload = TeamsAdaptiveCardNotifier::build_payload(&alert());
        assert_eq!(payload["type"], "message");
        assert_eq!(payload["themeColor"], "DD2222");

        let att = &payload["attachments"][0];
        assert_eq!(
            att["contentType"],
            "application/vnd.microsoft.card.adaptive"
        );

        let card = &att["content"];
        assert_eq!(card["type"], "AdaptiveCard");
        assert_eq!(card["version"], ADAPTIVE_CARD_SCHEMA_VERSION);

        let body = card["body"].as_array().unwrap();
        // Header + summary + factset = 3.
        assert_eq!(body.len(), 3);

        // Header carries CRITICAL + title and uses the Attention color.
        assert_eq!(body[0]["color"], "Attention");
        let header_text = body[0]["text"].as_str().unwrap();
        assert!(header_text.contains("CRITICAL"));
        assert!(header_text.contains("Privilege escalation"));

        // FactSet carries both key/value pairs.
        let facts = body[2]["facts"].as_array().unwrap();
        assert_eq!(facts.len(), 2);
        assert_eq!(facts[0]["title"], "actor");
        assert_eq!(facts[0]["value"], "u-42");

        // Actions: OpenUrl on the deep link.
        let actions = card["actions"].as_array().unwrap();
        assert_eq!(actions[0]["type"], "Action.OpenUrl");
        assert_eq!(actions[0]["url"], "https://sentinelx.example/f/xyz");
    }

    #[test]
    fn build_payload_theme_color_matches_severity_table() {
        for (sev, expected) in [
            (ChatSeverity::Critical, "DD2222"),
            (ChatSeverity::High, "DD8800"),
            (ChatSeverity::Medium, "DDDD22"),
            (ChatSeverity::Low, "2288DD"),
            (ChatSeverity::Info, "888888"),
        ] {
            let alert = ChatAlert::new(sev, "t", "s");
            let payload = TeamsAdaptiveCardNotifier::build_payload(&alert);
            assert_eq!(payload["themeColor"], expected, "sev={sev:?}");
        }
    }

    #[test]
    fn build_payload_omits_summary_and_factset_when_empty() {
        let alert = ChatAlert::new(ChatSeverity::Info, "Hi", "");
        let payload = TeamsAdaptiveCardNotifier::build_payload(&alert);
        let body = payload["attachments"][0]["content"]["body"]
            .as_array()
            .unwrap();
        assert_eq!(body.len(), 1);
        // No `actions` key when no deep link.
        assert!(payload["attachments"][0]["content"]
            .get("actions")
            .is_none());
    }

    #[tokio::test]
    async fn post_alert_hits_configured_webhook_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webhook/abc"))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let n = notifier_for(&server);
        n.post_alert(alert()).await.unwrap();
    }

    #[tokio::test]
    async fn post_alert_payload_carries_fields_in_factset() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webhook/abc"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let n = notifier_for(&server);
        n.post_alert(alert()).await.unwrap();

        let received: Vec<Request> = server.received_requests().await.unwrap();
        assert_eq!(received.len(), 1);
        let body: Value = serde_json::from_slice(&received[0].body).unwrap();
        let card_body = body["attachments"][0]["content"]["body"]
            .as_array()
            .unwrap();
        let facts = card_body[2]["facts"].as_array().unwrap();
        assert_eq!(facts[0]["title"], "actor");
        assert_eq!(facts[1]["title"], "role");
    }

    #[tokio::test]
    async fn post_alert_429_surfaces_as_rate_limited() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webhook/abc"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "7"))
            .mount(&server)
            .await;

        let n = notifier_for(&server);
        let err = n.post_alert(alert()).await.unwrap_err();
        match err {
            ChatError::RateLimited { retry_after_secs } => {
                assert_eq!(retry_after_secs, Some(7));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn post_alert_403_maps_to_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webhook/abc"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let n = notifier_for(&server);
        let err = n.post_alert(alert()).await.unwrap_err();
        assert!(matches!(err, ChatError::Unauthorized));
    }

    #[tokio::test]
    async fn post_alert_503_maps_to_transport() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/webhook/abc"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let n = notifier_for(&server);
        let err = n.post_alert(alert()).await.unwrap_err();
        assert!(matches!(err, ChatError::Transport(_)));
    }

    #[test]
    fn debug_impl_redacts_webhook_url() {
        let secret = "https://tenant.webhook.office.com/webhookb2/SUPER_SECRET_TEAMS_TOKEN";
        let n =
            TeamsAdaptiveCardNotifier::new(reqwest::Client::new(), TeamsWebhookConfig::new(secret))
                .unwrap();
        let dbg = format!("{n:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(
            !dbg.contains("SUPER_SECRET_TEAMS_TOKEN"),
            "webhook leaked: {dbg}"
        );
        let cfg_dbg = format!("{:?}", TeamsWebhookConfig::new(secret));
        assert!(!cfg_dbg.contains("SUPER_SECRET_TEAMS_TOKEN"));
    }
}
