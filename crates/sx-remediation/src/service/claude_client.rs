//! Real Anthropic Claude API client.
//!
//! Implements [`super::llm_client::LlmClient`] against the Messages API at
//! `https://api.anthropic.com/v1/messages`. Configured by
//! [`sx_config::AiCopilotConfig`].
//!
//! ## Guardrails
//!
//! * The API key is held inside a [`secrecy::SecretString`] (carried in the
//!   `AiCopilotConfig` value) and only `expose_secret`-ed at the moment the
//!   `x-api-key` header is written. It NEVER appears in `Debug` output,
//!   panic messages, or `tracing` events.
//! * The prompt body is NEVER logged. The crate emits one structured event
//!   per call carrying only `model` + `outcome` + `duration_ms` + (on
//!   error) the discriminated outcome variant.
//! * HTTP status codes are mapped onto strongly-typed
//!   [`RemediationError`] variants — `429 → RateLimited`,
//!   `401 → Unauthorized`, anything else non-2xx → `Transport`.
//!
//! ## Construction
//!
//! Production wire-up flows through
//! [`super::llm_client::build`], which inspects `cfg.enabled` and either
//! constructs a `RealClaudeClient` or returns the existing disabled stub.
//! Direct construction via [`RealClaudeClient::new`] /
//! [`RealClaudeClient::with_base_url`] is only used by `wiremock` tests.

use std::fmt;
use std::time::Instant;

use async_trait::async_trait;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use sx_config::AiCopilotConfig;
use url::Url;

use crate::error::RemediationError;
use crate::service::llm_client::LlmClient;
use crate::service::USER_AGENT;

/// Anthropic API version this crate pins. Bump intentionally.
pub(crate) const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Default public Messages endpoint base URL.
///
/// Wiremock tests supply an alternate base URL via
/// [`RealClaudeClient::with_base_url`]; production callers stick with the
/// default.
const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";

/// Vendor tag carried inside [`RemediationError`] variants emitted by this
/// client.
const VENDOR: &str = "anthropic";

/// Real Anthropic Claude API client.
///
/// Implements [`LlmClient`]. Constructed indirectly via
/// [`super::llm_client::build`]; direct constructors exist for `wiremock`
/// tests only.
pub struct RealClaudeClient {
    http: reqwest::Client,
    base_url: Url,
    cfg: AiCopilotConfig,
}

impl fmt::Debug for RealClaudeClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `AiCopilotConfig`'s own Debug already redacts the api_key via
        // `secrecy::SecretString`. Emit it through that pathway and never
        // touch the underlying string.
        f.debug_struct("RealClaudeClient")
            .field("base_url", &self.base_url.as_str())
            .field("model", &self.cfg.model)
            .field("max_tokens", &self.cfg.max_tokens)
            .field("temperature", &self.cfg.temperature)
            .field("api_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl RealClaudeClient {
    /// Build a client against the public Anthropic endpoint.
    ///
    /// Returns [`RemediationError::Config`] when the supplied
    /// [`AiCopilotConfig`] is disabled — the only legitimate path to a
    /// `RealClaudeClient` is through [`super::llm_client::build`] with an
    /// enabled config.
    pub fn new(http: reqwest::Client, cfg: AiCopilotConfig) -> Result<Self, RemediationError> {
        Self::with_base_url_str(http, cfg, DEFAULT_BASE_URL)
    }

    /// Build a client against an alternate base URL. Used by `wiremock`
    /// tests; production code calls [`RealClaudeClient::new`].
    pub fn with_base_url(
        http: reqwest::Client,
        cfg: AiCopilotConfig,
        base_url: Url,
    ) -> Result<Self, RemediationError> {
        Self::validate_cfg(&cfg)?;
        Ok(Self {
            http,
            base_url,
            cfg,
        })
    }

    fn with_base_url_str(
        http: reqwest::Client,
        cfg: AiCopilotConfig,
        base_url: &str,
    ) -> Result<Self, RemediationError> {
        let parsed = Url::parse(base_url)
            .map_err(|e| RemediationError::config(format!("ai_copilot.base_url: {e}")))?;
        Self::with_base_url(http, cfg, parsed)
    }

    fn validate_cfg(cfg: &AiCopilotConfig) -> Result<(), RemediationError> {
        if !cfg.enabled {
            return Err(RemediationError::config(
                "ai_copilot.enabled must be true to construct RealClaudeClient",
            ));
        }
        if cfg.api_key.expose_secret().is_empty() {
            return Err(RemediationError::config(
                "ai_copilot.api_key must be non-empty",
            ));
        }
        if cfg.model.trim().is_empty() {
            return Err(RemediationError::config(
                "ai_copilot.model must be non-empty",
            ));
        }
        if cfg.max_tokens == 0 {
            return Err(RemediationError::config(
                "ai_copilot.max_tokens must be > 0",
            ));
        }
        Ok(())
    }

    fn messages_url(&self) -> Result<Url, RemediationError> {
        self.base_url
            .join("/v1/messages")
            .map_err(|e| RemediationError::UrlBuild(e.to_string()))
    }
}

/// Returns `Instant::elapsed().as_millis()` saturated into a `u64` for
/// `tracing` field emission. A 584-million-year overflow window is more
/// than enough for any remediation call.
fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Wire-format request payload.
#[derive(Debug, Serialize)]
struct MessagesRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    messages: Vec<RequestMessage<'a>>,
    temperature: f32,
}

#[derive(Debug, Serialize)]
struct RequestMessage<'a> {
    role: &'a str,
    content: &'a str,
}

/// Wire-format response payload.
#[derive(Debug, Deserialize)]
struct MessagesResponse {
    content: Vec<ResponseBlock>,
}

#[derive(Debug, Deserialize)]
struct ResponseBlock {
    #[serde(default, rename = "type")]
    _kind: String,
    #[serde(default)]
    text: String,
}

#[async_trait]
impl LlmClient for RealClaudeClient {
    async fn complete(
        &self,
        system_prompt: &str,
        user_prompt: &str,
    ) -> Result<String, RemediationError> {
        let started = Instant::now();
        let url = self.messages_url()?;

        // Compose the user message. The trait predates the v1/messages
        // `system` top-level field, so when callers supply a non-empty
        // system prompt we prepend it inline; an empty system_prompt
        // keeps the original prompt untouched.
        let combined: String;
        let content: &str = if system_prompt.is_empty() {
            user_prompt
        } else {
            combined = format!("{system_prompt}\n\n{user_prompt}");
            &combined
        };

        let body = MessagesRequest {
            model: &self.cfg.model,
            max_tokens: self.cfg.max_tokens,
            messages: vec![RequestMessage {
                role: "user",
                content,
            }],
            temperature: self.cfg.temperature,
        };

        // Intentionally not logging the body / prompts: they may carry
        // (already-sanitised) finding context. Log only the model id.
        tracing::debug!(
            target: "sx_remediation::llm",
            model = %self.cfg.model,
            "issuing claude completion",
        );

        let resp = self
            .http
            .post(url)
            .header("x-api-key", self.cfg.api_key.expose_secret())
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("user-agent", USER_AGENT)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(
                    target: "sx_remediation::llm",
                    model = %self.cfg.model,
                    outcome = "transport",
                    duration_ms = elapsed_ms(started),
                    "claude completion failed",
                );
                RemediationError::transport(VENDOR, e.to_string())
            })?;

        let status = resp.status();
        if !status.is_success() {
            let outcome: &str = match status.as_u16() {
                429 => "rate_limited",
                401 | 403 => "unauthorized",
                _ => "transport",
            };
            tracing::warn!(
                target: "sx_remediation::llm",
                model = %self.cfg.model,
                outcome,
                status = status.as_u16(),
                duration_ms = elapsed_ms(started),
                "claude completion non-success status",
            );
            return Err(match status.as_u16() {
                429 => RemediationError::RateLimited(VENDOR),
                401 | 403 => RemediationError::Unauthorized(VENDOR),
                _ => RemediationError::transport(VENDOR, format!("status {status}")),
            });
        }

        let parsed: MessagesResponse = resp.json().await.map_err(|e| {
            tracing::warn!(
                target: "sx_remediation::llm",
                model = %self.cfg.model,
                outcome = "malformed",
                duration_ms = elapsed_ms(started),
                "claude completion malformed body",
            );
            RemediationError::malformed(VENDOR, e.to_string())
        })?;

        let first = parsed.content.into_iter().next().ok_or_else(|| {
            tracing::warn!(
                target: "sx_remediation::llm",
                model = %self.cfg.model,
                outcome = "malformed",
                duration_ms = elapsed_ms(started),
                "claude response missing content",
            );
            RemediationError::malformed(VENDOR, "response missing content")
        })?;

        tracing::debug!(
            target: "sx_remediation::llm",
            model = %self.cfg.model,
            outcome = "ok",
            duration_ms = elapsed_ms(started),
            "claude completion ok",
        );
        Ok(first.text)
    }

    fn model_id(&self) -> &str {
        &self.cfg.model
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::{RealClaudeClient, ANTHROPIC_VERSION, DEFAULT_BASE_URL, VENDOR};
    use crate::error::RemediationError;
    use crate::service::llm_client::LlmClient;
    use secrecy::SecretString;
    use serde_json::json;
    use sx_config::AiCopilotConfig;
    use url::Url;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn enabled_cfg() -> AiCopilotConfig {
        AiCopilotConfig {
            enabled: true,
            api_key: SecretString::from("sk-ant-test".to_string()),
            model: "claude-3-5-sonnet-latest".to_string(),
            max_tokens: 256,
            temperature: 0.2,
            external_targets: Vec::new(),
        }
    }

    fn server_base(server: &MockServer) -> Url {
        Url::parse(&server.uri()).unwrap()
    }

    #[tokio::test]
    async fn real_client_returns_text_on_200() {
        let server = MockServer::start().await;
        let response = json!({
            "content": [
                {"type": "text", "text": "remediation suggestion body"}
            ]
        });
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(header("anthropic-version", ANTHROPIC_VERSION))
            .and(header("x-api-key", "sk-ant-test"))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&server)
            .await;

        let client = RealClaudeClient::with_base_url(
            reqwest::Client::new(),
            enabled_cfg(),
            server_base(&server),
        )
        .unwrap();

        let text = client.complete("", "describe CVE-2024-1234").await.unwrap();
        assert_eq!(text, "remediation suggestion body");

        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body["model"], "claude-3-5-sonnet-latest");
        assert_eq!(body["max_tokens"], 256);
        assert_eq!(body["temperature"], 0.2);
        assert_eq!(body["messages"][0]["role"], "user");
        assert_eq!(body["messages"][0]["content"], "describe CVE-2024-1234");
    }

    #[tokio::test]
    async fn real_client_429_maps_to_rate_limited() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;
        let client = RealClaudeClient::with_base_url(
            reqwest::Client::new(),
            enabled_cfg(),
            server_base(&server),
        )
        .unwrap();
        let err = client.complete("", "u").await.unwrap_err();
        match err {
            RemediationError::RateLimited(v) => assert_eq!(v, VENDOR),
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn real_client_401_maps_to_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let client = RealClaudeClient::with_base_url(
            reqwest::Client::new(),
            enabled_cfg(),
            server_base(&server),
        )
        .unwrap();
        let err = client.complete("", "u").await.unwrap_err();
        match err {
            RemediationError::Unauthorized(v) => assert_eq!(v, VENDOR),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn real_client_500_maps_to_transport() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let client = RealClaudeClient::with_base_url(
            reqwest::Client::new(),
            enabled_cfg(),
            server_base(&server),
        )
        .unwrap();
        let err = client.complete("", "u").await.unwrap_err();
        match err {
            RemediationError::Transport { vendor, .. } => assert_eq!(vendor, VENDOR),
            other => panic!("expected Transport, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn real_client_malformed_json_maps_to_malformed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json at all"))
            .mount(&server)
            .await;
        let client = RealClaudeClient::with_base_url(
            reqwest::Client::new(),
            enabled_cfg(),
            server_base(&server),
        )
        .unwrap();
        let err = client.complete("", "u").await.unwrap_err();
        match err {
            RemediationError::Malformed { vendor, .. } => assert_eq!(vendor, VENDOR),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn real_client_sends_required_headers() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .and(header("anthropic-version", ANTHROPIC_VERSION))
            .and(header("x-api-key", "sk-ant-test"))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "content": [{"type": "text", "text": "ok"}]
            })))
            .mount(&server)
            .await;

        let client = RealClaudeClient::with_base_url(
            reqwest::Client::new(),
            enabled_cfg(),
            server_base(&server),
        )
        .unwrap();
        client.complete("", "u").await.unwrap();
    }

    #[test]
    fn debug_redacts_api_key() {
        let cfg = enabled_cfg();
        let client = RealClaudeClient::with_base_url(
            reqwest::Client::new(),
            cfg,
            Url::parse("https://example.invalid").unwrap(),
        )
        .unwrap();
        let dbg = format!("{client:?}");
        assert!(
            !dbg.contains("sk-ant-test"),
            "api_key leaked in Debug: {dbg}"
        );
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn new_rejects_disabled_config() {
        let mut cfg = enabled_cfg();
        cfg.enabled = false;
        let r = RealClaudeClient::new(reqwest::Client::new(), cfg);
        match r {
            Err(RemediationError::Config(_)) => {}
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[test]
    fn new_rejects_empty_api_key() {
        let mut cfg = enabled_cfg();
        cfg.api_key = SecretString::from(String::new());
        let r = RealClaudeClient::new(reqwest::Client::new(), cfg);
        match r {
            Err(RemediationError::Config(_)) => {}
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[test]
    fn new_against_default_base_url_parses() {
        // Smoke-test the default base URL constant — must stay parseable.
        let cfg = enabled_cfg();
        let client = RealClaudeClient::new(reqwest::Client::new(), cfg).unwrap();
        // The constructed URL string must match the documented default.
        assert!(format!("{client:?}").contains(DEFAULT_BASE_URL));
    }

    #[test]
    fn model_id_returns_configured_model() {
        let cfg = enabled_cfg();
        let client = RealClaudeClient::with_base_url(
            reqwest::Client::new(),
            cfg,
            Url::parse("https://example.invalid").unwrap(),
        )
        .unwrap();
        assert_eq!(client.model_id(), "claude-3-5-sonnet-latest");
    }
}
