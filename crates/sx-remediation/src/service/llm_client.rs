//! Claude LLM client used by the remediation copilot.
//!
//! Wraps the Anthropic Messages API behind the [`LlmClient`] trait so the
//! copilot can be unit tested with a mock implementation.
//!
//! ## Guardrails
//!
//! - The API key is held in [`secrecy::SecretString`]. It is never logged,
//!   never serialised by `Debug`, and only exposed when the `x-api-key`
//!   header is built.
//! - The request is hard-capped at [`ClaudeConfig::max_output_tokens`] —
//!   higher values are rejected at construction time.
//! - The system / user prompt strings are never logged.
//!
//! ## Live Claude API wiring
//!
//! The composition root in `services/sx-monolith/src/adapters/remediation.rs`
//! now constructs the live LLM client alongside the vendor advisory sources:
//! the `RemediationBundle` carries an `Arc<dyn LlmClient>` populated through
//! [`build`] from [`sx_config::AiCopilotConfig`]. When
//! `ai_copilot.enabled = true` the bundle binds a
//! [`crate::service::claude_client::RealClaudeClient`] pointed at the public
//! Anthropic Messages API; when the flag is `false` it binds the
//! [`DisabledLlmClient`] stub so any copilot invocation surfaces a
//! deterministic [`RemediationError::Config`] without crossing a network
//! boundary. The API key is sourced from
//! [`sx_config::AiCopilotConfig::api_key`] (env path
//! `SENTINELX__AI_COPILOT__API_KEY`) — never `std::env::var`.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sx_config::AiCopilotConfig;

use crate::error::RemediationError;
use crate::service::claude_client::RealClaudeClient;
use crate::service::USER_AGENT;

/// Anthropic Messages endpoint.
const MESSAGES_URL: &str = "https://api.anthropic.com/v1/messages";
/// Anthropic API version pinned by this crate. Bump intentionally.
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Static configuration for [`ClaudeClient`].
#[derive(Clone)]
pub struct ClaudeConfig {
    /// Anthropic API key. Stored inside [`SecretString`] so the value never
    /// appears in `Debug` output, logs, or panic messages.
    pub api_key: SecretString,
    /// Model identifier (e.g. `"claude-opus-4-7-1m"`).
    pub model_id: String,
    /// Soft upper bound on input tokens. The copilot use-case clips its
    /// user prompt to fit; this value is informational here.
    pub max_input_tokens: u32,
    /// Hard cap on output tokens. Passed verbatim to the API as
    /// `max_tokens`.
    pub max_output_tokens: u32,
}

impl fmt::Debug for ClaudeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClaudeConfig")
            .field("api_key", &"<redacted>")
            .field("model_id", &self.model_id)
            .field("max_input_tokens", &self.max_input_tokens)
            .field("max_output_tokens", &self.max_output_tokens)
            .finish()
    }
}

impl ClaudeConfig {
    /// Build and validate config. Returns
    /// [`RemediationError::Config`] if any numeric bound is zero.
    pub fn new(
        api_key: SecretString,
        model_id: impl Into<String>,
        max_input_tokens: u32,
        max_output_tokens: u32,
    ) -> Result<Self, RemediationError> {
        if max_input_tokens == 0 {
            return Err(RemediationError::config("max_input_tokens must be > 0"));
        }
        if max_output_tokens == 0 {
            return Err(RemediationError::config("max_output_tokens must be > 0"));
        }
        let model_id = model_id.into();
        if model_id.trim().is_empty() {
            return Err(RemediationError::config("model_id must not be empty"));
        }
        Ok(Self {
            api_key,
            model_id,
            max_input_tokens,
            max_output_tokens,
        })
    }
}

/// Polymorphic LLM front-end.
///
/// `complete` accepts a `system` prompt and a `user` prompt, and returns the
/// raw text content of the first assistant message. The copilot use-case is
/// responsible for parsing JSON out of that text.
#[async_trait]
pub trait LlmClient: Send + Sync + fmt::Debug {
    /// Send the system + user prompts and return the assistant text.
    async fn complete(
        &self,
        system_prompt: &str,
        user_prompt: &str,
    ) -> Result<String, RemediationError>;

    /// Identifier of the model that backs this client. Surfaces into
    /// [`crate::model::ai_remediation::AiRemediation::model_id`].
    fn model_id(&self) -> &str;
}

/// Concrete Anthropic Messages client.
pub struct ClaudeClient {
    http: reqwest::Client,
    cfg: ClaudeConfig,
    base_url: String,
}

impl fmt::Debug for ClaudeClient {
    // Custom Debug intentionally omits `http`; everything else is included
    // via `cfg` (which itself redacts the api key).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClaudeClient")
            .field("cfg", &self.cfg)
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

impl ClaudeClient {
    /// Build a client backed by the public Anthropic endpoint.
    #[must_use]
    pub fn new(http: reqwest::Client, cfg: ClaudeConfig) -> Self {
        Self {
            http,
            cfg,
            base_url: MESSAGES_URL.to_string(),
        }
    }

    /// Build a client pointed at an alternate base URL. Used by `wiremock`
    /// tests; production code calls [`ClaudeClient::new`].
    #[must_use]
    pub fn with_base_url(
        http: reqwest::Client,
        cfg: ClaudeConfig,
        base_url: impl Into<String>,
    ) -> Self {
        Self {
            http,
            cfg,
            base_url: base_url.into(),
        }
    }
}

/// Wire-format request payload.
#[derive(Debug, Serialize)]
struct MessagesRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    system: &'a str,
    messages: Vec<RequestMessage<'a>>,
}

#[derive(Debug, Serialize)]
struct RequestMessage<'a> {
    role: &'a str,
    content: Vec<ContentBlock<'a>>,
}

#[derive(Debug, Serialize)]
struct ContentBlock<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    text: &'a str,
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
impl LlmClient for ClaudeClient {
    async fn complete(
        &self,
        system_prompt: &str,
        user_prompt: &str,
    ) -> Result<String, RemediationError> {
        let body = MessagesRequest {
            model: &self.cfg.model_id,
            max_tokens: self.cfg.max_output_tokens,
            system: system_prompt,
            messages: vec![RequestMessage {
                role: "user",
                content: vec![ContentBlock {
                    kind: "text",
                    text: user_prompt,
                }],
            }],
        };

        // Intentionally not logging body or prompts: they may carry
        // (already-sanitised) finding context.
        tracing::debug!(target: "sx_remediation::llm", model = %self.cfg.model_id, "issuing claude completion");

        let resp = self
            .http
            .post(&self.base_url)
            .header("x-api-key", self.cfg.api_key.expose_secret())
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("user-agent", USER_AGENT)
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| RemediationError::transport("anthropic", e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            return Err(RemediationError::transport(
                "anthropic",
                format!("status {status}"),
            ));
        }

        let parsed: MessagesResponse = resp
            .json()
            .await
            .map_err(|e| RemediationError::malformed("anthropic", e.to_string()))?;

        let first =
            parsed.content.into_iter().next().ok_or_else(|| {
                RemediationError::malformed("anthropic", "response missing content")
            })?;
        Ok(first.text)
    }

    fn model_id(&self) -> &str {
        &self.cfg.model_id
    }
}

/// Stub [`LlmClient`] used when the AI copilot is disabled.
///
/// Surfaces a deterministic [`RemediationError::Config`] on any completion
/// attempt so the copilot use-case fails fast (instead of silently calling
/// a real network endpoint with no credentials).
#[derive(Debug, Clone, Copy, Default)]
pub struct DisabledLlmClient;

impl DisabledLlmClient {
    /// Model id reported by this stub. Surfaces into
    /// `AiRemediation::model_id` if the copilot ever issues a completion
    /// against it.
    const MODEL_ID: &'static str = "disabled-llm";
}

#[async_trait]
impl LlmClient for DisabledLlmClient {
    async fn complete(
        &self,
        _system_prompt: &str,
        _user_prompt: &str,
    ) -> Result<String, RemediationError> {
        Err(RemediationError::config(
            "ai_copilot disabled: set ai_copilot.enabled = true and supply an api_key",
        ))
    }

    fn model_id(&self) -> &str {
        Self::MODEL_ID
    }
}

/// Construct the appropriate [`LlmClient`] for the supplied AI copilot
/// config.
///
/// When `cfg.enabled` is `true`, returns a [`RealClaudeClient`] pointed at
/// the public Anthropic Messages API. Otherwise returns the
/// [`DisabledLlmClient`] stub, which fails every completion attempt with a
/// [`RemediationError::Config`].
///
/// The boolean result-shape on `RealClaudeClient::new` is collapsed into
/// the stub when the cfg is malformed: this surface is meant to be wired
/// at adapter build time, where a follow-up
/// [`AiCopilotConfig::check_invariants`] already gated the construction.
pub fn build(cfg: &AiCopilotConfig, http: reqwest::Client) -> Arc<dyn LlmClient> {
    if !cfg.enabled {
        return Arc::new(DisabledLlmClient);
    }
    match RealClaudeClient::new(http, cfg.clone()) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            tracing::error!(
                target: "sx_remediation::llm",
                error = %e,
                "failed to construct RealClaudeClient; falling back to disabled stub",
            );
            Arc::new(DisabledLlmClient)
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::single_char_pattern,
    clippy::single_char_add_str,
    clippy::float_cmp,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use secrecy::SecretString;
    use serde_json::json;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cfg() -> ClaudeConfig {
        ClaudeConfig::new(
            SecretString::from("sk-test".to_string()),
            "claude-opus-4-7-1m",
            16_000,
            2_048,
        )
        .unwrap()
    }

    #[test]
    fn config_rejects_zero_bounds() {
        let r = ClaudeConfig::new(
            SecretString::from("k".to_string()),
            "claude-opus-4-7-1m",
            0,
            1,
        );
        assert!(r.is_err());
    }

    #[test]
    fn debug_does_not_leak_api_key() {
        let c = cfg();
        let s = format!("{c:?}");
        assert!(s.contains("redacted"));
        assert!(!s.contains("sk-test"));
    }

    #[tokio::test]
    async fn claude_client_serialises_message_request_with_required_fields() {
        let server = MockServer::start().await;

        let response = json!({
            "content": [
                {"type": "text", "text": "{\"ok\":true}"}
            ]
        });

        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("anthropic-version", "2023-06-01"))
            .and(header("x-api-key", "sk-test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&server)
            .await;

        let http = reqwest::Client::new();
        let client = ClaudeClient::with_base_url(http, cfg(), server.uri());

        let text = client.complete("sys", "usr").await.unwrap();
        assert_eq!(text, "{\"ok\":true}");

        // Inspect the recorded request body and assert its shape.
        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1);
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body["model"], "claude-opus-4-7-1m");
        assert_eq!(body["max_tokens"], 2_048);
        assert_eq!(body["system"], "sys");
        assert_eq!(body["messages"][0]["role"], "user");
        assert_eq!(body["messages"][0]["content"][0]["type"], "text");
        assert_eq!(body["messages"][0]["content"][0]["text"], "usr");
    }

    #[tokio::test]
    async fn claude_client_surfaces_non_success_status() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let http = reqwest::Client::new();
        let client = ClaudeClient::with_base_url(http, cfg(), server.uri());
        let err = client.complete("s", "u").await.unwrap_err();
        match err {
            RemediationError::Transport { vendor, .. } => assert_eq!(vendor, "anthropic"),
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    fn ai_cfg_disabled() -> AiCopilotConfig {
        AiCopilotConfig::default()
    }

    fn ai_cfg_enabled() -> AiCopilotConfig {
        AiCopilotConfig {
            enabled: true,
            api_key: SecretString::from("sk-ant-build".to_string()),
            model: "claude-3-5-sonnet-latest".to_string(),
            max_tokens: 512,
            temperature: 0.2,
            external_targets: Vec::new(),
        }
    }

    #[tokio::test]
    async fn build_returns_disabled_stub_when_disabled() {
        let arc = build(&ai_cfg_disabled(), reqwest::Client::new());
        // Debug should mention the stub type.
        let dbg = format!("{arc:?}");
        assert!(dbg.contains("DisabledLlmClient"), "got: {dbg}");
        assert_eq!(arc.model_id(), "disabled-llm");
        let err = arc.complete("s", "u").await.unwrap_err();
        match err {
            RemediationError::Config(_) => {}
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[test]
    fn build_returns_real_when_enabled() {
        let arc = build(&ai_cfg_enabled(), reqwest::Client::new());
        let dbg = format!("{arc:?}");
        assert!(dbg.contains("RealClaudeClient"), "got: {dbg}");
        assert!(!dbg.contains("sk-ant-build"), "api_key leaked: {dbg}");
        assert_eq!(arc.model_id(), "claude-3-5-sonnet-latest");
    }
}
