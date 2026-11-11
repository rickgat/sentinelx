//! AI Copilot (Anthropic Claude) configuration.
//!
//! Configures the remediation crate's [`crate`] real Claude client. Ships
//! disabled by default — a freshly cloned checkout never reaches
//! `api.anthropic.com`. When an operator flips `enabled: true`, the
//! `api_key`, `model`, `max_tokens`, and `temperature` become mandatory and
//! `sx-remediation` constructs a `RealClaudeClient` pointed at
//! `https://api.anthropic.com/v1/messages`.
//!
//! The `api_key` is wrapped in [`secrecy::SecretString`] so it never
//! appears in `Debug` output and its backing memory is zeroed on drop. The
//! sx-remediation `RealClaudeClient` is the only consumer that ever
//! `expose_secret()`s it, and only at the moment the `x-api-key` header is
//! written into a `reqwest` request.

use secrecy::SecretString;
use serde::Deserialize;
use validator::Validate;

/// Default Anthropic model identifier.
fn default_ai_copilot_model() -> String {
    "claude-3-5-sonnet-latest".to_string()
}

/// Default cap on output tokens passed verbatim to the Messages API as
/// `max_tokens`.
const fn default_ai_copilot_max_tokens() -> u32 {
    1024
}

/// Default sampling temperature. Low temperature (0.2) keeps remediation
/// copilot output close to deterministic.
const fn default_ai_copilot_temperature() -> f32 {
    0.2
}

/// Default HTTP header an external target's auth token is sent in.
fn default_external_auth_header() -> String {
    "authorization".to_string()
}

/// Default scheme prefix prepended to the auth token (e.g. `Bearer <token>`).
fn default_external_auth_scheme() -> String {
    "Bearer ".to_string()
}

/// A config-registered external LLM endpoint the AI red-team harness may
/// probe (AI-SEC-002).
///
/// Secrets are referenced **by name**, never inlined: `auth_env` names an
/// environment variable holding the token, so the key is absent from the
/// config file, the API surface, and logs.
///
/// Probing an entry is gated by engagement authorization (the target's host
/// must be in an Active, in-window, approved engagement scope) — registration
/// alone grants no authority to attack the endpoint.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalLlmTarget {
    /// Stable id referenced by `POST /v1/ai-audit/run-external`.
    pub id: String,
    /// Full endpoint URL the probe prompt is sent to (HTTP POST). Its host
    /// is the scope target checked against the engagement.
    pub url: String,
    /// Name of the environment variable holding the auth token. When unset
    /// or the variable is absent, the request is sent without auth.
    #[serde(default)]
    pub auth_env: Option<String>,
    /// Header the token is written into (default `authorization`).
    #[serde(default = "default_external_auth_header")]
    pub auth_header: String,
    /// Prefix prepended to the token in the header (default `Bearer `).
    #[serde(default = "default_external_auth_scheme")]
    pub auth_scheme: String,
    /// Model identifier. When set and `request_template` is omitted, an
    /// OpenAI-compatible `/v1/chat/completions` body is derived from it so
    /// operators need not hand-write the JSON template.
    #[serde(default)]
    pub model: Option<String>,
    /// JSON request-body template. The literal `{PROMPT}` is replaced with
    /// the JSON-escaped probe string (quotes included) before sending.
    /// Optional: when omitted, derived from `model` (`OpenAI` chat shape).
    #[serde(default)]
    pub request_template: Option<String>,
    /// RFC-6901 JSON pointer to the completion text in the response body.
    /// Optional: defaults to the `OpenAI` pointer `/choices/0/message/content`.
    #[serde(default)]
    pub response_pointer: Option<String>,
}

impl ExternalLlmTarget {
    /// `OpenAI` chat/completions response pointer used when none is set.
    pub const OPENAI_RESPONSE_POINTER: &'static str = "/choices/0/message/content";

    /// Resolve the request-body template: an explicit `request_template`
    /// wins; otherwise an OpenAI-compatible chat/completions body is
    /// derived from `model`.
    ///
    /// # Errors
    ///
    /// Returns an error string when neither `request_template` nor a
    /// non-empty `model` is configured.
    pub fn resolved_request_template(&self) -> Result<String, String> {
        if let Some(t) = &self.request_template {
            return Ok(t.clone());
        }
        let model = self
            .model
            .as_deref()
            .filter(|m| !m.trim().is_empty())
            .ok_or_else(|| {
                format!(
                    "external LLM target '{}' needs either request_template or model",
                    self.id
                )
            })?;
        Ok(format!(
            r#"{{"model":"{model}","messages":[{{"role":"user","content":{{PROMPT}}}}]}}"#
        ))
    }

    /// Resolve the response pointer (explicit, else the `OpenAI` default).
    #[must_use]
    pub fn resolved_response_pointer(&self) -> String {
        self.response_pointer
            .clone()
            .unwrap_or_else(|| Self::OPENAI_RESPONSE_POINTER.to_owned())
    }
}

/// AI Copilot configuration.
///
/// Disabled by default. When `enabled: true`:
///   * `api_key` MUST be non-empty.
///   * `model` MUST be non-empty (defaulted to
///     `claude-3-5-sonnet-latest` when not supplied).
///   * `max_tokens` MUST be `> 0`.
///   * `temperature` MUST be a finite value in `[0.0, 1.0]`.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct AiCopilotConfig {
    /// Whether the `RealClaudeClient` should be constructed. When `false`,
    /// `sx_remediation::service::llm_client::build` returns a disabled stub
    /// that surfaces a deterministic error on any completion attempt.
    pub enabled: bool,

    /// Anthropic API key. Mandatory iff `enabled`.
    ///
    /// Wrapped in [`SecretString`] so the value never appears in `Debug`
    /// output, panic messages, or `tracing` logs. The remediation crate
    /// only exposes it inside a `reqwest` `x-api-key` header at the moment
    /// the request is sent.
    #[serde(default)]
    pub api_key: SecretString,

    /// Model identifier (e.g. `"claude-3-5-sonnet-latest"`,
    /// `"claude-opus-4-7-1m"`). Defaults to `"claude-3-5-sonnet-latest"`.
    #[serde(default = "default_ai_copilot_model")]
    pub model: String,

    /// Hard cap on output tokens. Passed verbatim to the Messages API as
    /// `max_tokens`. Defaults to `1024`.
    #[serde(default = "default_ai_copilot_max_tokens")]
    pub max_tokens: u32,

    /// Sampling temperature in `[0.0, 1.0]`. Defaults to `0.2` so the
    /// remediation copilot's output is close to deterministic.
    #[serde(default = "default_ai_copilot_temperature")]
    pub temperature: f32,

    /// External LLM endpoints the red-team harness may probe (AI-SEC-002).
    /// Empty by default; each entry references its auth token by env-var
    /// name. Probing is still gated by engagement authorization.
    #[serde(default)]
    pub external_targets: Vec<ExternalLlmTarget>,
}

impl Default for AiCopilotConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_key: SecretString::from(String::new()),
            model: default_ai_copilot_model(),
            max_tokens: default_ai_copilot_max_tokens(),
            temperature: default_ai_copilot_temperature(),
            external_targets: Vec::new(),
        }
    }
}

impl AiCopilotConfig {
    /// Cross-field invariants. Disabled configs always pass; enabled
    /// configs must supply a non-empty `api_key` + non-empty `model` +
    /// `max_tokens > 0` + finite `temperature in [0.0, 1.0]`.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        // External probe targets are validated regardless of `enabled`
        // (the red-team harness probes them independently of the copilot):
        // each must resolve a request template, i.e. supply one explicitly
        // or a non-empty model to derive the OpenAI shape from.
        for target in &self.external_targets {
            if let Err(msg) = target.resolved_request_template() {
                return Err(crate::ConfigError::invalid(
                    "ai_copilot.external_targets",
                    msg,
                ));
            }
        }
        if !self.enabled {
            return Ok(());
        }
        if crate::secret::is_empty(&self.api_key) {
            return Err(crate::ConfigError::missing("ai_copilot.api_key"));
        }
        if self.model.trim().is_empty() {
            return Err(crate::ConfigError::missing("ai_copilot.model"));
        }
        if self.max_tokens == 0 {
            return Err(crate::ConfigError::invalid(
                "ai_copilot.max_tokens",
                "must be > 0",
            ));
        }
        if !self.temperature.is_finite() {
            return Err(crate::ConfigError::invalid(
                "ai_copilot.temperature",
                "must be a finite number",
            ));
        }
        if self.temperature < 0.0 || self.temperature > 1.0 {
            return Err(crate::ConfigError::invalid(
                "ai_copilot.temperature",
                "must be in [0.0, 1.0]",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::AiCopilotConfig;
    use crate::secret;

    fn enabled_baseline() -> AiCopilotConfig {
        AiCopilotConfig {
            enabled: true,
            api_key: secret::wrap("sk-ant-test"),
            model: "claude-3-5-sonnet-latest".to_string(),
            max_tokens: 1024,
            temperature: 0.2,
            external_targets: Vec::new(),
        }
    }

    #[test]
    fn disabled_default_passes() {
        let cfg = AiCopilotConfig::default();
        cfg.check_invariants()
            .expect("disabled default config must pass invariants");
    }

    #[test]
    fn enabled_baseline_passes() {
        enabled_baseline()
            .check_invariants()
            .expect("complete enabled baseline must pass");
    }

    #[test]
    fn enabled_without_api_key_returns_missing() {
        let mut cfg = enabled_baseline();
        cfg.api_key = secret::wrap("");
        let err = cfg
            .check_invariants()
            .expect_err("missing api_key must surface");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "ai_copilot.api_key");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn enabled_without_model_returns_missing() {
        let mut cfg = enabled_baseline();
        cfg.model = "   ".to_string();
        let err = cfg
            .check_invariants()
            .expect_err("blank model must surface");
        match err {
            crate::ConfigError::MissingValue { key } => {
                assert_eq!(key, "ai_copilot.model");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn enabled_with_zero_max_tokens_returns_invalid() {
        let mut cfg = enabled_baseline();
        cfg.max_tokens = 0;
        let err = cfg
            .check_invariants()
            .expect_err("zero max_tokens must surface");
        match err {
            crate::ConfigError::InvalidValue { key, .. } => {
                assert_eq!(key, "ai_copilot.max_tokens");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn enabled_with_out_of_range_temperature_returns_invalid() {
        let mut cfg = enabled_baseline();
        cfg.temperature = 1.5;
        let err = cfg
            .check_invariants()
            .expect_err("out-of-range temperature must surface");
        match err {
            crate::ConfigError::InvalidValue { key, .. } => {
                assert_eq!(key, "ai_copilot.temperature");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn enabled_with_nan_temperature_returns_invalid() {
        let mut cfg = enabled_baseline();
        cfg.temperature = f32::NAN;
        let err = cfg
            .check_invariants()
            .expect_err("NaN temperature must surface");
        match err {
            crate::ConfigError::InvalidValue { key, .. } => {
                assert_eq!(key, "ai_copilot.temperature");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn debug_does_not_leak_api_key() {
        let cfg = enabled_baseline();
        let dbg = format!("{cfg:?}");
        assert!(
            !dbg.contains("sk-ant-test"),
            "api_key leaked in Debug: {dbg}"
        );
    }

    #[test]
    fn defaults_match_documented_values() {
        let cfg = AiCopilotConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.model, "claude-3-5-sonnet-latest");
        assert_eq!(cfg.max_tokens, 1024);
        assert!((cfg.temperature - 0.2_f32).abs() < f32::EPSILON);
    }
}
