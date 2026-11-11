#![allow(dead_code)] // Phase-3.5: many fields are reserved for the next-turn wire-up.
//! Remediation adapter.
//!
//! Builds the `sx-remediation` composition-root bundle. Registers all
//! four vendor advisory sources (MSRC, Red Hat, Ubuntu, Cisco) behind the
//! [`MultiSourceAdvisoryRegistry`]. Each source shares the monolith's
//! shared `reqwest::Client` via the crate's `with_client` constructors so
//! connection pools stay warm.
//!
//! ## AI Remediation Copilot wiring
//!
//! The bundle now also carries the [`LlmClient`] used by the AI remediation
//! use-case. When `ai_copilot.enabled = true` the bundle constructs a live
//! [`RealClaudeClient`] pointed at the public Anthropic Messages API; the
//! API key is sourced from
//! [`sx_config::AiCopilotConfig::api_key`][`AiCopilotConfig`] (loaded via
//! the workspace env prefix `SENTINELX__AI_COPILOT__API_KEY`). When the
//! flag is `false` the bundle binds the [`DisabledLlmClient`] stub so any
//! downstream copilot invocation fails fast with a deterministic
//! `RemediationError::Config`. Construction routes through
//! [`sx_remediation::service::llm_client::build`] which collapses an
//! enabled-but-malformed config into the stub and logs the rejection.

use std::sync::Arc;

use sx_config::AiCopilotConfig;
use sx_remediation::service::cisco::CiscoSource;
use sx_remediation::service::llm_client::{self, LlmClient};
use sx_remediation::service::msrc::MsrcSource;
use sx_remediation::service::redhat::RedHatSource;
use sx_remediation::service::registry::MultiSourceAdvisoryRegistry;
use sx_remediation::service::source::VendorAdvisorySource;
use sx_remediation::service::ubuntu::UbuntuSource;
use tracing::info;

/// Bundle returned by [`build`].
pub(crate) struct RemediationBundle {
    /// Fan-out registry across the four vendor sources.
    pub registry: Arc<MultiSourceAdvisoryRegistry>,
    /// LLM client used by the AI remediation copilot use-case. Live
    /// [`sx_remediation::service::claude_client::RealClaudeClient`] when
    /// `ai_copilot.enabled = true`; otherwise the disabled stub.
    pub llm: Arc<dyn LlmClient>,
}

/// Build the remediation bundle.
///
/// `http` is the shared HTTP client. Every vendor source is built with
/// `with_client(http.clone())` so they all share the same connection
/// pool. Cisco is registered without a bearer token (`None`); operators
/// supply the token through the Phase-3.5 config wire.
///
/// `ai_cfg` is consumed to build the [`LlmClient`] member of the returned
/// bundle. The bundle never inspects the API key directly — that secret
/// flows in through [`AiCopilotConfig`], wrapped in [`secrecy::SecretString`],
/// and is only exposed inside the `x-api-key` header at request time.
#[allow(dead_code)] // parent composition root wires this in
pub(crate) fn build(http: reqwest::Client, ai_cfg: &AiCopilotConfig) -> RemediationBundle {
    let sources: Vec<Arc<dyn VendorAdvisorySource>> = vec![
        Arc::new(MsrcSource::with_client(http.clone())),
        Arc::new(RedHatSource::with_client(http.clone())),
        Arc::new(UbuntuSource::with_client(http.clone())),
        Arc::new(CiscoSource::with_client(http.clone(), None)),
    ];
    let registry = Arc::new(MultiSourceAdvisoryRegistry::new(sources));

    // Compose the LLM client. `llm_client::build` is the single seam that
    // chooses between the live `RealClaudeClient` (when `cfg.enabled`) and
    // the `DisabledLlmClient` stub. It internally validates the
    // `AiCopilotConfig` and falls back to the stub if `RealClaudeClient`
    // construction rejects the values — production deployments never reach
    // that branch because `AiCopilotConfig::check_invariants` runs first at
    // `sx_config::load` time.
    let llm = llm_client::build(ai_cfg, http);

    info!(
        target = "adapters.remediation.built",
        sources = 4,
        vendors = "msrc,redhat,ubuntu,cisco",
        ai_copilot_enabled = ai_cfg.enabled,
        ai_copilot_model = %llm.model_id(),
        "remediation bundle constructed",
    );

    RemediationBundle { registry, llm }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::{build, AiCopilotConfig};
    use secrecy::SecretString;

    fn disabled_cfg() -> AiCopilotConfig {
        AiCopilotConfig::default()
    }

    fn enabled_cfg() -> AiCopilotConfig {
        AiCopilotConfig {
            enabled: true,
            api_key: SecretString::from("sk-ant-remediation-build".to_string()),
            model: "claude-3-5-sonnet-latest".to_string(),
            max_tokens: 256,
            temperature: 0.2,
            external_targets: Vec::new(),
        }
    }

    #[test]
    fn build_with_disabled_copilot_binds_stub_llm() {
        let bundle = build(reqwest::Client::new(), &disabled_cfg());
        assert_eq!(bundle.llm.model_id(), "disabled-llm");
    }

    #[test]
    fn build_with_enabled_copilot_wires_real_claude_client() {
        let bundle = build(reqwest::Client::new(), &enabled_cfg());
        // The live client surfaces the configured model id; the stub
        // would surface "disabled-llm".
        assert_eq!(bundle.llm.model_id(), "claude-3-5-sonnet-latest");
        // Sanity: the api key must never leak through Debug.
        let dbg = format!("{:?}", bundle.llm);
        assert!(
            !dbg.contains("sk-ant-remediation-build"),
            "api_key leaked through bundle Debug: {dbg}",
        );
    }
}
