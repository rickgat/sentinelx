//! Strongly-typed configuration schema for `SentinelX`.
//!
//! Every sub-module owns one logical section of the global [`Settings`]
//! struct. Sub-configs are kept small and self-contained so they can be
//! validated and tested in isolation.

pub mod ai_copilot;
pub mod anti_abuse;
pub mod audit;
pub mod bootstrap;
pub mod cloud;
pub mod collab;
pub mod database;
pub mod discovery;
pub mod engagement;
pub mod github;
pub mod graph;
pub mod iam;
pub mod integrations;
pub mod intel_feeds;
pub mod jwt;
pub mod log_ingest;
pub mod mtls;
pub mod oidc;
pub mod rba;
pub mod redis;
pub mod release_channel;
pub mod risk;
pub mod risk_weights;
pub mod saml;
pub mod secrets;
pub mod server;
pub mod telemetry;
pub mod tenant_risk;
pub mod tsa;
pub mod webhooks;

use serde::Deserialize;
use validator::Validate;

pub use self::ai_copilot::{AiCopilotConfig, ExternalLlmTarget};
pub use self::anti_abuse::AntiAbuseConfig;
pub use self::audit::AuditConfig;
pub use self::bootstrap::BootstrapConfig;
pub use self::cloud::{AwsConfig, AzureConfig, CloudConfig, GcpConfig};
pub use self::collab::CollabConfig;
pub use self::database::DatabaseConfig;
pub use self::discovery::DiscoveryConfig;
pub use self::engagement::{DenylistEntry, DenylistKind, EngagementConfig, Intensity};
pub use self::github::GithubConfig;
pub use self::graph::GraphConfig;
pub use self::iam::{Argon2Params, IamConfig, LockoutPolicy};
pub use self::integrations::{
    IntegrationsConfig, JiraAuthKind, JiraIntegrationConfig, PagerDutyIntegrationConfig,
};
pub use self::intel_feeds::IntelFeedsConfig;
pub use self::jwt::{JwtAlgorithm, JwtConfig};
pub use self::log_ingest::{LogIngestRateLimitConfig, TierRateConfig};
pub use self::mtls::MtlsConfig;
pub use self::oidc::OidcConfig;
pub use self::rba::{RbaFindingEmissionConfig, RbaSettings};
pub use self::redis::RedisConfig;
pub use self::release_channel::{ReleaseChannelConfig, DEFAULT_ORGANIZATION};
pub use self::risk::{CompositeWeights, RiskConfig};
pub use self::risk_weights::{RiskWeightsConfig, WEIGHTS_SUM_MAX, WEIGHTS_SUM_MIN};
pub use self::saml::{SamlConfig, XmlDsigConfig, XmlDsigVerifierKind};
pub use self::secrets::{AzureKekConfig, KekConfig, KekProviderKind, SecretsConfig};
pub use self::server::{RateLimitConfig, ServerConfig};
pub use self::telemetry::{LogFormat, LogLevel, TelemetryConfig};
pub use self::tenant_risk::{EffectiveRiskConfig, RiskThresholdsConfig, TenantRiskOverride};
pub use self::tsa::{
    default_endpoints as default_tsa_endpoints, TenantTsaConfig, TsaEndpointConfig,
    TsaFallbackConfig, DEV_PLACEHOLDER_CA_PEM,
};
pub use self::webhooks::{TenantWebhookRotationOverride, WebhookSigningRotationConfig};

/// Root configuration object. Built by the loader and consumed by every
/// `SentinelX` service.
///
/// All sub-fields are required. The struct deliberately does **not**
/// implement `Default` — there are no hardcoded defaults anywhere in this
/// crate.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// HTTP server settings.
    #[validate(nested)]
    pub server: ServerConfig,

    /// `PostgreSQL` settings.
    #[validate(nested)]
    pub database: DatabaseConfig,

    /// Redis settings.
    #[validate(nested)]
    pub redis: RedisConfig,

    /// JWT signing settings.
    #[validate(nested)]
    pub jwt: JwtConfig,

    /// Telemetry pipeline settings.
    #[validate(nested)]
    pub telemetry: TelemetryConfig,

    /// Risk scoring settings.
    #[validate(nested)]
    pub risk: RiskConfig,

    /// Engagement / scan settings.
    #[validate(nested)]
    pub engagement: EngagementConfig,

    /// IAM / auth settings.
    #[validate(nested)]
    pub iam: IamConfig,

    /// Discovery probe settings.
    #[validate(nested)]
    pub discovery: DiscoveryConfig,

    /// Bootstrap settings (admin seed at first boot).
    #[validate(nested)]
    pub bootstrap: BootstrapConfig,

    /// Collaborator (OOB receivers) settings.
    #[validate(nested)]
    pub collab: CollabConfig,

    /// Cloud-provider credentials (AWS / GCP / Azure).
    #[validate(nested)]
    pub cloud: CloudConfig,

    /// GitHub credentials for the autonomy auto-remediation PR adapter.
    #[validate(nested)]
    pub github: GithubConfig,

    /// OIDC verifier settings — when enabled, the `/v1/auth/oidc/exchange`
    /// endpoint is wired up to verify `id_token`s against the `IdP`'s JWKS
    /// and issue SX-internal tokens for the underlying user.
    #[serde(default)]
    #[validate(nested)]
    pub oidc: OidcConfig,

    /// Mutual TLS settings for inter-service listeners. Disabled by
    /// default — when an operator flips `enabled: true`, the `sx-mtls`
    /// crate builds a `rustls::ServerConfig` from the configured PEM
    /// chain + key + (optional) client CA bundle and hot-reloads it on
    /// disk changes.
    #[serde(default)]
    #[validate(nested)]
    pub mtls: MtlsConfig,

    /// Anti-abuse detector thresholds. Disabled by default — when an
    /// operator flips `enabled: true`, the router builder wraps the
    /// authenticated subrouter with the `AntiAbuseLayer` middleware from
    /// `sx-api`, which emits structured audit events on JWT replay,
    /// per-IP rate anomalies and user-agent rotation.
    #[serde(default)]
    #[validate(nested)]
    pub anti_abuse: AntiAbuseConfig,

    /// AI Copilot (Anthropic Claude) settings — disabled by default. When
    /// an operator flips `enabled: true`, the `sx-remediation` crate
    /// constructs a `RealClaudeClient` pointed at
    /// `https://api.anthropic.com/v1/messages` and the remediation copilot
    /// use-case starts issuing live completions.
    #[serde(default)]
    #[validate(nested)]
    pub ai_copilot: AiCopilotConfig,

    /// Threat-intelligence feed (TAXII) ingestion settings — disabled by
    /// default. When an operator flips `enabled: true`, the monolith
    /// spawns a background tokio task that polls the configured TAXII
    /// collection on `poll_interval_secs`. The full network adapter is
    /// deferred; the current build only logs the deferred status so the
    /// schema can be exercised end-to-end without external dependencies.
    #[serde(default)]
    #[validate(nested)]
    pub intel_feeds: IntelFeedsConfig,

    /// Knowledge-graph (Neo4j) settings — disabled by default. When an
    /// operator flips `neo4j_enabled: true`, the monolith composition
    /// root connects to the configured Bolt URI and registers the
    /// `Neo4jKnowledgeGraph` adapter as the production
    /// `GraphAttackPathsPort`. Otherwise the in-memory stub adapter
    /// stays in place.
    #[serde(default)]
    #[validate(nested)]
    pub graph: GraphConfig,

    /// Secrets / envelope-encryption settings — disabled by default.
    /// When `secrets.kek.provider = "azure_kv"`, the composition root
    /// constructs an `AzureKeyVaultKekProvider` (P1-007) from the
    /// configured vault URL, key name and AAD service-principal.
    #[serde(default)]
    #[validate(nested)]
    pub secrets: SecretsConfig,

    /// SAML 2.0 Service Provider settings (P0-004) — disabled by default.
    /// When `saml.enabled = true`, the API exposes `GET
    /// /v1/auth/saml/metadata`, `POST /v1/auth/saml/acs` and `GET
    /// /v1/auth/saml/logout`, and the composition root mounts the
    /// production `SamlSpAdapter` against the per-tenant `IdP` table.
    #[serde(default)]
    #[validate(nested)]
    pub saml: SamlConfig,

    /// TSA fallback + circuit-breaker settings (CRIT-006). Disabled by
    /// default; when `tsa.enabled = true` the monolith wires the
    /// `sx-audit::tsa_fallback::ResilientAnchorRunner` against the
    /// per-tenant primary + backup TSAs and starts the queued-retry
    /// scheduler tick.
    #[serde(default)]
    #[validate(nested)]
    pub tsa: TsaFallbackConfig,

    /// Per-tenant log-ingest rate-limiter settings (MED-001). Seeds the
    /// runtime [`sx_log_ingest::rate_limit::RateLimiter`] at composition
    /// time. Defaults to the `SentinelX` canonical tier rates (free 100/s,
    /// pro 1k/s, enterprise 10k/s) so omitting the section keeps the
    /// noisy-neighbour protection on with sane numbers.
    #[serde(default)]
    #[validate(nested)]
    pub log_ingest_rate_limit: LogIngestRateLimitConfig,

    /// Outbound webhook signing-key rotation settings (MED-003). When
    /// `enabled=true` the composition root spawns a background rotator
    /// that scans the per-tenant signing-key store and mints a new
    /// `kid` whenever the active key has aged past
    /// `cadence_days`. The previous key remains valid for the
    /// `grace_days` handover window.
    #[serde(default)]
    #[validate(nested)]
    pub webhook_signing_rotation: WebhookSigningRotationConfig,

    /// Risk-Based Authentication global config (TOP5-#3-P2-005). Today
    /// only `rba.finding_emission` is meaningful; when enabled the RBA
    /// adapter surfaces high-risk Block decisions as synthetic Findings.
    /// Disabled by default — fresh checkouts emit zero findings until
    /// an operator opts in.
    #[serde(default)]
    #[validate(nested)]
    pub rba: RbaSettings,

    /// Audit-pipeline operator settings (TOP5-#3-P2-007). Disabled
    /// section defaults are safe: when `system_engagement_id` is unset
    /// the at-boundary audit-break observer derives a deterministic
    /// per-tenant UUID instead of failing the emission path.
    #[serde(default)]
    #[validate(nested)]
    pub audit: AuditConfig,

    /// Outbound ticketing + alerting integrations (TOP5-#5). Disabled by
    /// default — see [`IntegrationsConfig`] for the per-vendor schema.
    /// When a vendor flips `enabled: true`, the monolith composition root
    /// constructs the matching `sx-integrations` adapter and registers it
    /// with the incident-sink fan-out so `Critical` findings, SOC
    /// playbook triggers, and audit-chain breaks generate vendor-side
    /// records.
    #[serde(default)]
    #[validate(nested)]
    pub integrations: IntegrationsConfig,

    /// Release-channel / SARIF `tool.driver` metadata (TOP5-#3 Phase 3).
    /// Populates `runs[].tool.driver.organization` (default `"SentinelX"`)
    /// and — when the operator wires a stable URL —
    /// `runs[].tool.driver.downloadUri` on every emitted SARIF envelope.
    /// Omitting the section keeps the safe posture (organization =
    /// `SentinelX`, downloadUri omitted).
    #[serde(default)]
    #[validate(nested)]
    pub release_channel: ReleaseChannelConfig,
}

impl Settings {
    /// Cross-cutting invariants that cannot be expressed via `#[validate]`
    /// attributes. Called by the loader after `validate()` succeeds.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        self.server.check_invariants()?;
        self.database.check_invariants()?;
        self.redis.check_invariants()?;
        self.jwt.check_invariants()?;
        self.telemetry.check_invariants()?;
        self.risk.check_invariants()?;
        self.engagement.check_invariants()?;
        self.iam.check_invariants()?;
        self.discovery.check_invariants()?;
        self.bootstrap.check_invariants()?;
        self.collab.check_invariants()?;
        self.cloud.check_invariants()?;
        self.github.check_invariants()?;
        self.oidc.check_invariants()?;
        self.mtls.check_invariants()?;
        self.anti_abuse.check_invariants()?;
        self.ai_copilot.check_invariants()?;
        self.intel_feeds.check_invariants()?;
        self.graph.check_invariants()?;
        self.secrets.check_invariants()?;
        self.saml.check_invariants()?;
        self.tsa.check_invariants()?;
        self.log_ingest_rate_limit.check_invariants()?;
        self.webhook_signing_rotation.check_invariants()?;
        self.rba.check_invariants()?;
        self.audit.check_invariants()?;
        self.integrations.check_invariants()?;
        self.release_channel.check_invariants()?;
        self.assert_production_safe()?;
        Ok(())
    }

    /// `true` when `telemetry.environment` names a production deployment.
    #[must_use]
    pub fn is_production(&self) -> bool {
        matches!(
            self.telemetry
                .environment
                .trim()
                .to_ascii_lowercase()
                .as_str(),
            "prod" | "production"
        )
    }

    /// SELL-P0-06: refuse to boot a production deployment configured with
    /// development-only, unsafe values. This fails closed at config-load time
    /// so a misconfigured production instance never starts, rather than
    /// silently running with a known-weak key or seeded admin. Non-production
    /// environments (`dev`, `staging`, …) are unaffected.
    fn assert_production_safe(&self) -> Result<(), crate::ConfigError> {
        // Known development / placeholder JWT signing keys that ship in the
        // repo's example configs and must never reach production.
        const DEV_SIGNING_KEYS: &[&str] = &[
            "DEV_ONLY_HS256_SIGNING_KEY_REPLACE_FOR_ANY_REAL_DEPLOYMENT__",
            // base64("MDEw…") decodes to "01" repeated 32 times (local-dev-pg).
            "0101010101010101010101010101010101010101010101010101010101010101",
        ];
        if !self.is_production() {
            return Ok(());
        }
        let key = crate::secret::expose_str(&self.jwt.signing_key);
        if key.starts_with("DEV_ONLY") || DEV_SIGNING_KEYS.contains(&key) {
            return Err(crate::ConfigError::invalid(
                "jwt.signing_key",
                "development/placeholder JWT signing key must not be used in a production environment",
            ));
        }
        if self.jwt.key_id.trim() == "kid-dev" {
            return Err(crate::ConfigError::invalid(
                "jwt.key_id",
                "development key id 'kid-dev' must not be used in production",
            ));
        }
        if !self.database.enabled {
            return Err(crate::ConfigError::invalid(
                "database.enabled",
                "production requires a persistent database; in-memory mode is development-only",
            ));
        }
        if self.bootstrap.enabled {
            return Err(crate::ConfigError::invalid(
                "bootstrap.enabled",
                "bootstrap admin seeding must be disabled in production",
            ));
        }
        Ok(())
    }
}
