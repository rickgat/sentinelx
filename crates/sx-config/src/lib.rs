//! # sx-config
//!
//! Configuration layer for every `SentinelX` service.
//!
//! ## Layering
//!
//! Configuration is loaded from, lowest precedence first:
//!
//! 1. An optional YAML file whose path comes from the `SENTINELX_CONFIG`
//!    environment variable (or is supplied explicitly to [`load_from`]).
//! 2. Environment variables prefixed `SENTINELX__`. The double underscore
//!    separates nested fields, so `SENTINELX__DATABASE__URL` populates
//!    `settings.database.url`.
//!
//! ## No hardcoded defaults
//!
//! This crate **never** falls back to "sensible defaults". A missing
//! required value is a [`ConfigError::MissingValue`] and `SentinelX` will
//! refuse to start. This is by design — silent defaults are how production
//! incidents start.
//!
//! ## Secrets
//!
//! Any field that carries a credential is wrapped in
//! [`secrecy::SecretString`] which redacts itself in `Debug` output and
//! zeros its backing memory on drop. Errors are also scrubbed before they
//! reach a `tracing::error!` call site.
//!
//! ## Example
//!
//! ```no_run
//! use sx_config::{load, Settings};
//!
//! let settings: Settings = load().expect("config error at boot is fatal");
//! println!("server bind: {}", settings.server.bind_addr);
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod error;
pub mod loader;
pub mod schema;
pub mod secret;

pub use crate::error::ConfigError;
pub use crate::loader::{load, load_from, CONFIG_PATH_ENV, ENV_NESTED_SEPARATOR, ENV_PREFIX};
pub use crate::schema::{
    default_tsa_endpoints, AiCopilotConfig, AntiAbuseConfig, Argon2Params, AwsConfig, AzureConfig,
    AzureKekConfig, CloudConfig, CompositeWeights, DatabaseConfig, DenylistEntry, DenylistKind,
    DiscoveryConfig, EffectiveRiskConfig, EngagementConfig, ExternalLlmTarget, GcpConfig,
    GithubConfig, GraphConfig, IamConfig, IntegrationsConfig, IntelFeedsConfig, Intensity,
    JiraAuthKind, JiraIntegrationConfig, JwtAlgorithm, JwtConfig, KekConfig, KekProviderKind,
    LockoutPolicy, LogFormat, LogLevel, MtlsConfig, OidcConfig, PagerDutyIntegrationConfig,
    RedisConfig, RiskConfig, RiskThresholdsConfig, RiskWeightsConfig, SamlConfig, SecretsConfig,
    ServerConfig, Settings, TelemetryConfig, TenantRiskOverride, TenantTsaConfig,
    TsaEndpointConfig, TsaFallbackConfig, DEV_PLACEHOLDER_CA_PEM, WEIGHTS_SUM_MAX, WEIGHTS_SUM_MIN,
};
