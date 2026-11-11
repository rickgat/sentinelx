//! Configuration loader.
//!
//! Configuration is layered, lowest-precedence first:
//!
//! 1. Optional YAML file (path from `SENTINELX_CONFIG` env var or supplied
//!    explicitly).
//! 2. Environment variables prefixed `SENTINELX__`, with `__` separating
//!    nested keys (e.g. `SENTINELX__DATABASE__URL=...`).
//!
//! Later sources override earlier ones. After deserialization the result is
//! run through `validator` field validation **and** the manual
//! `check_invariants` cross-field checks. Either step's failure becomes a
//! [`ConfigError`].

use std::path::{Path, PathBuf};

use figment::providers::{Env, Format, Yaml};
use figment::Figment;
use validator::Validate;

use crate::error::ConfigError;
use crate::schema::Settings;

/// Name of the environment variable that, when set, points at the YAML
/// configuration file.
pub const CONFIG_PATH_ENV: &str = "SENTINELX_CONFIG";

/// Prefix expected on all `SentinelX` environment variables.
pub const ENV_PREFIX: &str = "SENTINELX__";

/// Separator used inside env-var names to denote nested keys.
pub const ENV_NESTED_SEPARATOR: &str = "__";

/// Loads settings using the default discovery rules:
///
/// * If `SENTINELX_CONFIG` is set, treat its value as a path to a YAML file.
/// * Then merge in environment variables prefixed `SENTINELX__`.
pub fn load() -> Result<Settings, ConfigError> {
    let path = resolve_path_from_env();
    load_from(path.as_deref())
}

/// Loads settings, optionally seeding from the YAML file at `path`.
///
/// Environment variables prefixed `SENTINELX__` always override file values.
pub fn load_from(path: Option<&Path>) -> Result<Settings, ConfigError> {
    let mut figment = Figment::new();
    let mut sources: Vec<String> = Vec::new();

    if let Some(p) = path {
        if !p.exists() {
            return Err(ConfigError::Io(format!(
                "config file does not exist: {}",
                p.display()
            )));
        }
        figment = figment.merge(Yaml::file(p));
        sources.push(format!("yaml:{}", p.display()));
    }

    // We don't pull from std::env directly — figment's Env provider walks
    // std::env::vars under the hood. The `disallowed_methods` clippy lint
    // covers our own modules, not third-party crates.
    let env_provider = Env::prefixed(ENV_PREFIX).split(ENV_NESTED_SEPARATOR);
    figment = figment.merge(env_provider);
    sources.push(format!("env:{ENV_PREFIX}*"));

    tracing::info!(
        target: "sx_config",
        sources = ?sources,
        "loaded configuration"
    );

    let settings: Settings = figment.extract()?;

    // Field-level validation.
    settings.validate()?;
    // Cross-field invariants (URL schemes, weight sums, etc.).
    settings.check_invariants()?;

    Ok(settings)
}

/// Reads the `SENTINELX_CONFIG` env var and returns its value as a
/// [`PathBuf`], or `None` if unset or empty.
fn resolve_path_from_env() -> Option<PathBuf> {
    // Use the OS env API at one well-justified location. The clippy
    // `disallowed_methods` ban applies to general application code; this is
    // the single sanctioned read in the config crate.
    #[allow(clippy::disallowed_methods)]
    let raw = std::env::var(CONFIG_PATH_ENV).ok()?;
    if raw.is_empty() {
        None
    } else {
        Some(PathBuf::from(raw))
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use figment::Jail;
    use secrecy::ExposeSecret;

    use super::*;
    use crate::schema::{Intensity, JwtAlgorithm, LogFormat, LogLevel};

    /// Sets the full set of required env vars on `jail`. Tests can mutate
    /// individual entries afterwards.
    #[allow(clippy::too_many_lines)]
    fn set_full_env(jail: &mut Jail) {
        // server
        jail.set_env("SENTINELX__SERVER__BIND_ADDR", "127.0.0.1:8080");
        jail.set_env("SENTINELX__SERVER__SHUTDOWN_TIMEOUT", 30);
        jail.set_env("SENTINELX__SERVER__REQUEST_TIMEOUT", 15);
        jail.set_env("SENTINELX__SERVER__MAX_BODY_BYTES", 1_048_576);
        jail.set_env("SENTINELX__SERVER__RATE_LIMIT__LIMIT_PER_MINUTE", 600);
        jail.set_env("SENTINELX__SERVER__RATE_LIMIT__BURST", 60);
        jail.set_env("SENTINELX__SERVER__RATE_LIMIT__ENABLED", true);

        // database
        jail.set_env(
            "SENTINELX__DATABASE__URL",
            "postgres://user:pw@db.example.com:5432/sentinelx",
        );
        jail.set_env("SENTINELX__DATABASE__MAX_CONNECTIONS", 20);
        jail.set_env("SENTINELX__DATABASE__MIN_CONNECTIONS", 2);
        jail.set_env("SENTINELX__DATABASE__ACQUIRE_TIMEOUT", 5);
        jail.set_env("SENTINELX__DATABASE__IDLE_TIMEOUT", 300);
        jail.set_env("SENTINELX__DATABASE__STATEMENT_TIMEOUT_MS", 30000);
        jail.set_env("SENTINELX__DATABASE__MIGRATE_ON_START", true);
        jail.set_env("SENTINELX__DATABASE__ENABLED", false);

        // redis
        jail.set_env(
            "SENTINELX__REDIS__URL",
            "redis://:pw@cache.example.com:6379/0",
        );
        jail.set_env("SENTINELX__REDIS__POOL_SIZE", 10);
        jail.set_env("SENTINELX__REDIS__COMMAND_TIMEOUT", 2);
        jail.set_env("SENTINELX__REDIS__ENABLED", false);

        // jwt
        jail.set_env("SENTINELX__JWT__ISSUER", "sentinelx");
        jail.set_env("SENTINELX__JWT__AUDIENCE", "sentinelx-clients");
        jail.set_env(
            "SENTINELX__JWT__SIGNING_KEY",
            "this-is-a-very-long-hmac-secret-key-32b",
        );
        jail.set_env("SENTINELX__JWT__KEY_ID", "k1");
        jail.set_env("SENTINELX__JWT__ACCESS_TTL", 900);
        jail.set_env("SENTINELX__JWT__REFRESH_TTL", 86400);
        jail.set_env("SENTINELX__JWT__ALGORITHM", "HS256");
        jail.set_env("SENTINELX__JWT__LEEWAY_SECONDS", 30);

        // telemetry
        jail.set_env("SENTINELX__TELEMETRY__SERVICE_NAME", "sx-monolith");
        jail.set_env("SENTINELX__TELEMETRY__ENVIRONMENT", "test");
        jail.set_env("SENTINELX__TELEMETRY__LOG_LEVEL", "info");
        jail.set_env("SENTINELX__TELEMETRY__LOG_FORMAT", "json");
        jail.set_env("SENTINELX__TELEMETRY__SAMPLE_RATIO", 0.25);

        // risk
        jail.set_env("SENTINELX__RISK__WEIGHTS__W_SEVERITY", 0.3);
        jail.set_env("SENTINELX__RISK__WEIGHTS__W_EXPLOIT", 0.2);
        jail.set_env("SENTINELX__RISK__WEIGHTS__W_EXPOSURE", 0.15);
        jail.set_env("SENTINELX__RISK__WEIGHTS__W_CRITICALITY", 0.15);
        jail.set_env("SENTINELX__RISK__WEIGHTS__W_BUSINESS_IMPACT", 0.1);
        jail.set_env("SENTINELX__RISK__WEIGHTS__W_CHAIN", 0.1);
        jail.set_env("SENTINELX__RISK__KEV_BOOST_FACTOR", 1.5);
        jail.set_env("SENTINELX__RISK__EPSS_THRESHOLD_ACT", 0.7);

        // engagement
        jail.set_env("SENTINELX__ENGAGEMENT__MAX_CONCURRENT", 4);
        jail.set_env("SENTINELX__ENGAGEMENT__DEFAULT_INTENSITY", "normal");
        jail.set_env(
            "SENTINELX__ENGAGEMENT__KILL_SWITCH_CHANNEL",
            "sentinelx.killswitch",
        );
        jail.set_env("SENTINELX__ENGAGEMENT__KILLSWITCH_WATCHDOG_INTERVAL", 5);
        jail.set_env("SENTINELX__ENGAGEMENT__GLOBAL_DENYLIST", "[]");

        // iam
        jail.set_env("SENTINELX__IAM__PASSWORD__M_COST", 19456);
        jail.set_env("SENTINELX__IAM__PASSWORD__T_COST", 2);
        jail.set_env("SENTINELX__IAM__PASSWORD__P_COST", 1);
        jail.set_env("SENTINELX__IAM__PASSWORD__OUTPUT_LEN", 32);
        jail.set_env("SENTINELX__IAM__PASSWORD__SALT_LEN", 16);
        jail.set_env("SENTINELX__IAM__SESSION_INACTIVITY_TIMEOUT", 1800);
        jail.set_env("SENTINELX__IAM__MFA_REQUIRED", true);
        jail.set_env("SENTINELX__IAM__LOCKOUT__THRESHOLD", 5);
        jail.set_env("SENTINELX__IAM__LOCKOUT__WINDOW", 600);
        jail.set_env("SENTINELX__IAM__LOCKOUT__DURATION", 900);
        jail.set_env(
            "SENTINELX__IAM__ATTEMPT_EMAIL_PEPPER",
            "test-pepper-must-be-at-least-16b",
        );

        // bootstrap
        jail.set_env("SENTINELX__BOOTSTRAP__ENABLED", false);
        jail.set_env("SENTINELX__BOOTSTRAP__ADMIN_TENANT_SLUG", "default");
        jail.set_env("SENTINELX__BOOTSTRAP__ADMIN_TENANT_NAME", "Default Tenant");
        jail.set_env("SENTINELX__BOOTSTRAP__ADMIN_EMAIL", "admin@example.com");
        jail.set_env(
            "SENTINELX__BOOTSTRAP__ADMIN_PASSWORD_PHC",
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$abcdefghijklmnopqrstuvwxyz123456",
        );

        // discovery
        jail.set_env(
            "SENTINELX__DISCOVERY__DNS_RESOLVERS",
            r#"["1.1.1.1:53","8.8.8.8:53"]"#,
        );
        jail.set_env("SENTINELX__DISCOVERY__MAX_CONCURRENT_PROBES", 64);
        jail.set_env("SENTINELX__DISCOVERY__PER_TARGET_RPS_LIMIT", 10);
        jail.set_env("SENTINELX__DISCOVERY__HTTP_USER_AGENT", "SentinelX/0.1");
        jail.set_env("SENTINELX__DISCOVERY__HTTP_TIMEOUT", 10);
        jail.set_env("SENTINELX__DISCOVERY__PORT_SCAN_MAX_PORTS", 1024);

        // collab
        jail.set_env("SENTINELX__COLLAB__ENABLED", false);
        jail.set_env("SENTINELX__COLLAB__BASE_DOMAIN", "oob.sentinelx.invalid");
        jail.set_env("SENTINELX__COLLAB__DNS_BIND", "127.0.0.1:5353");
        jail.set_env("SENTINELX__COLLAB__HTTP_BIND", "127.0.0.1:9080");
        jail.set_env("SENTINELX__COLLAB__ANSWER_IPV4", "127.0.0.1");
        jail.set_env("SENTINELX__COLLAB__CALLBACK_TTL", 259_200);
        jail.set_env("SENTINELX__COLLAB__HTTP_BODY_CAPTURE_BYTES", 4096);
        jail.set_env("SENTINELX__COLLAB__SMTP_MAX_MESSAGE_BYTES", 65_536);

        // cloud
        jail.set_env("SENTINELX__CLOUD__AWS__ENABLED", "false");
        jail.set_env("SENTINELX__CLOUD__GCP__ENABLED", "false");
        jail.set_env("SENTINELX__CLOUD__AZURE__ENABLED", "false");

        // github
        jail.set_env("SENTINELX__GITHUB__ENABLED", "false");

        // mtls (disabled by default; sx-mtls only consumes these when enabled)
        jail.set_env("SENTINELX__MTLS__ENABLED", false);

        // anti_abuse (disabled by default; thresholds match middleware
        // defaults so a freshly seeded env produces the same behavior as
        // `AntiAbuseConfig::default()` in sx-api).
        jail.set_env("SENTINELX__ANTI_ABUSE__ENABLED", false);
        jail.set_env("SENTINELX__ANTI_ABUSE__REPLAY_WINDOW_SECS", 300);
        jail.set_env("SENTINELX__ANTI_ABUSE__RATE_WINDOW_SECS", 60);
        jail.set_env("SENTINELX__ANTI_ABUSE__RATE_ANOMALY_MULTIPLIER", 3.0);
        jail.set_env("SENTINELX__ANTI_ABUSE__RATE_MIN_SAMPLES", 4);
        jail.set_env("SENTINELX__ANTI_ABUSE__AGENT_WINDOW_SECS", 600);
        jail.set_env("SENTINELX__ANTI_ABUSE__AGENT_THRESHOLD", 5);

        // ai_copilot (disabled by default; remediation crate switches in a
        // `RealClaudeClient` against api.anthropic.com only when enabled).
        jail.set_env("SENTINELX__AI_COPILOT__ENABLED", false);
        jail.set_env("SENTINELX__AI_COPILOT__API_KEY", "");
        jail.set_env("SENTINELX__AI_COPILOT__MODEL", "claude-3-5-sonnet-latest");
        jail.set_env("SENTINELX__AI_COPILOT__MAX_TOKENS", 1024);
        jail.set_env("SENTINELX__AI_COPILOT__TEMPERATURE", 0.2);

        // intel_feeds (disabled by default; monolith spawns a TAXII
        // poller background task only when enabled — the network adapter
        // itself is deferred to a follow-up phase, only the schema +
        // stub job module ship in this scaffold).
        jail.set_env("SENTINELX__INTEL_FEEDS__ENABLED", false);
        jail.set_env("SENTINELX__INTEL_FEEDS__TAXII_ENDPOINT", "");
        jail.set_env("SENTINELX__INTEL_FEEDS__TAXII_BEARER", "");
        jail.set_env("SENTINELX__INTEL_FEEDS__COLLECTION_ID", "");
        jail.set_env("SENTINELX__INTEL_FEEDS__POLL_INTERVAL_SECS", 3600);

        // graph (disabled by default; sx-monolith only builds the
        // Neo4jKnowledgeGraph adapter when enabled).
        jail.set_env("SENTINELX__GRAPH__NEO4J_ENABLED", false);
        jail.set_env("SENTINELX__GRAPH__NEO4J_URI", "");
        jail.set_env("SENTINELX__GRAPH__NEO4J_USER", "");
        jail.set_env("SENTINELX__GRAPH__NEO4J_PASSWORD", "");
        jail.set_env("SENTINELX__GRAPH__NEO4J_DATABASE", "");
    }

    #[test]
    fn happy_path_loads_from_env() {
        Jail::expect_with(|jail| {
            set_full_env(jail);
            let settings = load_from(None).map_err(|e| e.to_string())?;
            assert_eq!(settings.server.bind_addr.port(), 8080);
            assert_eq!(settings.database.max_connections, 20);
            assert_eq!(settings.jwt.algorithm, JwtAlgorithm::Hs256);
            assert_eq!(settings.telemetry.log_format, LogFormat::Json);
            assert_eq!(settings.telemetry.log_level, LogLevel::Info);
            assert_eq!(settings.engagement.default_intensity, Intensity::Normal);
            assert!((settings.telemetry.sample_ratio - 0.25).abs() < f64::EPSILON);
            assert_eq!(settings.discovery.dns_resolvers.len(), 2);
            assert_eq!(settings.collab.base_domain, "oob.sentinelx.invalid");
            assert!(!settings.collab.enabled);
            // Secret value must round-trip.
            assert_eq!(
                settings.database.url.expose_secret(),
                "postgres://user:pw@db.example.com:5432/sentinelx"
            );
            Ok(())
        });
    }

    #[test]
    fn production_rejects_in_memory_database() {
        // SELL-P0-06: a production environment must not run the in-memory store.
        Jail::expect_with(|jail| {
            set_full_env(jail);
            jail.set_env("SENTINELX__TELEMETRY__ENVIRONMENT", "production");
            let err = load_from(None).expect_err("prod + in-memory db must fail");
            assert!(
                matches!(&err, ConfigError::InvalidValue { key, .. } if key == "database.enabled"),
                "got {err:?}"
            );
            Ok(())
        });
    }

    #[test]
    fn production_rejects_dev_signing_key() {
        Jail::expect_with(|jail| {
            set_full_env(jail);
            jail.set_env("SENTINELX__TELEMETRY__ENVIRONMENT", "production");
            jail.set_env("SENTINELX__DATABASE__ENABLED", true);
            jail.set_env(
                "SENTINELX__JWT__SIGNING_KEY",
                "DEV_ONLY_HS256_SIGNING_KEY_REPLACE_FOR_ANY_REAL_DEPLOYMENT__",
            );
            let err = load_from(None).expect_err("prod + dev signing key must fail");
            assert!(
                matches!(&err, ConfigError::InvalidValue { key, .. } if key == "jwt.signing_key"),
                "got {err:?}"
            );
            Ok(())
        });
    }

    #[test]
    fn non_production_allows_dev_values() {
        // The dev/test fixture (in-memory db, environment=test) must still load.
        Jail::expect_with(|jail| {
            set_full_env(jail);
            let settings = load_from(None).map_err(|e| e.to_string())?;
            assert!(!settings.is_production());
            Ok(())
        });
    }

    #[test]
    fn missing_required_value_returns_missing_error() {
        Jail::expect_with(|jail| {
            set_full_env(jail);
            // Wipe a single mandatory key.
            jail.set_env("SENTINELX__DATABASE__URL", "");
            let err = load_from(None).expect_err("expected MissingValue");
            assert!(
                matches!(&err, ConfigError::MissingValue { key } if key.starts_with("database")),
                "got {err:?}"
            );
            Ok(())
        });
    }

    #[test]
    fn empty_bind_addr_surfaces_as_invalid_value() {
        Jail::expect_with(|jail| {
            set_full_env(jail);
            // figment::Jail has no remove_env; setting empty turns into an
            // un-parseable SocketAddr → InvalidValue with the normalised key.
            jail.set_env("SENTINELX__SERVER__BIND_ADDR", "");
            let err = load_from(None).expect_err("expected InvalidValue");
            assert!(
                matches!(&err, ConfigError::InvalidValue { key, .. } if key == "server.bind_addr"),
                "got {err:?}"
            );
            Ok(())
        });
    }

    #[test]
    fn malformed_database_url_returns_invalid_value() {
        Jail::expect_with(|jail| {
            set_full_env(jail);
            jail.set_env("SENTINELX__DATABASE__URL", "not a url");
            let err = load_from(None).expect_err("expected InvalidValue");
            assert!(
                matches!(&err, ConfigError::InvalidValue { key, .. } if key == "database.url"),
                "got {err:?}"
            );
            Ok(())
        });
    }

    #[test]
    fn wrong_database_scheme_returns_invalid_value() {
        Jail::expect_with(|jail| {
            set_full_env(jail);
            jail.set_env(
                "SENTINELX__DATABASE__URL",
                "mysql://user:pw@db.example.com/sx",
            );
            let err = load_from(None).expect_err("expected InvalidValue");
            assert!(
                matches!(&err, ConfigError::InvalidValue { key, reason }
                    if key == "database.url" && reason.contains("postgres")),
                "got {err:?}"
            );
            Ok(())
        });
    }

    #[test]
    fn zero_weight_sum_is_rejected() {
        Jail::expect_with(|jail| {
            set_full_env(jail);
            jail.set_env("SENTINELX__RISK__WEIGHTS__W_SEVERITY", 0.0);
            jail.set_env("SENTINELX__RISK__WEIGHTS__W_EXPLOIT", 0.0);
            jail.set_env("SENTINELX__RISK__WEIGHTS__W_EXPOSURE", 0.0);
            jail.set_env("SENTINELX__RISK__WEIGHTS__W_CRITICALITY", 0.0);
            jail.set_env("SENTINELX__RISK__WEIGHTS__W_BUSINESS_IMPACT", 0.0);
            jail.set_env("SENTINELX__RISK__WEIGHTS__W_CHAIN", 0.0);
            let err = load_from(None).expect_err("expected InvalidValue");
            assert!(
                matches!(&err, ConfigError::InvalidValue { key, .. } if key == "risk.weights"),
                "got {err:?}"
            );
            Ok(())
        });
    }

    #[test]
    fn out_of_range_sample_ratio_is_rejected() {
        Jail::expect_with(|jail| {
            set_full_env(jail);
            jail.set_env("SENTINELX__TELEMETRY__SAMPLE_RATIO", 1.5);
            let err = load_from(None).expect_err("expected validation failure");
            assert!(
                matches!(
                    &err,
                    ConfigError::Validation(_) | ConfigError::InvalidValue { .. }
                ),
                "got {err:?}"
            );
            Ok(())
        });
    }

    #[test]
    fn hs256_key_too_short_is_rejected() {
        Jail::expect_with(|jail| {
            set_full_env(jail);
            jail.set_env("SENTINELX__JWT__SIGNING_KEY", "short");
            let err = load_from(None).expect_err("expected InvalidValue");
            assert!(
                matches!(&err, ConfigError::InvalidValue { key, .. } if key == "jwt.signing_key"),
                "got {err:?}"
            );
            Ok(())
        });
    }

    #[test]
    fn debug_output_does_not_contain_secrets() {
        Jail::expect_with(|jail| {
            set_full_env(jail);
            let settings = load_from(None).map_err(|e| e.to_string())?;
            let dbg = format!("{settings:?}");
            assert!(!dbg.contains("hunter2"));
            assert!(!dbg.contains("very-long-hmac"));
            assert!(!dbg.contains("pw@db.example.com"));
            assert!(!dbg.contains("pw@cache.example.com"));
            Ok(())
        });
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn yaml_file_is_overridden_by_env() {
        Jail::expect_with(|jail| {
            // First, write a YAML that supplies *everything* but uses a
            // different bind port.
            let yaml = r#"
server:
  bind_addr: "127.0.0.1:9999"
  shutdown_timeout: 30
  request_timeout: 15
  max_body_bytes: 1048576
  rate_limit:
    limit_per_minute: 600
    burst: 60
    enabled: true
database:
  url: "postgres://user:pw@db.example.com:5432/sentinelx"
  max_connections: 20
  min_connections: 2
  acquire_timeout: 5
  idle_timeout: 300
  statement_timeout_ms: 30000
  migrate_on_start: true
  enabled: false
redis:
  url: "redis://:pw@cache.example.com:6379/0"
  pool_size: 10
  command_timeout: 2
  enabled: false
jwt:
  issuer: sentinelx
  audience: sentinelx-clients
  signing_key: "this-is-a-very-long-hmac-secret-key-32b"
  key_id: k1
  access_ttl: 900
  refresh_ttl: 86400
  algorithm: HS256
  leeway_seconds: 30
telemetry:
  service_name: sx-monolith
  environment: test
  log_level: info
  log_format: json
  otlp_endpoint: ~
  prometheus_bind: ~
  sample_ratio: 0.25
risk:
  weights:
    w_severity: 0.3
    w_exploit: 0.2
    w_exposure: 0.15
    w_criticality: 0.15
    w_business_impact: 0.1
    w_chain: 0.1
  kev_boost_factor: 1.5
  epss_threshold_act: 0.7
engagement:
  max_concurrent: 4
  default_intensity: normal
  kill_switch_channel: sentinelx.killswitch
  killswitch_watchdog_interval: 5
  global_denylist: []
iam:
  password:
    m_cost: 19456
    t_cost: 2
    p_cost: 1
    output_len: 32
    salt_len: 16
  session_inactivity_timeout: 1800
  mfa_required: true
  lockout:
    threshold: 5
    window: 600
    duration: 900
  attempt_email_pepper: "test-pepper-must-be-at-least-16b"
bootstrap:
  enabled: false
  admin_tenant_slug: default
  admin_tenant_name: "Default Tenant"
  admin_email: admin@example.com
  admin_password_phc: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$abcdefghijklmnopqrstuvwxyz123456"
discovery:
  dns_resolvers:
    - "1.1.1.1:53"
  max_concurrent_probes: 64
  per_target_rps_limit: 10
  http_user_agent: "SentinelX/0.1"
  http_timeout: 10
  port_scan_max_ports: 1024
collab:
  enabled: false
  base_domain: "oob.sentinelx.invalid"
  dns_bind: "127.0.0.1:5353"
  http_bind: "127.0.0.1:9080"
  answer_ipv4: "127.0.0.1"
  callback_ttl: 259200
  http_body_capture_bytes: 4096
  smtp_max_message_bytes: 65536
cloud:
  aws: { enabled: false }
  gcp: { enabled: false }
  azure: { enabled: false }
github:
  enabled: false
mtls:
  enabled: false
  cert_path: ""
  key_path: ""
  client_ca_path: ""
  require_client_cert: false
  reload_interval_secs: 60
"#;
            jail.create_file("sentinelx.yaml", yaml)?;
            // Env override of one field.
            jail.set_env("SENTINELX__SERVER__BIND_ADDR", "0.0.0.0:7777");

            let path = jail.directory().join("sentinelx.yaml");
            let settings = load_from(Some(&path)).map_err(|e| e.to_string())?;
            assert_eq!(settings.server.bind_addr.port(), 7777);
            assert_eq!(settings.discovery.dns_resolvers.len(), 1);
            Ok(())
        });
    }

    #[test]
    fn missing_yaml_file_is_io_error() {
        Jail::expect_with(|jail| {
            // Even the env path: we want load_from to fail clearly.
            let path = jail.directory().join("does-not-exist.yaml");
            let err = load_from(Some(&path)).expect_err("expected Io");
            assert!(matches!(err, ConfigError::Io(_)), "got {err:?}");
            Ok(())
        });
    }

    #[test]
    fn anti_abuse_env_values_round_trip() {
        Jail::expect_with(|jail| {
            set_full_env(jail);
            // Override every anti_abuse key to a distinctive non-default
            // value so we can assert env->struct mapping is faithful.
            jail.set_env("SENTINELX__ANTI_ABUSE__ENABLED", true);
            jail.set_env("SENTINELX__ANTI_ABUSE__REPLAY_WINDOW_SECS", 123);
            jail.set_env("SENTINELX__ANTI_ABUSE__RATE_WINDOW_SECS", 45);
            jail.set_env("SENTINELX__ANTI_ABUSE__RATE_ANOMALY_MULTIPLIER", 4.5);
            jail.set_env("SENTINELX__ANTI_ABUSE__RATE_MIN_SAMPLES", 7);
            jail.set_env("SENTINELX__ANTI_ABUSE__AGENT_WINDOW_SECS", 240);
            jail.set_env("SENTINELX__ANTI_ABUSE__AGENT_THRESHOLD", 9);

            let settings = load_from(None).map_err(|e| e.to_string())?;
            assert!(settings.anti_abuse.enabled);
            assert_eq!(settings.anti_abuse.replay_window_secs, 123);
            assert_eq!(settings.anti_abuse.rate_window_secs, 45);
            assert!(
                (settings.anti_abuse.rate_anomaly_multiplier - 4.5).abs() < f64::EPSILON,
                "multiplier mapping diverged"
            );
            assert_eq!(settings.anti_abuse.rate_min_samples, 7);
            assert_eq!(settings.anti_abuse.agent_window_secs, 240);
            assert_eq!(settings.anti_abuse.agent_threshold, 9);
            Ok(())
        });
    }

    #[test]
    fn anti_abuse_enabled_with_zero_window_is_rejected() {
        Jail::expect_with(|jail| {
            set_full_env(jail);
            jail.set_env("SENTINELX__ANTI_ABUSE__ENABLED", true);
            jail.set_env("SENTINELX__ANTI_ABUSE__REPLAY_WINDOW_SECS", 0);
            let err = load_from(None).expect_err("expected InvalidValue for zero window");
            assert!(
                matches!(
                    &err,
                    ConfigError::InvalidValue { key, .. }
                    if key == "anti_abuse.replay_window_secs"
                ),
                "got {err:?}"
            );
            Ok(())
        });
    }

    #[test]
    fn intel_feeds_env_values_round_trip() {
        Jail::expect_with(|jail| {
            set_full_env(jail);
            // Override every intel_feeds key with a distinctive value
            // and flip `enabled` on so the loader exercises both the
            // env→struct path and the cross-field invariants.
            jail.set_env("SENTINELX__INTEL_FEEDS__ENABLED", true);
            jail.set_env(
                "SENTINELX__INTEL_FEEDS__TAXII_ENDPOINT",
                "https://taxii.example.com/api/v21/",
            );
            jail.set_env("SENTINELX__INTEL_FEEDS__TAXII_BEARER", "round-trip-bearer");
            jail.set_env(
                "SENTINELX__INTEL_FEEDS__COLLECTION_ID",
                "00000000-0000-0000-0000-000000000042",
            );
            jail.set_env("SENTINELX__INTEL_FEEDS__POLL_INTERVAL_SECS", 120);

            let settings = load_from(None).map_err(|e| e.to_string())?;
            assert!(settings.intel_feeds.enabled);
            assert_eq!(
                settings.intel_feeds.taxii_endpoint,
                "https://taxii.example.com/api/v21/"
            );
            assert_eq!(
                settings.intel_feeds.collection_id,
                "00000000-0000-0000-0000-000000000042"
            );
            assert_eq!(settings.intel_feeds.poll_interval_secs, 120);
            assert_eq!(
                settings.intel_feeds.taxii_bearer.expose_secret(),
                "round-trip-bearer"
            );
            // Debug must never leak the bearer.
            let dbg = format!("{:?}", settings.intel_feeds);
            assert!(!dbg.contains("round-trip-bearer"));
            Ok(())
        });
    }

    #[test]
    fn intel_feeds_enabled_without_endpoint_is_rejected() {
        Jail::expect_with(|jail| {
            set_full_env(jail);
            jail.set_env("SENTINELX__INTEL_FEEDS__ENABLED", true);
            jail.set_env("SENTINELX__INTEL_FEEDS__TAXII_ENDPOINT", "");
            jail.set_env("SENTINELX__INTEL_FEEDS__TAXII_BEARER", "round-trip-bearer");
            jail.set_env(
                "SENTINELX__INTEL_FEEDS__COLLECTION_ID",
                "00000000-0000-0000-0000-000000000042",
            );
            let err = load_from(None).expect_err("expected MissingValue");
            assert!(
                matches!(
                    &err,
                    ConfigError::MissingValue { key }
                    if key == "intel_feeds.taxii_endpoint"
                ),
                "got {err:?}"
            );
            Ok(())
        });
    }

    #[test]
    fn graph_env_values_round_trip_when_enabled() {
        Jail::expect_with(|jail| {
            set_full_env(jail);
            jail.set_env("SENTINELX__GRAPH__NEO4J_ENABLED", true);
            jail.set_env("SENTINELX__GRAPH__NEO4J_URI", "bolt://127.0.0.1:7687");
            jail.set_env("SENTINELX__GRAPH__NEO4J_USER", "neo4j");
            jail.set_env("SENTINELX__GRAPH__NEO4J_PASSWORD", "round-trip-pw");
            jail.set_env("SENTINELX__GRAPH__NEO4J_DATABASE", "neo4j");

            let settings = load_from(None).map_err(|e| e.to_string())?;
            assert!(settings.graph.neo4j_enabled);
            assert_eq!(settings.graph.neo4j_uri, "bolt://127.0.0.1:7687");
            assert_eq!(settings.graph.neo4j_user, "neo4j");
            assert_eq!(settings.graph.neo4j_database, "neo4j");
            assert_eq!(
                settings.graph.neo4j_password.expose_secret(),
                "round-trip-pw"
            );
            let dbg = format!("{:?}", settings.graph);
            assert!(!dbg.contains("round-trip-pw"), "password leaked: {dbg}");
            Ok(())
        });
    }

    #[test]
    fn graph_enabled_without_password_is_rejected() {
        Jail::expect_with(|jail| {
            set_full_env(jail);
            jail.set_env("SENTINELX__GRAPH__NEO4J_ENABLED", true);
            jail.set_env("SENTINELX__GRAPH__NEO4J_URI", "bolt://127.0.0.1:7687");
            jail.set_env("SENTINELX__GRAPH__NEO4J_USER", "neo4j");
            jail.set_env("SENTINELX__GRAPH__NEO4J_PASSWORD", "");
            jail.set_env("SENTINELX__GRAPH__NEO4J_DATABASE", "neo4j");
            let err = load_from(None).expect_err("expected MissingValue");
            assert!(
                matches!(
                    &err,
                    ConfigError::MissingValue { key }
                    if key == "graph.neo4j_password"
                ),
                "got {err:?}"
            );
            Ok(())
        });
    }

    #[test]
    fn invalid_denylist_cidr_is_rejected() {
        Jail::expect_with(|jail| {
            set_full_env(jail);
            jail.set_env(
                "SENTINELX__ENGAGEMENT__GLOBAL_DENYLIST",
                r#"[{"kind":"cidr","value":"not-a-cidr","reason":"test"}]"#,
            );
            let err = load_from(None).expect_err("expected InvalidValue");
            assert!(
                matches!(&err, ConfigError::InvalidValue { key, .. }
                    if key.starts_with("engagement.global_denylist")),
                "got {err:?}"
            );
            Ok(())
        });
    }
}
