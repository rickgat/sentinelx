//! Bridges [`sx_config::TelemetryConfig`] into the
//! [`sx_telemetry::TelemetryConfig`] shape expected by the telemetry crate.
//!
//! The two types intentionally diverge: `sx-config` uses typed enums
//! (`LogLevel`, `LogFormat`) so deserialisation is strict; `sx-telemetry`
//! holds the lower-level string forms needed by `tracing_subscriber::EnvFilter`
//! and by its own `LogFormat`. This module is the single conversion point.

use sx_config::schema::telemetry::{
    LogFormat as ConfigLogFormat, LogLevel, TelemetryConfig as ConfigTelemetryConfig,
};
use sx_telemetry::logging::LogFormat as RuntimeLogFormat;
use sx_telemetry::TelemetryConfig as RuntimeTelemetryConfig;

/// Convert a configuration view of telemetry settings into the form expected
/// by `sx-telemetry`. Pure data movement — no I/O, no fallible parsing.
///
/// Retained alongside [`from_config_with_override`] as a stable
/// no-override entry point for callers (and tests) that never need to
/// force a level.
#[allow(dead_code)] // exercised by the test module + retained API contract
pub(crate) fn from_config(cfg: &ConfigTelemetryConfig) -> RuntimeTelemetryConfig {
    from_config_with_override(cfg, None)
}

/// Convert with an optional caller-supplied log-level override.
///
/// Introduced for M3 / SX-REVIEW-002: the `--diagnose` flag on the
/// `sx-monolith` binary forces verbose adapter-wiring output without
/// requiring the operator to edit the YAML or restart with a different
/// config file. When `override_level` is `Some(_)`, the effective
/// `log_level` is taken from the override; otherwise the value from
/// `cfg.log_level` is used.
///
/// All other fields are passed through unchanged.
pub(crate) fn from_config_with_override(
    cfg: &ConfigTelemetryConfig,
    override_level: Option<LogLevel>,
) -> RuntimeTelemetryConfig {
    let effective_level = override_level.unwrap_or(cfg.log_level);
    RuntimeTelemetryConfig {
        service_name: cfg.service_name.clone(),
        environment: cfg.environment.clone(),
        service_version: None,
        log_level: log_level_to_filter(effective_level),
        log_format: log_format_to_runtime(cfg.log_format),
        otlp_endpoint: cfg.otlp_endpoint.clone(),
        prometheus_bind: cfg.prometheus_bind,
        sample_ratio: cfg.sample_ratio,
    }
}

fn log_level_to_filter(level: LogLevel) -> String {
    match level {
        LogLevel::Error => "error".to_owned(),
        LogLevel::Warn => "warn".to_owned(),
        LogLevel::Info => "info".to_owned(),
        LogLevel::Debug => "debug".to_owned(),
        LogLevel::Trace => "trace".to_owned(),
    }
}

const fn log_format_to_runtime(format: ConfigLogFormat) -> RuntimeLogFormat {
    match format {
        ConfigLogFormat::Json => RuntimeLogFormat::Json,
        ConfigLogFormat::Text => RuntimeLogFormat::Text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn cfg_with_level(level: LogLevel) -> ConfigTelemetryConfig {
        ConfigTelemetryConfig {
            service_name: "sx-monolith".to_owned(),
            environment: "dev".to_owned(),
            log_level: level,
            log_format: ConfigLogFormat::Json,
            otlp_endpoint: None,
            prometheus_bind: None::<SocketAddr>,
            sample_ratio: 0.1,
        }
    }

    #[test]
    fn log_level_filter_strings_are_envfilter_compatible() {
        assert_eq!(log_level_to_filter(LogLevel::Error), "error");
        assert_eq!(log_level_to_filter(LogLevel::Warn), "warn");
        assert_eq!(log_level_to_filter(LogLevel::Info), "info");
        assert_eq!(log_level_to_filter(LogLevel::Debug), "debug");
        assert_eq!(log_level_to_filter(LogLevel::Trace), "trace");
    }

    #[test]
    fn log_format_maps_one_to_one() {
        assert!(matches!(
            log_format_to_runtime(ConfigLogFormat::Json),
            RuntimeLogFormat::Json
        ));
        assert!(matches!(
            log_format_to_runtime(ConfigLogFormat::Text),
            RuntimeLogFormat::Text
        ));
    }

    #[test]
    fn from_config_uses_config_level_when_no_override() {
        let cfg = cfg_with_level(LogLevel::Warn);
        let runtime = from_config(&cfg);
        assert_eq!(runtime.log_level, "warn");
    }

    #[test]
    fn override_forces_info_even_when_config_says_warn() {
        // M3: --diagnose passes Some(LogLevel::Info) regardless of what
        // the operator's YAML config holds. This is the single
        // behaviour the diagnose flag promises; lock it down.
        let cfg = cfg_with_level(LogLevel::Warn);
        let runtime = from_config_with_override(&cfg, Some(LogLevel::Info));
        assert_eq!(runtime.log_level, "info");
    }

    #[test]
    fn override_none_is_equivalent_to_from_config() {
        let cfg = cfg_with_level(LogLevel::Error);
        let a = from_config(&cfg);
        let b = from_config_with_override(&cfg, None);
        assert_eq!(a.log_level, b.log_level);
        assert_eq!(a.service_name, b.service_name);
        assert_eq!(a.environment, b.environment);
    }
}
