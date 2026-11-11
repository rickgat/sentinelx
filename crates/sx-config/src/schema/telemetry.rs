//! Telemetry / observability configuration.

use std::net::SocketAddr;

use serde::Deserialize;
use url::Url;
use validator::Validate;

/// Log output format.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// One JSON object per line (production).
    Json,
    /// Pretty / coloured text (local dev).
    Text,
}

/// Log verbosity level. Maps directly onto `tracing::Level`.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Show errors only.
    Error,
    /// Errors + warnings.
    Warn,
    /// Errors, warnings, info (default for production).
    Info,
    /// + debug spans.
    Debug,
    /// + every event (very noisy).
    Trace,
}

/// Telemetry pipeline configuration: logs, metrics, traces.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    /// `service.name` resource attribute, used by every span/metric.
    #[validate(length(min = 1))]
    pub service_name: String,

    /// `deployment.environment` resource attribute (e.g. `prod`, `staging`).
    #[validate(length(min = 1))]
    pub environment: String,

    /// Minimum log level emitted by `tracing` subscribers.
    pub log_level: LogLevel,

    /// Format used by the log appender.
    pub log_format: LogFormat,

    /// Optional OpenTelemetry collector endpoint (`grpc://...` or
    /// `https://...`). When `None`, traces are emitted to logs only.
    pub otlp_endpoint: Option<Url>,

    /// Optional Prometheus scrape endpoint bind address. When `None`, no
    /// Prometheus server is started.
    pub prometheus_bind: Option<SocketAddr>,

    /// Head-based span sampling ratio in the range `0.0..=1.0`.
    #[validate(range(min = 0.0, max = 1.0))]
    pub sample_ratio: f64,
}

impl TelemetryConfig {
    /// Cross-field invariants checked by the loader.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if !self.sample_ratio.is_finite() {
            return Err(crate::ConfigError::invalid(
                "telemetry.sample_ratio",
                "must be a finite number in [0, 1]",
            ));
        }
        if !(0.0..=1.0).contains(&self.sample_ratio) {
            return Err(crate::ConfigError::invalid(
                "telemetry.sample_ratio",
                "must be in [0, 1]",
            ));
        }
        Ok(())
    }
}
