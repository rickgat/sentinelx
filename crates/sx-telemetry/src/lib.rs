//! # sx-telemetry
//!
//! Bootstrap and shutdown of the `SentinelX` observability stack:
//!
//! * Structured logging via [`tracing`] + [`tracing_subscriber`].
//! * Distributed tracing via [`tracing_opentelemetry`] + [`opentelemetry_otlp`] (gRPC).
//! * Metrics via [`metrics`] + [`metrics_exporter_prometheus`].
//!
//! The crate exposes a single [`init`] entry-point that returns a
//! [`TelemetryGuard`]. The guard is RAII: dropping it best-effort shuts down
//! the OpenTelemetry tracer provider and aborts the Prometheus listener task.
//! Prefer the async [`TelemetryGuard::shutdown`] method for graceful shutdown
//! when an async runtime is still available.
//!
//! ## Logging field conventions
//!
//! * **Never** log secrets, API keys, tokens or passwords. Use the
//!   [`secrecy`](https://docs.rs/secrecy) crate at the producer site so that
//!   `Debug` derivations cannot leak credentials.
//! * Prefer structured fields over string interpolation:
//!   `tracing::info!(user_id = %id, "login ok")` rather than embedding `id`
//!   inside the message.
//! * Request scoped values (e.g. `request_id`, `trace_id`, `tenant_id`) belong
//!   on a span, not on every event.
//! * Personally identifying information must be hashed or redacted before
//!   reaching a log layer.
//!
//! ## Configuration contract
//!
//! The crate accepts a [`TelemetryConfig`]. Its shape mirrors
//! `sx_config::schema::telemetry::TelemetryConfig` (owned by the `sx-config`
//! crate); once that type stabilises a `From` implementation can bridge the
//! two without breaking callers.
//!
//! Any field that is `None` simply disables the corresponding subsystem —
//! the crate never silently defaults to `localhost:4317` or any other
//! hardcoded endpoint.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod cardinality;
pub mod context;
pub mod error;
pub mod guard;
pub mod logging;
pub mod metrics;
pub mod otlp;

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

pub use crate::cardinality::{GuardOutcome, MetricSeriesGuard};
pub use crate::context::{current_trace_id, new_request_id};
pub use crate::error::TelemetryError;
pub use crate::guard::TelemetryGuard;
pub use crate::logging::LogFormat;
pub use crate::metrics::register_business_metrics;
pub use crate::otlp::{build_otlp_layer, OtlpLayer};

/// Telemetry configuration consumed by [`init`].
///
/// Mirrors `sx_config::schema::telemetry::TelemetryConfig`. The local copy
/// keeps `sx-telemetry` compilable while `sx-config` is still being built
/// out, and lets the crate be unit-tested without a circular dependency.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct TelemetryConfig {
    /// Logical service name used for both log records and the `OTel` resource.
    pub service_name: String,
    /// Deployment environment (e.g. `dev`, `staging`, `prod`).
    pub environment: String,
    /// Optional service version reported as the `service.version` resource
    /// attribute.
    #[serde(default)]
    pub service_version: Option<String>,
    /// `EnvFilter` directive (e.g. `info,sx_api=debug`).
    pub log_level: String,
    /// Selects JSON or compact text formatting for the fmt layer.
    pub log_format: LogFormat,
    /// Optional OTLP/gRPC endpoint for span export. When `None`, no tracer
    /// is wired up.
    pub otlp_endpoint: Option<url::Url>,
    /// Optional bind address for the Prometheus `/metrics` listener.
    pub prometheus_bind: Option<std::net::SocketAddr>,
    /// Trace sampling ratio in the inclusive range `0.0..=1.0`.
    pub sample_ratio: f64,
}

impl TelemetryConfig {
    /// Validate config invariants that are not expressible in the type
    /// system. Currently checks that [`Self::sample_ratio`] is a finite
    /// number within `0.0..=1.0` and that [`Self::service_name`] /
    /// [`Self::environment`] / [`Self::log_level`] are non-empty.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::InvalidFilter`] when the log level is
    /// blank, and [`TelemetryError::Io`] tagged validation messages for
    /// other invariant violations.
    pub fn validate(&self) -> Result<(), TelemetryError> {
        if self.service_name.trim().is_empty() {
            return Err(TelemetryError::Io("service_name must not be empty".into()));
        }
        if self.environment.trim().is_empty() {
            return Err(TelemetryError::Io("environment must not be empty".into()));
        }
        if self.log_level.trim().is_empty() {
            return Err(TelemetryError::InvalidFilter(
                "log_level must not be empty".into(),
            ));
        }
        if !self.sample_ratio.is_finite() || self.sample_ratio < 0.0 || self.sample_ratio > 1.0 {
            return Err(TelemetryError::Io(format!(
                "sample_ratio must be a finite number in 0.0..=1.0, got {}",
                self.sample_ratio
            )));
        }
        Ok(())
    }
}

/// Initialise the global telemetry stack.
///
/// Steps performed in order:
/// 1. Build an [`tracing_subscriber::EnvFilter`] from
///    [`TelemetryConfig::log_level`].
/// 2. Install a fmt layer — JSON when [`LogFormat::Json`], compact text
///    otherwise. File, line, target and span fields are always recorded
///    and timestamps are RFC3339 UTC.
/// 3. When [`TelemetryConfig::otlp_endpoint`] is present, wire an
///    OpenTelemetry layer pointed at that endpoint with a `TraceIdRatioBased`
///    sampler and resource attributes derived from
///    [`TelemetryConfig::service_name`], [`TelemetryConfig::service_version`]
///    and [`TelemetryConfig::environment`].
/// 4. When [`TelemetryConfig::prometheus_bind`] is present, install a
///    Prometheus recorder and spawn a tokio task that serves `/metrics` on
///    the supplied address.
///
/// Returns a [`TelemetryGuard`] that must be kept alive for the lifetime of
/// the process. Dropping it shuts the subsystems down.
///
/// # Errors
///
/// Returns a [`TelemetryError`] when any subsystem cannot be initialised,
/// for example invalid filter directives, unreachable OTLP endpoints, or
/// a previously installed global subscriber.
pub fn init(cfg: &TelemetryConfig) -> Result<TelemetryGuard, TelemetryError> {
    cfg.validate()?;

    let env_filter = logging::build_env_filter(&cfg.log_level)?;
    let fmt_layer = logging::build_fmt_layer(cfg.log_format);

    let otlp_layer = match cfg.otlp_endpoint.as_ref() {
        Some(endpoint) => {
            let layer = otlp::build_otlp_layer(
                endpoint.as_str(),
                &cfg.service_name,
                &cfg.environment,
                cfg.sample_ratio,
            )?;
            otlp::install_global(&layer);
            Some(layer)
        }
        None => None,
    };
    let metrics_state = metrics::init_metrics(cfg)?;

    let registry = tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer);

    match otlp_layer.as_ref().map(otlp::OtlpLayer::layer) {
        Some(layer) => registry
            .with(layer)
            .try_init()
            .map_err(|_| TelemetryError::AlreadyInitialized)?,
        None => registry
            .try_init()
            .map_err(|_| TelemetryError::AlreadyInitialized)?,
    }

    Ok(TelemetryGuard::new(otlp_layer, metrics_state))
}
