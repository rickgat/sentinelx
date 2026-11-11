//! Prometheus metrics wiring.
//!
//! When [`TelemetryConfig::prometheus_bind`](crate::TelemetryConfig::prometheus_bind)
//! is `Some`, [`init_metrics`] installs a global Prometheus recorder and
//! spawns the exporter future on the current tokio runtime, returning the
//! [`MetricsState`] which the [`TelemetryGuard`](crate::TelemetryGuard) keeps
//! alive.
//!
//! No HTTP listener is created when the bind address is `None`; this matches
//! the "feature flag via config" approach used throughout the crate — there
//! is intentionally no hardcoded fallback address.

use std::net::SocketAddr;

use metrics::{describe_counter, describe_gauge, describe_histogram, Unit};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tokio::task::JoinHandle;

use crate::error::TelemetryError;
use crate::TelemetryConfig;

/// State produced by [`init_metrics`].
///
/// Holds the recorder handle and the join handle of the spawned HTTP
/// listener so the [`TelemetryGuard`](crate::TelemetryGuard) can abort it on
/// shutdown.
pub struct MetricsState {
    /// Bound address (echoes [`TelemetryConfig::prometheus_bind`]).
    pub bind: SocketAddr,
    handle: PrometheusHandle,
    task: JoinHandle<()>,
}

impl std::fmt::Debug for MetricsState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsState")
            .field("bind", &self.bind)
            .field("task_finished", &self.task.is_finished())
            .finish_non_exhaustive()
    }
}

impl MetricsState {
    /// Render the current metrics snapshot in Prometheus text format.
    pub fn render(&self) -> String {
        self.handle.render()
    }

    /// Abort the spawned listener task. Idempotent.
    pub fn abort(&self) {
        self.task.abort();
    }

    /// Whether the listener task has finished (either gracefully or via
    /// `abort`).
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }
}

/// Install the Prometheus recorder and spawn the listener.
///
/// Returns `Ok(None)` when no bind address is configured.
///
/// # Errors
///
/// Returns [`TelemetryError::Prometheus`] when the recorder cannot be
/// installed (typically because one is already registered) or the listener
/// cannot be built.
pub fn init_metrics(cfg: &TelemetryConfig) -> Result<Option<MetricsState>, TelemetryError> {
    let Some(bind) = cfg.prometheus_bind else {
        return Ok(None);
    };

    let builder = PrometheusBuilder::new().with_http_listener(bind);

    let (recorder, exporter) = builder.build().map_err(|e| TelemetryError::Prometheus {
        addr: bind,
        message: e.to_string(),
    })?;

    let handle = recorder.handle();

    metrics::set_global_recorder(recorder).map_err(|e| TelemetryError::Prometheus {
        addr: bind,
        message: e.to_string(),
    })?;

    let task = tokio::spawn(async move {
        // The exporter future runs forever; if it returns an error we drop
        // it silently — the tracing subscriber may not be installed yet at
        // the time this future yields, and panicking would tear the
        // service down.
        let _ = exporter.await;
    });

    Ok(Some(MetricsState { bind, handle, task }))
}

/// Describe the starter set of business metrics shared across services.
///
/// Callers are responsible for actually recording values. This helper only
/// registers metadata so the Prometheus exporter emits `# HELP` / `# TYPE`
/// lines for the well-known names.
pub fn register_business_metrics() {
    describe_counter!(
        "sx_findings_ingested_total",
        Unit::Count,
        "Total number of security findings ingested across all engagements."
    );
    describe_gauge!(
        "sx_engagement_active_count",
        Unit::Count,
        "Current number of active engagements."
    );
    describe_counter!(
        "sx_killswitch_triggered_total",
        Unit::Count,
        "Total times an engagement killswitch has fired."
    );
    describe_counter!(
        "sx_http_requests_total",
        Unit::Count,
        "Total HTTP requests handled by the API surface."
    );
    describe_histogram!(
        "sx_http_request_duration_seconds",
        Unit::Seconds,
        "Distribution of HTTP request handling latency in seconds."
    );
    // P2-012 — chaos engineering injection counter. Emitted by
    // `sx-chaos` every time the registry consults its sampler, regardless
    // of whether the sample fires. `kind` is one of {latency, error_rate,
    // dependency, none} and `outcome` is one of {pass, latency, error,
    // dependency_unavailable, dependency_timeout}.
    describe_counter!(
        "sx_chaos_injections_total",
        Unit::Count,
        "Chaos engineering injection decisions labelled by kind + outcome."
    );
    // TOP5-#1-PHASE-2A — XMLDSig shadow-mode mismatch counter. Emitted
    // by `sx_xmlsec::DualVerifier` every time the primary and secondary
    // verifiers disagree on a SAML response. The `kind` label is one of
    // {`both_accept_differ`, `primary_only_accept`, `secondary_only_accept`}
    // mirroring the senior plan §2.2 Class A/B/C classifier. The
    // 14-day-zero-disagreement SLO that gates PHASE-2B's cutover reads
    // this counter; alert routing for the `primary_only_accept` and
    // `secondary_only_accept` labels pages out the on-call.
    describe_counter!(
        "xmldsig_shadow_mismatch_total",
        Unit::Count,
        "XMLDSig shadow-mode verifier disagreement count, labelled by mismatch kind."
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::LogFormat;

    #[test]
    fn returns_none_without_bind() {
        let cfg = TelemetryConfig {
            service_name: "sx-test".into(),
            environment: "test".into(),
            service_version: None,
            log_level: "info".into(),
            log_format: LogFormat::Json,
            otlp_endpoint: None,
            prometheus_bind: None,
            sample_ratio: 0.0,
        };
        let result = init_metrics(&cfg);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn describe_does_not_panic() {
        // Without a recorder installed, describe_* calls are no-ops.
        register_business_metrics();
    }
}
