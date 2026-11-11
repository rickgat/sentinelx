//! Prometheus metrics registry for the SentinelX HTTP gateway.
//!
//! All `sx-*` metrics live on a single process-local
//! [`prometheus::Registry`] that is initialised lazily on first access via
//! [`registry`]. Helper functions ([`record_http_request`],
//! [`set_findings_total`], [`set_engagements_active`],
//! [`record_soc_alert_fired`], [`record_bas_run`]) wrap the typed
//! `*Vec` collectors so callers do not need to import `prometheus`
//! directly and so we keep label cardinality contracts inside this
//! module.
//!
//! ## Metric inventory
//!
//! | name                              | type      | labels                     |
//! |-----------------------------------|-----------|----------------------------|
//! | `sx_http_requests_total`          | counter   | `method`, `path`, `status` |
//! | `sx_http_request_duration_seconds`| histogram | `method`, `path`           |
//! | `sx_findings_total`               | gauge     | `severity`, `status`       |
//! | `sx_engagements_active`           | gauge     | _none_                     |
//! | `sx_soc_alerts_fired_total`       | counter   | `severity`                 |
//! | `sx_bas_runs_total`               | counter   | `mode`, `outcome`          |
//!
//! ## Failure handling
//!
//! All metric names and label identifiers used here are valid per the
//! Prometheus exposition spec, so collector construction and registration
//! never fail at runtime. We still avoid `unwrap`/`panic` to honour the
//! workspace clippy gates — instead, the internal `Option<MetricsHandles>`
//! cache silently no-ops on the unreachable error path so the process
//! never crashes on a metrics bug.

use std::sync::OnceLock;

use prometheus::{
    CounterVec, GaugeVec, HistogramOpts, HistogramVec, IntGauge, Opts, Registry, TextEncoder,
};

/// Bucket boundaries (seconds) used by `sx_http_request_duration_seconds`.
const HTTP_DURATION_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Bundle of typed collectors registered against the process registry.
#[derive(Clone)]
pub struct MetricsHandles {
    registry: Registry,
    http_requests_total: CounterVec,
    http_duration_seconds: HistogramVec,
    findings_total: GaugeVec,
    engagements_active: IntGauge,
    soc_alerts_fired_total: CounterVec,
    bas_runs_total: CounterVec,
}

impl std::fmt::Debug for MetricsHandles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsHandles").finish_non_exhaustive()
    }
}

impl MetricsHandles {
    /// Borrow the underlying registry — primarily for the `/metrics`
    /// scrape endpoint.
    #[must_use]
    pub const fn registry(&self) -> &Registry {
        &self.registry
    }
}

/// Wrapper that owns an `Option<MetricsHandles>`.
///
/// Construction is infallible in practice; the `Option` exists purely to
/// keep the `OnceLock` initialiser panic-free if Prometheus ever rejects
/// a collector.
struct MetricsSlot {
    handles: Option<MetricsHandles>,
    fallback_registry: Registry,
}

fn slot() -> &'static MetricsSlot {
    static SLOT: OnceLock<MetricsSlot> = OnceLock::new();
    SLOT.get_or_init(build_slot)
}

fn build_slot() -> MetricsSlot {
    MetricsSlot {
        handles: build_handles_inner(),
        fallback_registry: Registry::new(),
    }
}

fn build_handles_inner() -> Option<MetricsHandles> {
    let registry = Registry::new();

    let http_requests_total = CounterVec::new(
        Opts::new(
            "sx_http_requests_total",
            "Total HTTP requests handled by the SentinelX gateway.",
        ),
        &["method", "path", "status"],
    )
    .ok()?;
    let http_duration_seconds = HistogramVec::new(
        HistogramOpts::new(
            "sx_http_request_duration_seconds",
            "HTTP request handler duration in seconds.",
        )
        .buckets(HTTP_DURATION_BUCKETS.to_vec()),
        &["method", "path"],
    )
    .ok()?;
    let findings_total = GaugeVec::new(
        Opts::new(
            "sx_findings_total",
            "Current count of findings labelled by severity and status.",
        ),
        &["severity", "status"],
    )
    .ok()?;
    let engagements_active = IntGauge::new(
        "sx_engagements_active",
        "Number of currently active engagements.",
    )
    .ok()?;
    let soc_alerts_fired_total = CounterVec::new(
        Opts::new(
            "sx_soc_alerts_fired_total",
            "Total SOC alerts fired by severity.",
        ),
        &["severity"],
    )
    .ok()?;
    let bas_runs_total = CounterVec::new(
        Opts::new(
            "sx_bas_runs_total",
            "Total breach-and-attack-simulation runs by mode and outcome.",
        ),
        &["mode", "outcome"],
    )
    .ok()?;

    registry
        .register(Box::new(http_requests_total.clone()))
        .ok()?;
    registry
        .register(Box::new(http_duration_seconds.clone()))
        .ok()?;
    registry.register(Box::new(findings_total.clone())).ok()?;
    registry
        .register(Box::new(engagements_active.clone()))
        .ok()?;
    registry
        .register(Box::new(soc_alerts_fired_total.clone()))
        .ok()?;
    registry.register(Box::new(bas_runs_total.clone())).ok()?;

    Some(MetricsHandles {
        registry,
        http_requests_total,
        http_duration_seconds,
        findings_total,
        engagements_active,
        soc_alerts_fired_total,
        bas_runs_total,
    })
}

fn handles_opt() -> Option<&'static MetricsHandles> {
    slot().handles.as_ref()
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Borrow the process-wide `sx-*` metrics registry, initialising it on
/// first access.
#[must_use]
pub fn registry() -> &'static Registry {
    let s = slot();
    s.handles
        .as_ref()
        .map_or(&s.fallback_registry, MetricsHandles::registry)
}

/// Encode the registry into the Prometheus text exposition format.
///
/// Returns the encoded body together with its canonical content type
/// (`text/plain; version=0.0.4`).
#[must_use]
pub fn render_text_exposition() -> (String, &'static str) {
    let encoder = TextEncoder::new();
    let metric_families = registry().gather();
    let body = encoder
        .encode_to_string(&metric_families)
        .unwrap_or_default();
    (body, prometheus::TEXT_FORMAT)
}

/// Record an HTTP request observation: bump the counter and observe the
/// histogram.
pub fn record_http_request(method: &str, path: &str, status: u16, duration_secs: f64) {
    let Some(h) = handles_opt() else { return };
    let status_str = status_label(status);
    h.http_requests_total
        .with_label_values(&[method, path, &status_str])
        .inc();
    h.http_duration_seconds
        .with_label_values(&[method, path])
        .observe(duration_secs);
}

/// Set the gauge for findings broken down by severity and status.
pub fn set_findings_total(severity: &str, status: &str, value: f64) {
    let Some(h) = handles_opt() else { return };
    h.findings_total
        .with_label_values(&[severity, status])
        .set(value);
}

/// Set the number of currently active engagements.
pub fn set_engagements_active(value: i64) {
    let Some(h) = handles_opt() else { return };
    h.engagements_active.set(value);
}

/// Increment the SOC-alert counter for a given severity.
pub fn record_soc_alert_fired(severity: &str) {
    let Some(h) = handles_opt() else { return };
    h.soc_alerts_fired_total
        .with_label_values(&[severity])
        .inc();
}

/// Increment the BAS-runs counter for a given (mode, outcome) pair.
pub fn record_bas_run(mode: &str, outcome: &str) {
    let Some(h) = handles_opt() else { return };
    h.bas_runs_total.with_label_values(&[mode, outcome]).inc();
}

fn status_label(status: u16) -> String {
    use std::fmt::Write as _;
    let mut buf = String::with_capacity(3);
    // Writing into a String is infallible.
    let _ = write!(&mut buf, "{status}");
    buf
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;
    use prometheus::proto::MetricType;

    fn metric_names() -> Vec<String> {
        registry()
            .gather()
            .into_iter()
            .map(|mf| mf.get_name().to_owned())
            .collect()
    }

    #[test]
    fn registry_exposes_all_sx_metrics() {
        // Touch every collector at least once so its family appears in
        // `gather()` output (gauges/histograms with no observations may
        // otherwise be elided depending on the prometheus version).
        record_http_request("GET", "/x", 200, 0.001);
        set_findings_total("low", "open", 0.0);
        set_engagements_active(0);
        record_soc_alert_fired("low");
        record_bas_run("dry_run", "pass");

        let names = metric_names();
        for expected in [
            "sx_http_requests_total",
            "sx_http_request_duration_seconds",
            "sx_findings_total",
            "sx_engagements_active",
            "sx_soc_alerts_fired_total",
            "sx_bas_runs_total",
        ] {
            assert!(
                names.iter().any(|n| n == expected),
                "missing metric: {expected} (registered: {names:?})"
            );
        }
    }

    #[test]
    fn scrape_body_contains_sx_http_requests_total() {
        record_http_request("GET", "/healthz", 200, 0.001);
        let (body, _ct) = render_text_exposition();
        assert!(
            body.contains("sx_http_requests_total"),
            "scrape body missing counter: {body}"
        );
    }

    #[test]
    fn findings_total_label_set_works() {
        set_findings_total("critical", "open", 7.0);
        set_findings_total("high", "resolved", 3.0);
        let (body, _) = render_text_exposition();
        assert!(body.contains("sx_findings_total"));
        assert!(body.contains("severity=\"critical\""));
        assert!(body.contains("status=\"open\""));
        assert!(body.contains("severity=\"high\""));
    }

    #[test]
    fn http_duration_histogram_has_buckets() {
        record_http_request("GET", "/v1/findings", 200, 0.05);
        let families = registry().gather();
        let hist = families
            .iter()
            .find(|mf| mf.get_name() == "sx_http_request_duration_seconds")
            .unwrap();
        assert_eq!(hist.get_field_type(), MetricType::HISTOGRAM);
        let metric = &hist.get_metric()[0];
        let buckets = metric.get_histogram().get_bucket();
        assert!(
            !buckets.is_empty(),
            "expected non-empty bucket boundaries on histogram"
        );
        assert_eq!(buckets.len(), HTTP_DURATION_BUCKETS.len());
    }

    #[test]
    fn text_encoder_content_type_is_valid() {
        let (_body, content_type) = render_text_exposition();
        assert_eq!(content_type, "text/plain; version=0.0.4");
        assert_eq!(content_type, prometheus::TEXT_FORMAT);
    }

    #[test]
    fn helper_functions_do_not_panic() {
        record_http_request("POST", "/v1/bas/run", 202, 0.42);
        record_soc_alert_fired("high");
        record_bas_run("dry_run", "success");
        set_engagements_active(12);
        let names = metric_names();
        assert!(names.contains(&"sx_soc_alerts_fired_total".to_owned()));
        assert!(names.contains(&"sx_bas_runs_total".to_owned()));
        assert!(names.contains(&"sx_engagements_active".to_owned()));
    }

    #[test]
    fn registry_handle_is_stable_across_calls() {
        let r1 = registry();
        let r2 = registry();
        assert!(std::ptr::eq(r1, r2));
    }
}
