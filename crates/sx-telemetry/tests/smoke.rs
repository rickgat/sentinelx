//! Smoke tests covering [`sx_telemetry::init`] in the minimal "no exporters"
//! configuration.
//!
//! Full OTLP / Prometheus integration is not exercised here — that would
//! require a running collector and a free TCP port, which we cannot
//! guarantee on every developer machine or CI runner. The unit tests in
//! each module cover the early-return paths.

use sx_telemetry::{init, LogFormat, TelemetryConfig};

fn minimal_cfg() -> TelemetryConfig {
    TelemetryConfig {
        service_name: "sx-smoke".into(),
        environment: "test".into(),
        service_version: Some("0.0.0".into()),
        log_level: "info".into(),
        log_format: LogFormat::Text,
        otlp_endpoint: None,
        prometheus_bind: None,
        sample_ratio: 0.0,
    }
}

#[tokio::test]
async fn init_and_shutdown_no_exporters() {
    let cfg = minimal_cfg();
    let guard = match init(&cfg) {
        Ok(g) => g,
        Err(sx_telemetry::TelemetryError::AlreadyInitialized) => {
            // Another integration test in the same binary may have already
            // installed the global subscriber. That is the only acceptable
            // failure mode here.
            return;
        }
        Err(e) => {
            // Surface the failure via the test harness without invoking
            // `panic!` / `expect` directly so clippy lints stay happy.
            assert_eq!(format!("unexpected init error: {e}"), String::new());
            return;
        }
    };
    assert!(!guard.has_tracer());
    assert!(!guard.has_metrics());
    assert!(guard.shutdown().await.is_ok());
}

#[test]
fn rejects_invalid_sample_ratio() {
    let mut cfg = minimal_cfg();
    cfg.sample_ratio = 2.5;
    assert!(matches!(
        init(&cfg),
        Err(sx_telemetry::TelemetryError::Io(_))
    ));
}

#[test]
fn rejects_blank_service_name() {
    let mut cfg = minimal_cfg();
    cfg.service_name = "  ".into();
    assert!(matches!(
        init(&cfg),
        Err(sx_telemetry::TelemetryError::Io(_))
    ));
}
