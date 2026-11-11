//! OTLP end-to-end smoke test.
//!
//! LOW-001-FU6-TONIC-OTEL landed the tonic 0.14 + opentelemetry 0.32
//! cascade. The `SpanExporter` / `SdkTracerProvider` builder surface
//! changed and the historical batch-exporter no longer needs an explicit
//! runtime handle. This suite locks the new surface down at the crate's
//! public API level so a future opentelemetry rev cannot silently regress
//! it.
//!
//! Coverage:
//! * The layer builds against a syntactically valid endpoint, emits at
//!   least one span through the tracing bridge, and shuts down without
//!   surfacing an error.
//! * The layer rejects empty / whitespace endpoints (contract with
//!   [`sx_telemetry::TelemetryConfig::otlp_endpoint`]).
//!
//! We do NOT stand up a real OTLP collector: dialing an ephemeral loopback
//! address is enough to exercise the batch exporter's construction + the
//! background flush task's spawn path. A real receiver would be flaky in
//! CI (port collisions, protobuf version drift) — the smoke assertion is
//! that `build_otlp_layer -> span -> shutdown` returns clean.
//!
//! The style of surfacing failures via `assert_eq!(format!(...), String::new())`
//! rather than `.expect(...)` / `panic!(...)` mirrors the existing
//! `crates/sx-telemetry/tests/smoke.rs` — it keeps the workspace-wide
//! `clippy::expect_used` / `clippy::panic` denials from firing on the
//! test module without needing `#[allow(...)]` attributes.

use std::net::TcpListener;

use sx_telemetry::build_otlp_layer;
use sx_telemetry::TelemetryError;

/// Reserve a loopback port by binding a listener, then dropping it, then
/// handing the port back. Racy in theory; fine in practice for a smoke
/// test that only cares whether the exporter's builder is happy with a
/// syntactically valid endpoint.
///
/// Returns `None` when we cannot bind at all — the smoke test then
/// short-circuits so it never fails on a CI runner with a fully-locked
/// loopback (rare but non-zero).
fn free_loopback_port() -> Option<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").ok()?;
    let port = listener.local_addr().ok()?.port();
    drop(listener);
    Some(port)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn build_emit_shutdown_round_trip() {
    let Some(port) = free_loopback_port() else {
        // Loopback bind refused — nothing this test can meaningfully do.
        // Treat as skip.
        return;
    };
    let endpoint = format!("http://127.0.0.1:{port}");

    let layer = match build_otlp_layer(&endpoint, "sx-otlp-smoke", "test", 1.0) {
        Ok(l) => l,
        Err(e) => {
            assert_eq!(format!("unexpected build error: {e:?}"), String::new());
            return;
        }
    };

    // Emit one span through the tracing bridge so the batch exporter's
    // work queue is non-empty by the time we shut down. The exporter is
    // pointed at an unreachable port; the batch worker will fail to
    // flush but `shutdown()` MUST still return `Ok(())` — the SDK's
    // contract is that shutdown reports "clean" as long as the shutdown
    // path itself completes.
    {
        let span = tracing::info_span!("otlp_smoke_span", cascade = "LOW-001-FU6-TONIC-OTEL");
        let _guard = span.enter();
        tracing::info!("smoke event");
    }

    if let Err(e) = layer.shutdown() {
        assert_eq!(format!("unexpected shutdown error: {e:?}"), String::new());
    }
}

#[test]
fn empty_endpoint_is_rejected() {
    let err = build_otlp_layer("", "svc", "test", 1.0);
    assert!(
        matches!(err, Err(TelemetryError::Otlp(_))),
        "expected TelemetryError::Otlp for empty endpoint, got {err:?}"
    );
}

#[test]
fn whitespace_endpoint_is_rejected() {
    let err = build_otlp_layer("   ", "svc", "test", 1.0);
    assert!(
        matches!(err, Err(TelemetryError::Otlp(_))),
        "expected TelemetryError::Otlp for whitespace endpoint, got {err:?}"
    );
}
