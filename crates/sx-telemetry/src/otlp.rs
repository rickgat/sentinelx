//! Real OTLP/gRPC span export wiring.
//!
//! Today's [`crate::TelemetryConfig`] carries an `otlp_endpoint` field but the
//! historical layer build path only materialised the layer indirectly via a
//! [`TelemetryConfig`]-shaped constructor. This module promotes the work to a
//! first-class, configuration-free public API so spans actually flow to a
//! local collector / Jaeger when callers want it:
//!
//! ```ignore
//! use sx_telemetry::otlp;
//! // Must be called inside a tokio runtime since the batch exporter
//! // spawns its flush task onto the ambient runtime.
//! let _layer = otlp::build_otlp_layer(
//!     "http://127.0.0.1:4317",
//!     "sx-monolith",
//!     "dev",
//!     1.0,
//! )?;
//! # Ok::<_, sx_telemetry::TelemetryError>(())
//! ```
//!
//! The returned [`OtlpLayer`] owns the [`SdkTracerProvider`] that backs the
//! exporter; dropping it (or calling [`OtlpLayer::shutdown`]) flushes pending
//! batches. The crate-wide [`TelemetryGuard`](crate::TelemetryGuard) takes
//! care of that under the standard [`crate::init`] entry point.
//!
//! ## Resource attributes
//!
//! Every emitted span carries three resource attributes computed once at
//! layer construction time:
//!
//! | key                         | value                          |
//! |-----------------------------|--------------------------------|
//! | `service.name`              | caller-supplied `service_name` |
//! | `service.namespace`         | `sentinelx` (constant)         |
//! | `deployment.environment`    | caller-supplied `environment`  |
//!
//! The semantic-convention crate keeps `deployment.environment` behind an
//! experimental feature flag, so the literal key is used directly. The key
//! itself is stable across collector and Jaeger releases.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider, Tracer};
use opentelemetry_sdk::Resource;
use opentelemetry_semantic_conventions::resource::SERVICE_NAME;
use tracing::Subscriber;
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::registry::LookupSpan;

use crate::error::TelemetryError;

/// Instrumentation scope name advertised to the collector.
const INSTRUMENTATION_NAME: &str = "sx-telemetry";

/// Resource attribute key for the service namespace.
///
/// The typed constant in `opentelemetry-semantic-conventions` is gated
/// behind the `semconv_experimental` feature flag; we use the stable literal
/// directly instead of enabling that flag, since the key value is part of
/// the spec and will not move.
const SERVICE_NAMESPACE_KEY: &str = "service.namespace";

/// Value reported for `service.namespace`. All services in the platform
/// report under the same namespace so collectors can group them in a single
/// dashboard.
const SERVICE_NAMESPACE_VALUE: &str = "sentinelx";

/// Resource attribute key for the deployment environment.
///
/// Sourced as a literal for the same reason as [`SERVICE_NAMESPACE_KEY`].
const DEPLOYMENT_ENVIRONMENT_KEY: &str = "deployment.environment";

/// A built OTLP exporter pipeline.
///
/// Holds the backing [`SdkTracerProvider`] and [`Tracer`] so the caller can
/// hand the [`OpenTelemetryLayer`] to a [`tracing_subscriber::Registry`] and
/// later call [`OtlpLayer::shutdown`] to flush pending batches.
#[derive(Debug)]
pub struct OtlpLayer {
    provider: SdkTracerProvider,
    tracer: Tracer,
}

impl OtlpLayer {
    /// Build an [`OpenTelemetryLayer`] over the held tracer.
    ///
    /// The returned layer is generic over the subscriber it is composed into;
    /// callers typically attach it to `tracing_subscriber::registry()` along
    /// with their fmt/filter layers.
    pub fn layer<S>(&self) -> OpenTelemetryLayer<S, Tracer>
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        OpenTelemetryLayer::new(self.tracer.clone())
    }

    /// Borrow the underlying provider; used by guards to register it as the
    /// global tracer provider exactly once.
    pub(crate) const fn provider(&self) -> &SdkTracerProvider {
        &self.provider
    }

    /// Flush and shut the OTLP exporter down. Idempotent at the SDK level.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryError::Otlp`] when the SDK reports a failure
    /// flushing pending batches.
    pub fn shutdown(&self) -> Result<(), TelemetryError> {
        self.provider
            .shutdown()
            .map_err(|e: opentelemetry_sdk::error::OTelSdkError| {
                TelemetryError::Otlp(e.to_string())
            })
    }
}

/// Build an OTLP/gRPC span-exporter layer.
///
/// Constructs a [`SpanExporter`] pointed at `endpoint`, wraps it in a batch
/// [`SdkTracerProvider`] sampled at `sample_ratio` (via
/// [`Sampler::TraceIdRatioBased`]) and returns the corresponding
/// [`OtlpLayer`].
///
/// The endpoint is trimmed of any trailing `/` because the OTLP tonic client
/// rejects URLs that end in a slash. Empty endpoints are rejected up front
/// with [`TelemetryError::Otlp`] rather than being forwarded to the exporter
/// builder, which produces a less actionable error.
///
/// # Resource attributes
///
/// Three attributes are attached to the provider's [`Resource`]:
///
/// * `service.name` = `service_name`
/// * `service.namespace` = `sentinelx`
/// * `deployment.environment` = `environment`
///
/// # Errors
///
/// Returns [`TelemetryError::Otlp`] if `endpoint` is empty or whitespace,
/// or if the gRPC exporter cannot be constructed (invalid URL scheme,
/// unreachable host at build-time TLS validation, etc.).
pub fn build_otlp_layer(
    endpoint: &str,
    service_name: &str,
    environment: &str,
    sample_ratio: f64,
) -> Result<OtlpLayer, TelemetryError> {
    let trimmed = endpoint.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(TelemetryError::Otlp(
            "OTLP endpoint must not be empty".into(),
        ));
    }

    let exporter: SpanExporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(trimmed.to_owned())
        .build()
        .map_err(|e| TelemetryError::Otlp(e.to_string()))?;

    let resource = Resource::builder()
        .with_attributes([
            KeyValue::new(SERVICE_NAME, service_name.to_owned()),
            KeyValue::new(SERVICE_NAMESPACE_KEY, SERVICE_NAMESPACE_VALUE),
            KeyValue::new(DEPLOYMENT_ENVIRONMENT_KEY, environment.to_owned()),
        ])
        .build();

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(Sampler::TraceIdRatioBased(sample_ratio))
        .with_resource(resource)
        .build();

    let tracer = provider.tracer(INSTRUMENTATION_NAME);

    Ok(OtlpLayer { provider, tracer })
}

/// Install `layer`'s provider as the global OpenTelemetry tracer provider.
///
/// Kept as a separate step from [`build_otlp_layer`] so unit tests can
/// construct layers without touching global state.
pub(crate) fn install_global(layer: &OtlpLayer) {
    opentelemetry::global::set_tracer_provider(layer.provider().clone());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn layer_builds_with_valid_endpoint() {
        // The OTLP batch exporter spawns its background flush task onto the
        // ambient tokio runtime — without one the SpanProcessor panics at
        // construction. A `multi_thread` flavor is required (not
        // `current_thread`) because dropping `OtlpLayer` triggers a
        // synchronous `block_on` inside the SDK's shutdown path: that
        // `block_on` waits for the batch worker to ack, and the worker can
        // only run on a different thread.
        //
        // The test does no network I/O of its own — no spans are emitted
        // and the layer is dropped immediately after construction, so the
        // batch worker exits cleanly without ever dialing the endpoint.
        let result = build_otlp_layer("http://localhost:4317", "sx-test", "test", 1.0);
        assert!(
            result.is_ok(),
            "layer should build with a syntactically valid endpoint, got {result:?}",
        );
        drop(result);
    }

    #[test]
    fn layer_rejects_empty_endpoint() {
        let err = build_otlp_layer("", "sx-test", "test", 1.0);
        assert!(
            matches!(err, Err(TelemetryError::Otlp(_))),
            "expected Otlp error, got {err:?}",
        );
    }

    #[test]
    fn layer_rejects_whitespace_endpoint() {
        let err = build_otlp_layer("   ", "sx-test", "test", 1.0);
        assert!(
            matches!(err, Err(TelemetryError::Otlp(_))),
            "expected Otlp error, got {err:?}",
        );
    }
}
