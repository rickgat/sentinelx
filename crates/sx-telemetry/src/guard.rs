//! RAII guard returned by [`init`](crate::init).
//!
//! Holds whatever telemetry subsystems were enabled by config so that the
//! caller can keep them alive for the lifetime of the process. When the
//! guard is dropped a best-effort shutdown is attempted; for graceful async
//! shutdown the caller should explicitly `await` [`TelemetryGuard::shutdown`]
//! before exit.

use crate::error::TelemetryError;
use crate::metrics::MetricsState;
use crate::otlp::OtlpLayer;

/// RAII wrapper around the live telemetry subsystems.
///
/// Dropping the guard:
/// * aborts the Prometheus listener task (if any), and
/// * calls `shutdown()` on the `OTel` tracer provider (if any), discarding
///   any error since `Drop` cannot return one.
///
/// Prefer the async [`TelemetryGuard::shutdown`] method when an async
/// runtime is still available — it surfaces errors and lets the `OTel` batch
/// exporter flush pending spans before exit.
#[derive(Debug)]
pub struct TelemetryGuard {
    tracer: Option<OtlpLayer>,
    metrics: Option<MetricsState>,
}

impl TelemetryGuard {
    pub(crate) const fn new(tracer: Option<OtlpLayer>, metrics: Option<MetricsState>) -> Self {
        Self { tracer, metrics }
    }

    /// Whether a distributed tracing exporter is active.
    pub const fn has_tracer(&self) -> bool {
        self.tracer.is_some()
    }

    /// Whether the Prometheus exporter is active.
    pub const fn has_metrics(&self) -> bool {
        self.metrics.is_some()
    }

    /// Borrow the metrics state if installed. Useful for rendering snapshots
    /// inline in tests without going through HTTP.
    pub const fn metrics(&self) -> Option<&MetricsState> {
        self.metrics.as_ref()
    }

    /// Graceful async shutdown.
    ///
    /// Aborts the Prometheus listener task and flushes the `OTel` provider.
    /// Consumes `self` so the [`Drop`] impl will see empty `Option`s and
    /// become a no-op.
    ///
    /// # Errors
    ///
    /// Returns the first error encountered. Other subsystems are still
    /// shut down regardless of the order they fail in.
    pub async fn shutdown(mut self) -> Result<(), TelemetryError> {
        let mut first_err: Option<TelemetryError> = None;

        if let Some(metrics) = self.metrics.take() {
            metrics.abort();
            // Allow tokio to actually run the abort.
            tokio::task::yield_now().await;
        }

        if let Some(tracer) = self.tracer.take() {
            if let Err(e) = tracer.shutdown() {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }

        first_err.map_or(Ok(()), Err)
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(metrics) = self.metrics.take() {
            metrics.abort();
        }
        if let Some(tracer) = self.tracer.take() {
            // Drop can't await or surface errors. Best-effort.
            let _ = tracer.shutdown();
        }
    }
}
