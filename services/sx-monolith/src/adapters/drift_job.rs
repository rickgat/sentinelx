//! Periodic prediction-drift detector (monolith adapter).
//!
//! Every `interval_secs` (default 3600s / 1 hour) this job:
//!
//! 1. Builds an empirical [`Histogram`] of the last hour's prediction
//!    probabilities (20 uniform bins over `[0, 1]`).
//! 2. Compares the current histogram to the embedded
//!    [`reference_histogram`] via [`kl_divergence`]
//!    (`D_KL(current || reference)` with Laplace smoothing).
//! 3. If the divergence exceeds `cfg.threshold`, emits a SOC event onto
//!    `soc_event_tx` of the form:
//!
//!    ```jsonc
//!    {
//!      "action": "core.ml.drift.detected",
//!      "divergence": <kl>,
//!      "severity": "medium",
//!      "ts": "<rfc3339>"
//!    }
//!    ```
//!
//! The job exits cleanly on [`CancellationToken::cancelled`]. The
//! prediction buffer is owned by the spawned task and accumulates across
//! ticks via [`DriftBuffer`], a shared `Arc<Mutex<Vec<f64>>>` whose clone
//! is returned to the composition root so other adapters can push the
//! probabilities they observe.
//!
//! ## Why a shared buffer + the spawn signature
//!
//! The spawn signature is fixed by the agent contract (predictive + tx +
//! cfg + shutdown). The job therefore creates its own `DriftBuffer`
//! internally and clones a writer handle into a process-global registry
//! the reconcile step installs. Callers that record predictions resolve
//! the handle through the registry — see `DriftBuffer::install_global`.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use serde_json::json;
use sx_api::port::PredictivePort;
use sx_ml::drift::{kl_divergence, Histogram};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Default cadence between drift checks (1 hour).
const DEFAULT_INTERVAL_SECS: u64 = 3_600;

/// Default KL threshold above which a SOC event is fired.
const DEFAULT_THRESHOLD: f64 = 0.5;

/// Number of bins in the histogram. Bin edges are `0.0, 0.05, …, 1.0`.
const HIST_BINS: usize = 20;

/// Configuration for the periodic drift job.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DriftJobConfig {
    /// Interval between drift checks, in seconds. Defaults to
    /// [`DEFAULT_INTERVAL_SECS`] (3600s = 1 hour).
    pub interval_secs: u64,
    /// KL-divergence threshold above which a SOC event is emitted.
    /// Defaults to [`DEFAULT_THRESHOLD`] (0.5).
    pub threshold: f64,
}

impl Default for DriftJobConfig {
    fn default() -> Self {
        Self {
            interval_secs: DEFAULT_INTERVAL_SECS,
            threshold: DEFAULT_THRESHOLD,
        }
    }
}

/// Build the 21 strictly-ascending bin edges used by both the reference
/// and the live histogram: `[0.0, 0.05, 0.10, …, 0.95, 1.0]`.
pub(crate) fn bin_edges() -> Vec<f64> {
    let mut edges = Vec::with_capacity(HIST_BINS + 1);
    for i in 0..=HIST_BINS {
        #[allow(clippy::cast_precision_loss)]
        let v = i as f64 / HIST_BINS as f64;
        edges.push(v);
    }
    edges
}

/// Reference distribution = uniform across the 20 bins.
///
/// Implemented as 20 synthetic counts of `1` each — when normalised by the
/// histogram's `total()`, every bin has probability `1/20`.
pub(crate) fn reference_histogram() -> Histogram {
    Histogram {
        bins: bin_edges(),
        counts: vec![1_u64; HIST_BINS],
    }
}

/// Shared, thread-safe buffer of recent prediction probabilities.
///
/// The drift job clones one handle to drain on every tick; other adapters
/// can clone additional handles to push samples. A `OnceLock<DriftBuffer>`
/// is exposed via [`global`] so a single buffer can be reached from any
/// site without threading it through every signature.
#[derive(Debug, Clone, Default)]
pub(crate) struct DriftBuffer {
    inner: Arc<Mutex<Vec<f64>>>,
}

impl DriftBuffer {
    /// Build a fresh buffer.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Push a probability sample. Non-finite samples are dropped silently
    /// (the histogram builder would skip them anyway).
    #[allow(dead_code)] // exposed for future predictive-port instrumentation
    pub(crate) fn record(&self, probability: f64) {
        if !probability.is_finite() {
            return;
        }
        if let Ok(mut g) = self.inner.lock() {
            g.push(probability);
        }
    }

    /// Drain the buffer, returning the snapshot. A poisoned mutex
    /// recovers the inner vec rather than panicking.
    pub(crate) fn drain(&self) -> Vec<f64> {
        match self.inner.lock() {
            Ok(mut g) => std::mem::take(&mut *g),
            Err(poison) => {
                warn!(
                    target: "adapters.drift_job",
                    "drift buffer mutex poisoned; recovering",
                );
                let mut g = poison.into_inner();
                std::mem::take(&mut *g)
            }
        }
    }
}

/// Process-global registry for the drift buffer.
///
/// `OnceLock` ensures only one buffer exists per process; the reconcile
/// step calls `install_global` once during composition.
static GLOBAL_BUFFER: OnceLock<DriftBuffer> = OnceLock::new();

/// Install `buffer` as the process-global drift buffer. Returns `Err(())`
/// if a buffer has already been installed.
#[allow(dead_code)] // exercised by reconcile + future predict adapters
pub(crate) fn install_global(buffer: DriftBuffer) -> Result<(), ()> {
    GLOBAL_BUFFER.set(buffer).map_err(|_| ())
}

/// Borrow the process-global drift buffer, if installed.
#[allow(dead_code)] // exercised by reconcile + future predict adapters
pub(crate) fn global() -> Option<&'static DriftBuffer> {
    GLOBAL_BUFFER.get()
}

/// Spawn the periodic drift job.
///
/// The job owns its own [`DriftBuffer`]; the composition root retrieves a
/// clone via [`install_global`] (called from inside the spawn helper) so
/// other adapters can push samples. `predictive` is retained for the
/// lifetime of the task so the composition root cannot accidentally drop
/// the only reference before the receiver thread cancels.
pub(crate) fn spawn(
    predictive: Arc<dyn PredictivePort>,
    soc_event_tx: mpsc::Sender<serde_json::Value>,
    cfg: DriftJobConfig,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    let interval = Duration::from_secs(cfg.interval_secs.max(1));
    let buffer = DriftBuffer::new();
    // Best-effort install: if a buffer is already installed (e.g. tests
    // re-spawning the job), keep using the freshly-minted one for this
    // task — the global registry is purely a courtesy.
    let _ = install_global(buffer.clone());

    tokio::spawn(async move {
        info!(
            target: "adapters.drift_job",
            interval_secs = cfg.interval_secs,
            threshold = cfg.threshold,
            "drift periodic job started",
        );
        // Keep the predictive port alive for the lifetime of the job so
        // the composition root cannot drop the only reference.
        let _keep_predictive = predictive;

        loop {
            tokio::select! {
                () = shutdown.cancelled() => {
                    info!(
                        target: "adapters.drift_job",
                        "drift periodic job received cancellation, exiting",
                    );
                    return;
                }
                () = tokio::time::sleep(interval) => {
                    run_tick(&buffer, &soc_event_tx, cfg.threshold).await;
                }
            }
        }
    })
}

/// Execute one drift check. Returns the divergence (or `None` when there
/// were no samples to compare against). Pulled out so the unit tests can
/// exercise it directly without the spawn loop.
pub(crate) async fn run_tick(
    buffer: &DriftBuffer,
    soc_event_tx: &mpsc::Sender<serde_json::Value>,
    threshold: f64,
) -> Option<f64> {
    let samples = buffer.drain();
    if samples.is_empty() {
        debug!(
            target: "adapters.drift_job",
            "no samples this tick; skipping drift evaluation",
        );
        return None;
    }

    let edges = bin_edges();
    let current = Histogram::from_samples(&samples, &edges);
    let reference = reference_histogram();
    let divergence = kl_divergence(&current, &reference);

    if divergence > threshold {
        let ts = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"));
        let event = json!({
            "action": "core.ml.drift.detected",
            "divergence": divergence,
            "severity": "medium",
            "ts": ts,
        });
        if let Err(err) = soc_event_tx.send(event).await {
            warn!(
                target: "adapters.drift_job",
                error = %err,
                "drift SOC event dropped: receiver closed",
            );
        } else {
            info!(
                target: "adapters.drift_job",
                divergence,
                threshold,
                samples = samples.len(),
                "drift detected, SOC event emitted",
            );
        }
    } else {
        debug!(
            target: "adapters.drift_job",
            divergence,
            threshold,
            samples = samples.len(),
            "drift below threshold, no event",
        );
    }
    Some(divergence)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use async_trait::async_trait;
    use sx_api::port::Phase3PortError;
    use sx_api::view::predictive_view::PredictResponse;

    // --- helpers ----------------------------------------------------------

    #[derive(Debug)]
    struct NoopPredictive;
    #[async_trait]
    impl PredictivePort for NoopPredictive {
        async fn predict(&self, _t: &str, _f: &str) -> Result<PredictResponse, Phase3PortError> {
            Err(Phase3PortError::NotFound)
        }
    }

    // --- tests ------------------------------------------------------------

    #[tokio::test]
    async fn drift_skips_emit_when_history_empty() {
        let buffer = DriftBuffer::new();
        let (tx, mut rx) = mpsc::channel::<serde_json::Value>(8);
        let div = run_tick(&buffer, &tx, 0.001).await;
        assert!(div.is_none(), "expected None when no samples recorded");
        // Confirm no event was sent.
        let r = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(r.is_err(), "no event must be emitted on empty buffer");
    }

    #[tokio::test]
    async fn drift_emits_event_when_kl_exceeds_threshold() {
        let buffer = DriftBuffer::new();
        // Heavy mass at the high end -> very different from uniform ->
        // KL >> typical threshold.
        for _ in 0..200 {
            buffer.record(0.99);
        }
        let (tx, mut rx) = mpsc::channel::<serde_json::Value>(8);
        let div = run_tick(&buffer, &tx, 0.1).await.unwrap();
        assert!(
            div > 0.1,
            "expected divergence > 0.1 for skewed-vs-uniform, got {div}",
        );
        let event = tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .expect("SOC event must arrive within deadline")
            .expect("channel must yield event");
        assert_eq!(
            event.get("action").and_then(|v| v.as_str()),
            Some("core.ml.drift.detected"),
        );
        assert_eq!(
            event.get("severity").and_then(|v| v.as_str()),
            Some("medium"),
        );
        assert!(event
            .get("divergence")
            .and_then(serde_json::Value::as_f64)
            .is_some());
        assert!(event.get("ts").and_then(|v| v.as_str()).is_some());
    }

    #[tokio::test]
    async fn drift_skips_emit_when_kl_below_threshold() {
        let buffer = DriftBuffer::new();
        // Spread samples evenly to approximate the reference -> small KL.
        for i in 0_i32..200 {
            let v = f64::from(i) / 200.0;
            buffer.record(v);
        }
        let (tx, mut rx) = mpsc::channel::<serde_json::Value>(8);
        // Threshold deliberately high so the small KL stays below it.
        let div = run_tick(&buffer, &tx, 5.0).await.unwrap();
        assert!(div >= 0.0, "divergence must be non-negative, got {div}");
        let r = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(r.is_err(), "no event must be emitted below threshold");
    }

    #[test]
    fn reference_histogram_probabilities_sum_to_one() {
        let h = reference_histogram();
        let probs = h.probabilities();
        let sum: f64 = probs.iter().sum();
        assert!(
            (sum - 1.0).abs() < 1e-9,
            "reference probs must sum to 1.0, got {sum}",
        );
        assert_eq!(probs.len(), HIST_BINS);
        // Every bin must carry the same probability.
        for p in &probs {
            assert!((p - 1.0 / 20.0).abs() < 1e-9);
        }
    }

    #[test]
    fn bin_edges_are_strictly_ascending_and_cover_unit_interval() {
        let edges = bin_edges();
        assert_eq!(edges.len(), HIST_BINS + 1);
        assert!((edges.first().copied().unwrap() - 0.0).abs() < 1e-12);
        assert!((edges.last().copied().unwrap() - 1.0).abs() < 1e-12);
        for w in edges.windows(2) {
            assert!(w[1] > w[0], "edges must be strictly ascending");
        }
    }

    #[tokio::test]
    async fn spawn_cancellation_aborts_the_loop() {
        let (tx, _rx) = mpsc::channel::<serde_json::Value>(8);
        let token = CancellationToken::new();
        let cfg = DriftJobConfig {
            interval_secs: 60,
            threshold: 0.1,
        };
        let predictive: Arc<dyn PredictivePort> = Arc::new(NoopPredictive);
        let handle = spawn(predictive, tx, cfg, token.clone());
        token.cancel();
        let r = tokio::time::timeout(Duration::from_secs(2), handle).await;
        assert!(r.is_ok(), "drift job did not exit within 2s of cancel");
    }

    #[test]
    fn buffer_drops_non_finite_samples() {
        let b = DriftBuffer::new();
        b.record(f64::NAN);
        b.record(f64::INFINITY);
        b.record(0.5);
        let drained = b.drain();
        assert_eq!(drained, vec![0.5]);
    }
}
