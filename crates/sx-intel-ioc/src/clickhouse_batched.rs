//! Batching decorator for any [`ClickHouseLink`] implementation.
//!
//! [`BatchingClickHouseLink`] wraps an inner sink and amortises per-row
//! overhead by accumulating rows in an in-memory buffer that flushes when any
//! of three thresholds is crossed:
//!
//! * `max_batch_rows` — total queued rows (findings + audit) reached
//! * `max_batch_bytes` — approximate serialised buffer footprint reached
//! * `flush_interval` — wall-clock interval elapsed without a flush
//!
//! Flushes go through an exponential-backoff retry loop with jitter
//! (`initial * 2^attempt`, capped at `max_backoff`, multiplied by
//! `1.0..1.1`). After exhausting [`BatchingConfig::max_retries`], the batch is
//! handled per [`BatchingConfig::on_error`]: either dropped (the default —
//! observability sink should never block the caller) or propagated to the
//! caller of [`BatchingClickHouseLink::flush`].
//!
//! The decorator is itself a [`ClickHouseLink`]; the per-row trait calls
//! simply append to the buffer in `O(1)` and never await on I/O. A background
//! task — spawned in [`BatchingClickHouseLink::start`] — drives the interval
//! tick and the actual upstream writes.
//!
//! Graceful shutdown is via [`BatchingClickHouseLink::flush`], which drains
//! the buffer synchronously through the same retry policy.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::{interval, sleep, MissedTickBehavior};

use crate::clickhouse::{AuditProjection, ClickHouseError, ClickHouseLink, FindingProjection};

/// Policy applied to a batch whose flush exhausts all retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnError {
    /// Drop the batch and log the failure — write path stays unblocked.
    Drop,
    /// Surface the underlying [`ClickHouseError`] back to the caller of
    /// [`BatchingClickHouseLink::flush`].
    ///
    /// Background-task flushes always drop on terminal failure regardless of
    /// this policy, because there is no caller to surface the error to.
    Propagate,
}

/// Configuration for [`BatchingClickHouseLink`].
#[derive(Debug, Clone)]
pub struct BatchingConfig {
    /// Maximum queued rows (findings + audit) before a flush is forced.
    pub max_batch_rows: usize,
    /// Approximate serialised footprint cap, in bytes. We track the sum of
    /// `serde_json::to_string(row).len()` per buffered row.
    pub max_batch_bytes: usize,
    /// Maximum wall-clock interval between flushes.
    pub flush_interval: Duration,
    /// Number of additional attempts beyond the initial flush before giving
    /// up. `0` means "try once, never retry".
    pub max_retries: u32,
    /// Backoff used for the first retry. Doubled per attempt up to
    /// [`Self::max_backoff`].
    pub initial_backoff: Duration,
    /// Upper bound for the per-attempt backoff sleep.
    pub max_backoff: Duration,
    /// What to do with a batch whose flush exhausts retries.
    pub on_error: OnError,
}

impl Default for BatchingConfig {
    fn default() -> Self {
        Self {
            max_batch_rows: 1_000,
            max_batch_bytes: 4 * 1024 * 1024,
            flush_interval: Duration::from_secs(5),
            max_retries: 3,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(10),
            on_error: OnError::Drop,
        }
    }
}

/// In-memory buffer of pending rows tracked by approximate byte size.
#[derive(Debug, Default)]
struct Buffer {
    findings: Vec<FindingProjection>,
    audit: Vec<AuditProjection>,
    bytes: usize,
}

impl Buffer {
    const fn total_rows(&self) -> usize {
        self.findings.len() + self.audit.len()
    }

    fn take(&mut self) -> (Vec<FindingProjection>, Vec<AuditProjection>) {
        self.bytes = 0;
        (
            std::mem::take(&mut self.findings),
            std::mem::take(&mut self.audit),
        )
    }
}

/// Decorator that buffers rows and forwards them to `inner` in retrying
/// batches. See module documentation for the flush + retry contract.
#[derive(Debug)]
pub struct BatchingClickHouseLink {
    inner: Arc<dyn ClickHouseLink>,
    config: BatchingConfig,
    buffer: Arc<Mutex<Buffer>>,
    flusher: Mutex<Option<JoinHandle<()>>>,
}

impl BatchingClickHouseLink {
    /// Build a new batcher wrapping `inner`. The background flush task is
    /// *not* started — call [`Self::start`] to launch it. This split exists
    /// so callers can construct the link inside contexts that do not yet have
    /// a tokio runtime (e.g. configuration-time wiring).
    #[must_use]
    pub fn new(inner: Arc<dyn ClickHouseLink>, config: BatchingConfig) -> Self {
        Self {
            inner,
            config,
            buffer: Arc::new(Mutex::new(Buffer::default())),
            flusher: Mutex::new(None),
        }
    }

    /// Spawn the background interval-driven flush task.
    ///
    /// Safe to call multiple times — subsequent calls are a no-op once a task
    /// is already running. Requires a tokio runtime context.
    pub async fn start(self: &Arc<Self>) {
        let mut guard = self.flusher.lock().await;
        if guard.is_some() {
            return;
        }
        let weak = Arc::downgrade(self);
        let tick = self.config.flush_interval;
        let handle = tokio::spawn(async move {
            let mut ticker = interval(tick);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            // First tick fires immediately — skip it so we don't flush an
            // empty buffer on startup.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let Some(this) = weak.upgrade() else {
                    return;
                };
                // Background flushes always drop on terminal failure — there
                // is no caller to bubble the error up to.
                let _ = this.flush_inner(true).await;
            }
        });
        *guard = Some(handle);
    }

    /// Drain the buffer through the retry policy. Honours
    /// [`BatchingConfig::on_error`] for terminal failures.
    pub async fn flush(&self) -> Result<(), ClickHouseError> {
        self.flush_inner(false).await
    }

    /// Stop the background flush task, if one is running, and drain pending
    /// rows. Intended for graceful shutdown.
    pub async fn shutdown(&self) -> Result<(), ClickHouseError> {
        let taken = {
            let mut guard = self.flusher.lock().await;
            guard.take()
        };
        if let Some(handle) = taken {
            handle.abort();
        }
        self.flush_inner(false).await
    }

    /// Approximate buffered-byte footprint. Exposed for observability and
    /// tests; not part of the [`ClickHouseLink`] surface.
    pub async fn buffered_bytes(&self) -> usize {
        self.buffer.lock().await.bytes
    }

    /// Buffered row count (findings + audit).
    pub async fn buffered_rows(&self) -> usize {
        self.buffer.lock().await.total_rows()
    }

    /// Internal flush. `force_drop_on_error` overrides [`OnError::Propagate`]
    /// — used by the background loop where errors have nowhere to go.
    #[allow(clippy::cognitive_complexity)] // retry/backoff branches inflate the score
    async fn flush_inner(&self, force_drop_on_error: bool) -> Result<(), ClickHouseError> {
        let (findings, audit) = {
            let mut buf = self.buffer.lock().await;
            if buf.total_rows() == 0 {
                return Ok(());
            }
            buf.take()
        };

        let mut last_err: Option<ClickHouseError> = None;
        let attempts = self.config.max_retries.saturating_add(1);
        for attempt in 0..attempts {
            if attempt > 0 {
                let backoff = compute_backoff(
                    self.config.initial_backoff,
                    self.config.max_backoff,
                    attempt - 1,
                );
                sleep(backoff).await;
            }

            match self.try_write(&findings, &audit).await {
                Ok(()) => return Ok(()),
                Err(err) => {
                    tracing::warn!(
                        target: "sx_intel_ioc::clickhouse_batched",
                        attempt = attempt + 1,
                        max = attempts,
                        error = %err,
                        "batched clickhouse flush failed; will retry if attempts remain",
                    );
                    last_err = Some(err);
                }
            }
        }

        let err = last_err.unwrap_or_else(|| {
            ClickHouseError::Transport("flush exhausted retries without error".to_string())
        });
        tracing::error!(
            target: "sx_intel_ioc::clickhouse_batched",
            finding_rows = findings.len(),
            audit_rows = audit.len(),
            error = %err,
            "dropping batch after retry exhaustion",
        );
        if force_drop_on_error || matches!(self.config.on_error, OnError::Drop) {
            Ok(())
        } else {
            Err(err)
        }
    }

    /// One attempt at writing both row types to the inner sink. Findings go
    /// first so a partial failure can be re-observed by the audit log.
    async fn try_write(
        &self,
        findings: &[FindingProjection],
        audit: &[AuditProjection],
    ) -> Result<(), ClickHouseError> {
        if !findings.is_empty() {
            self.inner.write_findings(findings).await?;
        }
        if !audit.is_empty() {
            self.inner.write_audit(audit).await?;
        }
        Ok(())
    }

    /// Append rows and decide whether the size/byte thresholds demand an
    /// immediate flush.
    async fn enqueue_findings(&self, rows: &[FindingProjection]) -> bool {
        if rows.is_empty() {
            return false;
        }
        let mut buf = self.buffer.lock().await;
        for row in rows {
            buf.bytes = buf.bytes.saturating_add(approx_bytes(row));
            buf.findings.push(row.clone());
        }
        let hit = threshold_hit(&self.config, &buf);
        drop(buf);
        hit
    }

    async fn enqueue_audit(&self, rows: &[AuditProjection]) -> bool {
        if rows.is_empty() {
            return false;
        }
        let mut buf = self.buffer.lock().await;
        for row in rows {
            buf.bytes = buf.bytes.saturating_add(approx_bytes(row));
            buf.audit.push(row.clone());
        }
        let hit = threshold_hit(&self.config, &buf);
        drop(buf);
        hit
    }
}

impl Drop for BatchingClickHouseLink {
    fn drop(&mut self) {
        // We can't await Mutex::lock() here, but try_lock is sufficient: by
        // the time we're being dropped no one else holds a reference, so the
        // mutex is uncontended.
        if let Ok(mut guard) = self.flusher.try_lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
    }
}

#[async_trait]
impl ClickHouseLink for BatchingClickHouseLink {
    async fn write_findings(&self, rows: &[FindingProjection]) -> Result<(), ClickHouseError> {
        if self.enqueue_findings(rows).await {
            self.flush().await?;
        }
        Ok(())
    }

    async fn write_audit(&self, rows: &[AuditProjection]) -> Result<(), ClickHouseError> {
        if self.enqueue_audit(rows).await {
            self.flush().await?;
        }
        Ok(())
    }
}

const fn threshold_hit(config: &BatchingConfig, buf: &Buffer) -> bool {
    buf.total_rows() >= config.max_batch_rows || buf.bytes >= config.max_batch_bytes
}

/// Rough size estimate — `serde_json::to_string` may fail for exotic floats
/// (NaN, infinity); we fall back to a conservative constant in that case so
/// the buffer accounting never silently understates.
fn approx_bytes<T: serde::Serialize>(value: &T) -> usize {
    serde_json::to_string(value).map_or(64, |s| s.len())
}

/// `initial * 2^attempt`, capped at `max`, multiplied by a `[1000, 1100]`
/// permille jitter factor so the realised sleep is always within
/// `[capped, capped * 1.1]`.
///
/// All math is integer: we add `0..=10%` of `capped.as_millis()` (one extra
/// millisecond of granularity is enough for retry-jitter purposes and avoids
/// `u128`→`f64` precision loss complaints). The intentional integer division
/// by 1000 truncates sub-millisecond jitter on purpose; that's the resolution
/// we sleep at via [`tokio::time::sleep`] anyway.
#[allow(clippy::integer_division)]
fn compute_backoff(initial: Duration, max: Duration, attempt: u32) -> Duration {
    // 2^21 ≈ 2.1M; way past anything we care about retry-wise. Clamp the
    // exponent so the shift can't overflow.
    let shifted = initial.saturating_mul(2_u32.saturating_pow(attempt.min(20)));
    let capped = if shifted > max { max } else { shifted };
    // jitter_permille in `[0, 100]` → multiplier in `[1.00, 1.10]`.
    let jitter_permille: u32 = rand::random::<u32>() % 101;
    let base_millis = u128_to_u64_saturating(capped.as_millis());
    let extra = base_millis.saturating_mul(u64::from(jitter_permille)) / 1_000;
    let total_millis = base_millis.saturating_add(extra);
    Duration::from_millis(total_millis)
}

fn u128_to_u64_saturating(v: u128) -> u64 {
    u64::try_from(v).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// Test double that records every call and can be configured to fail the
    /// first `fail_first` writes.
    #[derive(Debug, Default)]
    struct RecordingSink {
        finding_calls: AtomicUsize,
        finding_rows: AtomicUsize,
        audit_calls: AtomicUsize,
        audit_rows: AtomicUsize,
        fail_first: AtomicUsize,
    }

    impl RecordingSink {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        fn with_failures(n: usize) -> Arc<Self> {
            let s = Self::default();
            s.fail_first.store(n, Ordering::SeqCst);
            Arc::new(s)
        }
    }

    #[async_trait]
    impl ClickHouseLink for RecordingSink {
        async fn write_findings(&self, rows: &[FindingProjection]) -> Result<(), ClickHouseError> {
            if self.fail_first.load(Ordering::SeqCst) > 0 {
                self.fail_first.fetch_sub(1, Ordering::SeqCst);
                return Err(ClickHouseError::Transport("simulated failure".to_string()));
            }
            self.finding_calls.fetch_add(1, Ordering::SeqCst);
            self.finding_rows.fetch_add(rows.len(), Ordering::SeqCst);
            Ok(())
        }

        async fn write_audit(&self, rows: &[AuditProjection]) -> Result<(), ClickHouseError> {
            if self.fail_first.load(Ordering::SeqCst) > 0 {
                self.fail_first.fetch_sub(1, Ordering::SeqCst);
                return Err(ClickHouseError::Transport("simulated failure".to_string()));
            }
            self.audit_calls.fetch_add(1, Ordering::SeqCst);
            self.audit_rows.fetch_add(rows.len(), Ordering::SeqCst);
            Ok(())
        }
    }

    fn finding(id: &str) -> FindingProjection {
        FindingProjection {
            id: id.to_string(),
            tenant_id: "11111111-1111-1111-1111-111111111111".to_string(),
            severity: "high".to_string(),
            cvss: 7.5,
            ts_epoch_secs: 1_700_000_000,
        }
    }

    fn audit(seq: u64) -> AuditProjection {
        AuditProjection {
            tenant_id: "11111111-1111-1111-1111-111111111111".to_string(),
            seq,
            action: "scan.start".to_string(),
            actor: "system:test".to_string(),
            ts_epoch_secs: 1_700_000_000,
        }
    }

    fn test_config() -> BatchingConfig {
        BatchingConfig {
            max_batch_rows: 1_000,
            max_batch_bytes: usize::MAX,
            flush_interval: Duration::from_secs(60),
            max_retries: 0,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(100),
            on_error: OnError::Propagate,
        }
    }

    #[tokio::test]
    async fn batches_by_row_threshold() {
        let sink = RecordingSink::new();
        let mut cfg = test_config();
        cfg.max_batch_rows = 3;
        let link = BatchingClickHouseLink::new(sink.clone(), cfg);

        // 2 rows: stays buffered.
        link.write_findings(&[finding("a"), finding("b")])
            .await
            .unwrap();
        assert_eq!(sink.finding_calls.load(Ordering::SeqCst), 0);
        assert_eq!(link.buffered_rows().await, 2);

        // 1 more row: hits the threshold, flushes.
        link.write_findings(&[finding("c")]).await.unwrap();
        assert_eq!(sink.finding_calls.load(Ordering::SeqCst), 1);
        assert_eq!(sink.finding_rows.load(Ordering::SeqCst), 3);
        assert_eq!(link.buffered_rows().await, 0);
    }

    #[tokio::test]
    async fn batches_by_byte_threshold() {
        let sink = RecordingSink::new();
        let mut cfg = test_config();
        cfg.max_batch_rows = usize::MAX;
        cfg.max_batch_bytes = approx_bytes(&finding("x")) * 2;
        let link = BatchingClickHouseLink::new(sink.clone(), cfg);

        link.write_findings(&[finding("a")]).await.unwrap();
        assert_eq!(sink.finding_calls.load(Ordering::SeqCst), 0);
        link.write_findings(&[finding("b")]).await.unwrap();
        assert_eq!(
            sink.finding_calls.load(Ordering::SeqCst),
            1,
            "exceeding byte threshold should trigger a flush",
        );
        assert_eq!(sink.finding_rows.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn batches_by_interval_tick() {
        let sink = RecordingSink::new();
        let mut cfg = test_config();
        cfg.flush_interval = Duration::from_millis(50);
        let link = Arc::new(BatchingClickHouseLink::new(sink.clone(), cfg));
        link.start().await;

        link.write_findings(&[finding("a")]).await.unwrap();
        assert_eq!(sink.finding_calls.load(Ordering::SeqCst), 0);

        // Advance just past one interval (the first tick is consumed at
        // startup, so we need a second tick to flush).
        tokio::time::advance(Duration::from_millis(60)).await;
        // Yield repeatedly so the background task can observe the tick.
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        // Drain any in-flight flush.
        link.flush().await.unwrap();
        assert_eq!(
            sink.finding_calls.load(Ordering::SeqCst),
            1,
            "expected the interval-driven flush to push the buffered row",
        );
        assert_eq!(sink.finding_rows.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn retries_then_succeeds() {
        let sink = RecordingSink::with_failures(2);
        let mut cfg = test_config();
        cfg.max_retries = 3;
        cfg.initial_backoff = Duration::from_millis(10);
        let link = BatchingClickHouseLink::new(sink.clone(), cfg);

        link.write_findings(&[finding("a")]).await.unwrap();
        link.flush().await.unwrap();

        assert_eq!(sink.fail_first.load(Ordering::SeqCst), 0);
        assert_eq!(
            sink.finding_calls.load(Ordering::SeqCst),
            1,
            "the successful retry should record exactly one call",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn retries_exhaust_and_propagate() {
        let sink = RecordingSink::with_failures(usize::MAX);
        let mut cfg = test_config();
        cfg.max_retries = 2;
        cfg.on_error = OnError::Propagate;
        let link = BatchingClickHouseLink::new(sink.clone(), cfg);

        link.write_findings(&[finding("a")]).await.unwrap();
        let err = link.flush().await.expect_err("retries should be exhausted");
        assert!(matches!(err, ClickHouseError::Transport(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn retries_exhaust_and_drop() {
        let sink = RecordingSink::with_failures(usize::MAX);
        let mut cfg = test_config();
        cfg.max_retries = 2;
        cfg.on_error = OnError::Drop;
        let link = BatchingClickHouseLink::new(sink.clone(), cfg);

        link.write_findings(&[finding("a")]).await.unwrap();
        link.flush()
            .await
            .expect("Drop policy must swallow retry exhaustion");
        // Buffer is drained even though no upstream call succeeded.
        assert_eq!(link.buffered_rows().await, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_actually_sleeps() {
        let sink = RecordingSink::with_failures(2);
        let mut cfg = test_config();
        cfg.max_retries = 3;
        cfg.initial_backoff = Duration::from_secs(1);
        cfg.max_backoff = Duration::from_secs(60);
        let link = BatchingClickHouseLink::new(sink.clone(), cfg);

        link.write_findings(&[finding("a")]).await.unwrap();
        let start = tokio::time::Instant::now();
        link.flush().await.unwrap();
        let elapsed = start.elapsed();
        // First retry sleeps ~1s, second ~2s — call it at least 2.5s combined
        // even allowing the jitter to subtract a tick.
        assert!(
            elapsed >= Duration::from_millis(2_500),
            "expected cumulative backoff >= 2.5s, observed {elapsed:?}",
        );
    }

    #[tokio::test]
    async fn shutdown_drains_buffer() {
        let sink = RecordingSink::new();
        let cfg = test_config();
        let link = Arc::new(BatchingClickHouseLink::new(sink.clone(), cfg));
        link.start().await;

        link.write_findings(&[finding("a"), finding("b")])
            .await
            .unwrap();
        link.write_audit(&[audit(1)]).await.unwrap();
        assert_eq!(link.buffered_rows().await, 3);

        link.shutdown().await.unwrap();
        assert_eq!(link.buffered_rows().await, 0);
        assert_eq!(sink.finding_rows.load(Ordering::SeqCst), 2);
        assert_eq!(sink.audit_rows.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn start_is_idempotent() {
        let sink = RecordingSink::new();
        let cfg = test_config();
        let link = Arc::new(BatchingClickHouseLink::new(sink, cfg));
        link.start().await;
        link.start().await;
        link.shutdown().await.unwrap();
    }

    #[test]
    fn compute_backoff_caps_at_max() {
        let initial = Duration::from_millis(10);
        let max = Duration::from_millis(100);
        // Attempt 10 would otherwise be ~10s; cap is 100ms (+ <=10% jitter).
        let b = compute_backoff(initial, max, 10);
        assert!(b >= max, "{b:?} should be at least the cap");
        assert!(
            b <= Duration::from_millis(110),
            "{b:?} should not exceed cap + jitter",
        );
    }

    #[test]
    fn compute_backoff_grows_exponentially() {
        let initial = Duration::from_millis(100);
        let max = Duration::from_secs(60);
        let b0 = compute_backoff(initial, max, 0);
        let b1 = compute_backoff(initial, max, 1);
        let b2 = compute_backoff(initial, max, 2);
        assert!(
            b0 < b1 && b1 < b2,
            "backoff should grow: {b0:?} {b1:?} {b2:?}"
        );
    }
}
