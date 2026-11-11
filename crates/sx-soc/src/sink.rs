//! Alert sinks.
//!
//! A [`AlertSink`] receives every alert that survives correlation. The crate
//! ships two implementations:
//!
//! - [`LogAlertSink`] — emits a `tracing::warn!` line per alert.
//! - [`BufferAlertSink`] — bounded ring buffer for tests and in-memory UIs.

use std::collections::VecDeque;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::alert::Alert;

/// Trait implemented by any destination that wants to receive alerts.
///
/// Implementations should be cheap to clone (typically `Arc`-backed) and
/// must be `Send + Sync` so the correlator can fan-out across tasks.
#[async_trait]
pub trait AlertSink: Send + Sync + std::fmt::Debug {
    /// Forward one alert. Implementations should not block the caller for
    /// long; expensive I/O should be queued internally.
    async fn forward(&self, alert: &Alert);
}

/// A sink that logs each alert via `tracing::warn!`.
#[derive(Debug, Default, Clone)]
pub struct LogAlertSink;

impl LogAlertSink {
    /// Construct a new logger sink.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl AlertSink for LogAlertSink {
    async fn forward(&self, alert: &Alert) {
        tracing::warn!(
            alert.id = %alert.id,
            alert.severity = alert.severity.as_str(),
            alert.kind = %alert.kind,
            alert.tenant_id = ?alert.tenant_id,
            "sx-soc alert fired: {}",
            alert.title,
        );
    }
}

/// A bounded ring buffer of alerts.
///
/// Useful for tests and for the in-memory UI panel. When `capacity` is
/// exceeded, the oldest alert is dropped (FIFO eviction).
#[derive(Debug, Clone)]
pub struct BufferAlertSink {
    capacity: usize,
    inner: Arc<Mutex<VecDeque<Alert>>>,
}

impl BufferAlertSink {
    /// Build a buffer sink that retains the most-recent `capacity` alerts.
    ///
    /// `capacity` is clamped to `1` if zero is passed in, so the sink is
    /// always usable.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
        }
    }

    /// Snapshot the currently buffered alerts (oldest first).
    pub async fn snapshot(&self) -> Vec<Alert> {
        let guard = self.inner.lock().await;
        guard.iter().cloned().collect()
    }

    /// Number of alerts currently in the buffer.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// Whether the buffer is empty.
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }
}

#[async_trait]
impl AlertSink for BufferAlertSink {
    async fn forward(&self, alert: &Alert) {
        let mut guard = self.inner.lock().await;
        if guard.len() == self.capacity {
            let _evicted = guard.pop_front();
        }
        guard.push_back(alert.clone());
    }
}
