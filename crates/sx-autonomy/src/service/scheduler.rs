//! In-process scheduler primitives used by the validation engine.
//!
//! The scheduler is intentionally tiny: it owns a `tokio::time::interval`
//! whose period is derived from a [`crate::model::schedule::Schedule`], plus
//! a `tokio::sync::Notify` used as a shutdown signal. The engine selects
//! between the two on every iteration so shutdown is observed within one
//! tick.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

/// Coarse tick driver shared between the engine and its handle.
#[derive(Debug)]
pub struct Ticker {
    /// Shutdown notifier — `notify_one()` releases the engine loop.
    pub shutdown: Arc<Notify>,
    /// Tick interval.
    pub period: Duration,
}

impl Ticker {
    /// Build a new ticker.
    #[must_use]
    pub fn new(period: Duration) -> Self {
        Self {
            shutdown: Arc::new(Notify::new()),
            period,
        }
    }
}
