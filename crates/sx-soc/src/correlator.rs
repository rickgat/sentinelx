//! Event-stream correlator with per-key throttling.
//!
//! The [`Correlator`] drains a `tokio::sync::mpsc::Receiver<serde_json::Value>`
//! of events, runs each event through the [`crate::engine::RuleEngine`], and
//! fans out surviving alerts to every registered [`crate::sink::AlertSink`].
//!
//! ## Throttling
//!
//! Two alerts sharing the same `(rule_id, tenant_id, kind)` key are collapsed
//! to a single forwarded alert as long as they fall within the originating
//! rule's `throttle` window. The first alert in any window always passes;
//! subsequent ones are silently suppressed. After the window expires the next
//! alert with the same key is forwarded again.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use time::OffsetDateTime;
use tokio::sync::mpsc::Receiver;
use tokio::sync::Mutex;

use crate::alert::Alert;
use crate::engine::RuleEngine;
use crate::sink::AlertSink;

/// Key under which throttle bookkeeping is stored.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ThrottleKey {
    rule_id: String,
    tenant_id: Option<String>,
    kind: String,
}

/// Stream correlator.
///
/// Wraps an engine plus a list of sinks plus throttle state. Cheaply
/// cloneable (everything is `Arc` / `Mutex`-backed) so multiple drainers
/// could run against the same logical correlator if desired.
#[derive(Debug, Clone)]
pub struct Correlator {
    engine: Arc<RuleEngine>,
    sinks: Vec<Arc<dyn AlertSink>>,
    throttle_state: Arc<Mutex<HashMap<ThrottleKey, OffsetDateTime>>>,
    throttles: Arc<HashMap<String, Duration>>,
}

impl Correlator {
    /// Build a correlator from an engine and a list of sinks.
    ///
    /// The throttle windows are derived from `engine.rules()`; rules without
    /// a throttle window pass every match through.
    #[must_use]
    pub fn new(engine: RuleEngine, sinks: Vec<Arc<dyn AlertSink>>) -> Self {
        let throttles: HashMap<String, Duration> = engine
            .rules()
            .iter()
            .filter_map(|r| r.throttle.map(|d| (r.id.clone(), d)))
            .collect();
        Self {
            engine: Arc::new(engine),
            sinks,
            throttle_state: Arc::new(Mutex::new(HashMap::new())),
            throttles: Arc::new(throttles),
        }
    }

    /// Drain `rx` until the sender side is closed.
    ///
    /// Each event is evaluated by the engine; surviving alerts are forwarded
    /// to all sinks. Returns the total number of events seen and the total
    /// number of alerts forwarded after throttling.
    pub async fn run(&self, mut rx: Receiver<Value>) -> CorrelatorStats {
        let mut stats = CorrelatorStats::default();
        while let Some(event) = rx.recv().await {
            stats.events += 1;
            let alerts = self.engine.evaluate(&event).await;
            for alert in alerts {
                stats.alerts_raw += 1;
                if self.allow(&alert).await {
                    stats.alerts_forwarded += 1;
                    for sink in &self.sinks {
                        sink.forward(&alert).await;
                    }
                }
            }
        }
        stats
    }

    /// Throttle gate: returns `true` if the alert should be forwarded.
    async fn allow(&self, alert: &Alert) -> bool {
        let Some(window) = self.throttles.get(alert.kind.as_str()).copied() else {
            return true;
        };
        let key = ThrottleKey {
            rule_id: alert.kind.clone(),
            tenant_id: alert.tenant_id.clone(),
            kind: alert.kind.clone(),
        };
        let now = OffsetDateTime::now_utc();
        let Ok(window) = time::Duration::try_from(window) else {
            return true;
        };
        let mut state = self.throttle_state.lock().await;
        match state.get(&key) {
            Some(last) if now - *last < window => false,
            _ => {
                state.insert(key, now);
                true
            }
        }
    }
}

/// Outcome counters for one [`Correlator::run`] invocation.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CorrelatorStats {
    /// Total events drained from the channel.
    pub events: u64,
    /// Total alerts produced by the engine, before throttling.
    pub alerts_raw: u64,
    /// Total alerts actually forwarded to sinks after throttling.
    pub alerts_forwarded: u64,
}
