//! `GraphsageRiskPort` adapter — exposes a read-only view onto the cache
//! written by the periodic [`super::graphsage_job`] task.
//!
//! The graphsage job recomputes per-asset risk scores every
//! `interval_secs` (default 900s / 15 minutes) and writes them into a
//! shared `Arc<Mutex<HashMap<String, f64>>>`. This adapter wraps the same
//! handle and surfaces only the `get(asset_id) -> Option<f64>` read path,
//! satisfying the [`sx_api::port::GraphsageRiskPort`] trait so the rest of
//! the HTTP layer never touches the mutex directly.
//!
//! ## Why a `Mutex<HashMap>` not `RwLock`
//!
//! The write side runs at most once every 15 minutes and rebuilds the
//! entire map in one shot. Reads are O(1) probes and the critical section
//! is a single lookup; under no realistic workload does a `RwLock` win
//! against the simpler `Mutex` here. Picking `std::sync::Mutex` (not
//! `tokio::sync::Mutex`) keeps the trait `get` method synchronous, which
//! matches the port contract.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sx_api::port::GraphsageRiskPort;

/// Concrete adapter wrapping the shared cache.
///
/// `pub(crate)` because the composition root constructs it and threads it
/// into [`sx_api::AppState`]; external code reaches it exclusively through
/// the trait object.
#[derive(Debug, Clone)]
pub(crate) struct GraphsageRiskAdapter {
    /// Shared per-asset score cache; the periodic job overwrites the map
    /// wholesale on every tick.
    pub(crate) cache: Arc<Mutex<HashMap<String, f64>>>,
}

impl GraphsageRiskAdapter {
    /// Build a fresh adapter around `cache`.
    pub(crate) const fn new(cache: Arc<Mutex<HashMap<String, f64>>>) -> Self {
        Self { cache }
    }
}

impl GraphsageRiskPort for GraphsageRiskAdapter {
    fn get(&self, asset_id: &str) -> Option<f64> {
        // A poisoned mutex means a previous writer panicked mid-update;
        // returning `None` is the safe, non-panicking behaviour and
        // matches the "asset not yet scored" semantic the port already
        // documents.
        let guard = self.cache.lock().ok()?;
        guard.get(asset_id).copied()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn get_returns_none_for_missing_asset() {
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let adapter = GraphsageRiskAdapter::new(Arc::clone(&cache));
        assert!(adapter.get("asset-ghost").is_none());
    }

    #[test]
    fn get_returns_value_after_writer_publishes() {
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let adapter = GraphsageRiskAdapter::new(Arc::clone(&cache));
        {
            let mut guard = cache.lock().unwrap();
            guard.insert("asset-a".to_owned(), 0.42_f64);
        }
        assert_eq!(adapter.get("asset-a"), Some(0.42));
    }

    #[test]
    fn get_set_concurrent_safe_across_threads() {
        // Hammer the cache from many writers + one reader and confirm we
        // never panic and the final state is consistent.
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let adapter = GraphsageRiskAdapter::new(Arc::clone(&cache));

        let mut handles = Vec::with_capacity(8);
        for i in 0..8_u32 {
            let c = Arc::clone(&cache);
            let h = std::thread::spawn(move || {
                for j in 0..32_u32 {
                    let key = format!("asset-{i}-{j}");
                    let mut guard = c.lock().unwrap();
                    guard.insert(key, f64::from(j));
                }
            });
            handles.push(h);
        }
        for h in handles {
            h.join().expect("writer panic");
        }

        // Spot-check a few keys round-trip.
        assert_eq!(adapter.get("asset-0-0"), Some(0.0));
        assert_eq!(adapter.get("asset-7-31"), Some(31.0));
        assert!(adapter.get("asset-nope").is_none());
    }
}
