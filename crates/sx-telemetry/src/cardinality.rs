//! Process-wide cardinality cap for high-fanout label sets.
//!
//! The Prometheus exporter itself does not cap series count; an
//! attacker (or a buggy caller) that emits an unbounded `tenant_id`
//! label space can blow up the scrape and OOM the recorder. This module
//! ships a tiny `Arc<DashSet>` shared between call sites that records
//! a stable `(metric, label_value)` key on every emission and refuses
//! to admit new keys once a per-metric cap is reached.
//!
//! ## Usage
//!
//! ```ignore
//! use sx_telemetry::cardinality::{MetricSeriesGuard, GuardOutcome};
//!
//! let guard = MetricSeriesGuard::new(1_000);
//! let outcome = guard.admit("rba_signal_fired_total", "tenant=abc");
//! match outcome {
//!     GuardOutcome::Admit => metrics::counter!(/* ... */).increment(1),
//!     GuardOutcome::Drop => { /* drop silently; the registry already
//!                                emitted at-cap series in earlier scrapes */ }
//! }
//! ```
//!
//! The guard is **not** transactional — once a `(metric, label_value)`
//! is admitted it stays admitted for the lifetime of the process. This
//! mirrors how Prometheus itself behaves: the cost of a label-value
//! is the series, not the scrape, so once you've paid for it you
//! amortise.

use std::sync::Arc;

use dashmap::{DashMap, DashSet};

/// Outcome of a `MetricSeriesGuard::admit` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardOutcome {
    /// Caller MAY emit the underlying metric — the series is either
    /// already admitted or has just been admitted under the cap.
    Admit,
    /// Caller MUST NOT emit the underlying metric — admitting it would
    /// breach the per-metric cap.
    Drop,
}

/// Process-wide cardinality cap.
///
/// One guard handles every metric the process emits. The cap is
/// **per metric name**, not global — a process that wants `1_000`
/// distinct `tenant_id` values on `rba_signal_fired_total` AND on
/// `rba_decision_total` uses a single guard with `cap = 1_000`.
///
/// Cheap to clone (`Arc<DashMap>`-backed).
#[derive(Debug, Clone)]
pub struct MetricSeriesGuard {
    inner: Arc<MetricSeriesGuardInner>,
}

#[derive(Debug)]
struct MetricSeriesGuardInner {
    cap: usize,
    admitted: DashMap<&'static str, DashSet<String>>,
}

impl MetricSeriesGuard {
    /// Build a guard with the supplied per-metric series cap.
    ///
    /// A cap of `0` admits every series (effectively disables the
    /// guard) — useful for tests that want to bypass the cap without
    /// constructing the parameters needed by a real recorder.
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Arc::new(MetricSeriesGuardInner {
                cap,
                admitted: DashMap::new(),
            }),
        }
    }

    /// Per-metric series cap configured at construction. `0` means the
    /// cap is disabled.
    #[must_use]
    pub fn cap(&self) -> usize {
        self.inner.cap
    }

    /// Check whether `metric, label_value` may be emitted. The
    /// label-value string is opaque to the guard — callers concatenate
    /// the volatile labels (e.g. `tenant_id`) into a single hashable
    /// key. Static labels (e.g. `signal`, `bucket`) are part of the
    /// metric name from the guard's perspective and need not be
    /// included.
    ///
    /// Reads against an already-admitted key never take the write lock.
    pub fn admit(&self, metric: &'static str, label_value: &str) -> GuardOutcome {
        if self.inner.cap == 0 {
            return GuardOutcome::Admit;
        }

        let set = self.inner.admitted.entry(metric).or_default();
        if set.contains(label_value) {
            return GuardOutcome::Admit;
        }
        if set.len() >= self.inner.cap {
            return GuardOutcome::Drop;
        }
        set.insert(label_value.to_owned());
        GuardOutcome::Admit
    }

    /// Total admitted-series count for `metric`. Useful for tests and
    /// admin endpoints; not on the hot path.
    #[must_use]
    pub fn admitted_count(&self, metric: &'static str) -> usize {
        self.inner
            .admitted
            .get(metric)
            .map_or(0, |s| s.value().len())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn zero_cap_admits_everything() {
        let g = MetricSeriesGuard::new(0);
        for i in 0..10_000 {
            assert_eq!(g.admit("m", &format!("t{i}")), GuardOutcome::Admit);
        }
    }

    #[test]
    fn admits_up_to_cap_then_drops() {
        let g = MetricSeriesGuard::new(3);
        assert_eq!(g.admit("m", "a"), GuardOutcome::Admit);
        assert_eq!(g.admit("m", "b"), GuardOutcome::Admit);
        assert_eq!(g.admit("m", "c"), GuardOutcome::Admit);
        // Fourth distinct value crosses the cap.
        assert_eq!(g.admit("m", "d"), GuardOutcome::Drop);
        // Re-admitting an existing one still works.
        assert_eq!(g.admit("m", "a"), GuardOutcome::Admit);
        assert_eq!(g.admitted_count("m"), 3);
    }

    #[test]
    fn cap_is_per_metric_not_global() {
        let g = MetricSeriesGuard::new(2);
        assert_eq!(g.admit("m1", "a"), GuardOutcome::Admit);
        assert_eq!(g.admit("m1", "b"), GuardOutcome::Admit);
        assert_eq!(g.admit("m1", "c"), GuardOutcome::Drop);
        // m2 has its own budget.
        assert_eq!(g.admit("m2", "x"), GuardOutcome::Admit);
        assert_eq!(g.admit("m2", "y"), GuardOutcome::Admit);
        assert_eq!(g.admit("m2", "z"), GuardOutcome::Drop);
    }

    #[test]
    fn guard_is_cheap_to_clone() {
        let g1 = MetricSeriesGuard::new(2);
        let g2 = g1.clone();
        assert_eq!(g1.admit("m", "a"), GuardOutcome::Admit);
        assert_eq!(g2.admit("m", "b"), GuardOutcome::Admit);
        assert_eq!(g1.admit("m", "c"), GuardOutcome::Drop);
        // Both handles see the same admitted set.
        assert_eq!(g1.admitted_count("m"), 2);
        assert_eq!(g2.admitted_count("m"), 2);
    }

    #[test]
    fn readmit_is_cheap_and_idempotent() {
        let g = MetricSeriesGuard::new(1);
        assert_eq!(g.admit("m", "only"), GuardOutcome::Admit);
        for _ in 0..1_000 {
            assert_eq!(g.admit("m", "only"), GuardOutcome::Admit);
        }
        assert_eq!(g.admitted_count("m"), 1);
    }
}
