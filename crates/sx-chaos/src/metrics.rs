//! Metric helpers for the chaos crate.

use metrics::counter;

/// Counter name for chaos injections.
pub const METRIC_CHAOS_INJECTIONS: &str = "sx_chaos_injections_total";

/// Outcome label for "no fault injected".
pub const OUTCOME_PASS: &str = "pass";
/// Outcome label for "latency injected".
pub const OUTCOME_LATENCY: &str = "latency";
/// Outcome label for "error response synthesised".
pub const OUTCOME_ERROR: &str = "error";
/// Outcome label for "dependency unavailable injected".
pub const OUTCOME_DEPENDENCY_UNAVAILABLE: &str = "dependency_unavailable";
/// Outcome label for "dependency timeout injected".
pub const OUTCOME_DEPENDENCY_TIMEOUT: &str = "dependency_timeout";

/// Record one injection decision against the
/// `sx_chaos_injections_total{kind,outcome}` counter.
pub fn record_injection(kind: &str, outcome: &str) {
    counter!(
        METRIC_CHAOS_INJECTIONS,
        "kind" => kind.to_owned(),
        "outcome" => outcome.to_owned(),
    )
    .increment(1);
}
