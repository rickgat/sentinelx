//! Risk scorers.
//!
//! The MVP ships a single rule-based implementation
//! ([`rule_based::RuleBasedScorer`]). Production deployments can
//! swap in a richer model later by implementing the [`Scorer`] trait.
//!
//! The optional `ml-rba` feature unlocks the [`gbdt::GbdtScorer`]
//! skeleton (HIGH-001), reserved for the next sprint.

pub mod rule_based;

#[cfg(feature = "ml-rba")]
pub mod gbdt;

use serde::{Deserialize, Serialize};

use crate::config::RbaConfig;
use crate::service::SignalSnapshot;
use crate::signals::SignalKind;

/// A scorer takes the bundle of collected signals and a configuration
/// and returns the composite 0-100 risk score plus a free-form
/// human-readable reason string.
pub trait Scorer: Send + Sync + std::fmt::Debug {
    /// Compute the risk score for `signals` under `cfg`.
    fn score(&self, signals: &SignalSnapshot, cfg: &RbaConfig) -> ScoredSignals;
}

/// Output of a [`Scorer`] call.
#[derive(Debug, Clone)]
pub struct ScoredSignals {
    /// Composite score, clamped to `[0, 100]`.
    pub score: i32,
    /// Human-readable reason summarising the dominant signal.
    pub reason: String,
    /// Per-signal contributions to the composite score (LOW-007).
    ///
    /// Each enabled signal contributes one [`SignalContribution`] row;
    /// disabled signals are excluded entirely (not included with weight
    /// `0.0`). The list is intended for investigator-side
    /// reconstruction: `weighted = sub_score * weight` so an analyst can
    /// see which signal "voted what" without re-running the scorer.
    pub contributions: Vec<SignalContribution>,
}

/// One row in the per-signal breakdown of a composite RBA decision
/// (LOW-007). Persisted into the `signal_contributions` JSONB column on
/// `rba_decisions` and exposed via the admin-gated decision-audit view.
///
/// ## Field semantics
///
/// * `signal` — stable enum identifier for the signal that produced
///   `sub_score`. Serialised using the same `snake_case` strings as
///   [`SignalKind::as_str`] so JSONB rows stay diffable.
/// * `sub_score` — the raw `[0, 100]` value the signal emitted.
/// * `weight` — the per-tenant weight applied to `sub_score` when
///   computing the composite.
/// * `weighted` — `sub_score * weight`. Stored verbatim so the
///   investigator does not have to multiply by hand and so a future
///   change to weight handling (e.g. signed weights) does not silently
///   break old audit rows.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SignalContribution {
    /// Which signal produced this row.
    pub signal: SignalKind,
    /// Raw `[0, 100]` sub-score emitted by the signal.
    pub sub_score: i32,
    /// Per-tenant weight applied to `sub_score`.
    pub weight: f64,
    /// `sub_score * weight` — the weighted contribution to the
    /// composite. Stored so investigators do not have to recompute.
    pub weighted: f64,
}

impl SignalContribution {
    /// Construct a contribution row, computing `weighted` internally.
    #[must_use]
    pub fn new(signal: SignalKind, sub_score: i32, weight: f64) -> Self {
        Self {
            signal,
            sub_score,
            weight,
            weighted: f64::from(sub_score) * weight,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn signal_contribution_serializes_to_snake_case_signal_label() {
        // LOW-007: the JSONB shape persisted in `rba_decisions.signal_contributions`
        // uses the same snake_case strings as the existing `signals` map.
        // Pin every variant so a future rename is caught here rather than
        // by an angry SOC analyst comparing old and new audit rows.
        for (kind, expected) in [
            (SignalKind::IpGeo, "ip_geo"),
            (SignalKind::Velocity, "velocity"),
            (SignalKind::BusinessHours, "business_hours"),
            (SignalKind::DeviceFingerprint, "device_fp"),
            (SignalKind::MfaRecent, "mfa_recent"),
            (SignalKind::SuccessRate, "success_rate"),
            (SignalKind::ImpossibleTravel, "impossible_travel"),
        ] {
            let c = SignalContribution::new(kind, 80, 0.25);
            let json = serde_json::to_value(c).unwrap();
            assert_eq!(json["signal"], expected);
            assert_eq!(json["sub_score"], 80);
            assert!((json["weight"].as_f64().unwrap() - 0.25).abs() < 1e-9);
            assert!((json["weighted"].as_f64().unwrap() - 20.0).abs() < 1e-9);
        }
    }

    #[test]
    fn signal_contribution_round_trips_through_serde_json() {
        // Investigator workflow: pull the JSONB column, deserialise
        // it back into the engine type, then replay assertions. The
        // round-trip must be lossless.
        let original = SignalContribution::new(SignalKind::ImpossibleTravel, 100, 0.15);
        let raw = serde_json::to_string(&original).unwrap();
        let back: SignalContribution = serde_json::from_str(&raw).unwrap();
        assert_eq!(back, original);
        // weighted is computed at construction; round-tripping
        // preserves the persisted value rather than recomputing — that
        // way an old row with stale arithmetic stays auditable.
        assert!((back.weighted - 15.0).abs() < 1e-9);
    }

    #[test]
    fn signal_contribution_new_is_pure() {
        // Defensive: constructing a contribution must never panic on
        // out-of-range sub_score or weight values. The engine clamps
        // upstream, but we want the audit type itself to be total.
        let c = SignalContribution::new(SignalKind::Velocity, -10, 0.0);
        assert_eq!(c.weighted, 0.0);
        let c = SignalContribution::new(SignalKind::Velocity, 100, 1.5);
        assert!((c.weighted - 150.0).abs() < 1e-9);
    }
}
