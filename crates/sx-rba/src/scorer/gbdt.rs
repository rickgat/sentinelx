//! Gradient-boosted decision-tree scorer (HIGH-001).
//!
//! This module is gated behind the `ml-rba` feature flag, default OFF.
//! When enabled it delegates inference to the dependency-free
//! gradient-boosted-tree engine already shipped in `sx-ml`
//! ([`sx_ml::predictive::gbdt::Forest`]) — no ONNX runtime or external ML
//! dependency is pulled in.
//!
//! ## Model artifact
//!
//! The `model_artifact` bytes are a UTF-8 JSON encoding of a
//! [`sx_ml::predictive::gbdt::Forest`] (a stack of regression trees plus a
//! bias term). Train/export the forest offline, then hand the JSON bytes to
//! [`GbdtScorer::new`]. The forest's regression output (a logit) is squashed
//! to the engine's `[0, 100]` risk range with a logistic function.
//!
//! ## Feature projection
//!
//! [`project_features`] maps a [`SignalSnapshot`] into a **fixed-arity, stable
//! order** feature vector. Changing the order or meaning of any slot is a
//! breaking change to the model contract, so the layout is documented inline
//! and asserted by tests. Every feature is in `[0.0, 1.0]`, higher = riskier,
//! with a neutral `0.5` (or signal-specific default) when a signal is absent.
//!
//! ## Fail-closed behaviour
//!
//! If the artifact is missing, not valid JSON, or decodes to an empty forest,
//! the scorer does **not** panic and does **not** silently allow: it returns
//! [`FAIL_CLOSED_SCORE`] (maximum risk) so a deployment that enables `ml-rba`
//! without shipping a usable model forces step-up / block rather than
//! degrading to "allow everything".

use sx_ml::predictive::gbdt::Forest;

use crate::config::RbaConfig;
use crate::scorer::{ScoredSignals, Scorer};
use crate::service::SignalSnapshot;

/// Number of features [`project_features`] emits. The model forest must have
/// been trained against exactly this feature layout.
pub const FEATURE_ARITY: usize = 7;

/// Risk score returned when no usable model is available. Set to the maximum
/// so the scorer fails closed (forces block / step-up), never fail-open.
pub const FAIL_CLOSED_SCORE: i32 = 100;

/// GBDT-based scorer.
#[derive(Debug, Clone)]
pub struct GbdtScorer {
    model_artifact: Vec<u8>,
    /// Parsed forest, or `None` when the artifact is missing / invalid /
    /// empty. `None` makes [`GbdtScorer::score`] fail closed.
    forest: Option<Forest>,
}

impl GbdtScorer {
    /// Build a scorer from the JSON-encoded model artifact. Parsing is done
    /// once here; an unparseable or empty forest leaves the scorer in its
    /// fail-closed state rather than erroring (so composition roots that
    /// enable `ml-rba` still build a usable — if conservative — engine).
    #[must_use]
    pub fn new(model_artifact: Vec<u8>) -> Self {
        let forest = serde_json::from_slice::<Forest>(&model_artifact)
            .ok()
            .filter(|f| !f.is_empty());
        Self {
            model_artifact,
            forest,
        }
    }

    /// Bytes of the underlying model artifact.
    #[must_use]
    pub fn artifact_len(&self) -> usize {
        self.model_artifact.len()
    }

    /// `true` when a usable (non-empty) model forest was loaded.
    #[must_use]
    pub fn has_model(&self) -> bool {
        self.forest.is_some()
    }
}

/// Project a [`SignalSnapshot`] into the fixed `[0.0, 1.0]^FEATURE_ARITY`
/// feature vector the model consumes. Slot order is a stable contract:
///
/// | idx | feature            | 0.0            | 1.0            | absent |
/// |-----|--------------------|----------------|----------------|--------|
/// | 0   | geo mismatch       | same country   | different      | 0.5    |
/// | 1   | login velocity     | 1 attempt      | >= 11 attempts | 0.0    |
/// | 2   | out of hours       | in hours       | out of hours   | 0.5    |
/// | 3   | device risk        | known device   | revoked        | 0.5    |
/// | 4   | MFA staleness      | recent MFA     | stale / never  | 0.5    |
/// | 5   | failure rate       | 100% success   | 0% success     | 0.5    |
/// | 6   | impossible travel  | plausible      | impossible     | 0.3    |
#[must_use]
pub fn project_features(s: &SignalSnapshot) -> [f64; FEATURE_ARITY] {
    use crate::signals::device_fp::DeviceFingerprintStatus;
    use crate::signals::impossible_travel::TravelVerdict;

    // f0 — geo mismatch vs the tenant's anchor country.
    let geo = match (&s.country, &s.home_country) {
        (Some(c), Some(h)) => {
            if c.eq_ignore_ascii_case(h) {
                0.0
            } else {
                1.0
            }
        }
        _ => 0.5,
    };

    // f1 — login velocity in the sliding window, saturating at 11 attempts.
    let velocity = (((s.velocity_window_count.max(1) - 1) as f64) / 10.0).clamp(0.0, 1.0);

    // f2 — outside business hours.
    let off_hours = s
        .business_hours_status
        .map_or(0.5, |b| if b.in_hours { 0.0 } else { 1.0 });

    // f3 — device-fingerprint risk.
    let device = s
        .device_fingerprint
        .as_ref()
        .map_or(0.5, |d| match d.status {
            DeviceFingerprintStatus::Known => 0.0,
            DeviceFingerprintStatus::Unknown => 0.7,
            DeviceFingerprintStatus::Revoked => 1.0,
        });

    // f4 — MFA staleness: recent if the last MFA is within the recency window.
    let mfa = s.mfa_recent.as_ref().map_or(0.5, |m| match m.last_mfa_at {
        Some(last) => {
            let elapsed = (m.observed_at - last).whole_seconds();
            // Future timestamps (clock skew) count as recent.
            if elapsed <= 0 || (elapsed as u64) <= m.recent_window_secs {
                0.0
            } else {
                1.0
            }
        }
        None => 1.0,
    });

    // f5 — rolling failure rate (1 - success rate).
    let failure = s
        .success_rate
        .as_ref()
        .and_then(|sr| sr.rate())
        .map_or(0.5, |rate| (1.0 - rate).clamp(0.0, 1.0));

    // f6 — impossible-travel verdict.
    let travel = s
        .impossible_travel
        .as_ref()
        .map_or(0.3, |t| match t.verdict {
            TravelVerdict::Unknown => 0.3,
            TravelVerdict::Plausible => 0.0,
            TravelVerdict::Suspicious => 0.6,
            TravelVerdict::Impossible => 1.0,
        });

    [geo, velocity, off_hours, device, mfa, failure, travel]
}

/// Squash an unbounded GBDT logit into the engine's `[0, 100]` risk range.
fn logistic_to_score(logit: f64) -> i32 {
    let p = 1.0 / (1.0 + (-logit).exp());
    (p * 100.0).round().clamp(0.0, 100.0) as i32
}

impl Scorer for GbdtScorer {
    fn score(&self, signals: &SignalSnapshot, _cfg: &RbaConfig) -> ScoredSignals {
        let Some(forest) = self.forest.as_ref() else {
            return ScoredSignals {
                score: FAIL_CLOSED_SCORE,
                reason: "gbdt: no usable model artifact — failing closed".to_owned(),
                contributions: Vec::new(),
            };
        };
        let features = project_features(signals);
        let score = logistic_to_score(forest.predict(&features));
        ScoredSignals {
            score,
            reason: format!("gbdt: ensemble score {score} over {FEATURE_ARITY} signals"),
            // A tree ensemble has no per-signal linear decomposition, so the
            // investigator-facing contribution breakdown is intentionally
            // empty for this scorer (unlike the rule-based scorer).
            contributions: Vec::new(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sx_ml::predictive::gbdt::{leaf_pointer, Forest, Split, Tree};

    fn snapshot() -> SignalSnapshot {
        use crate::signals::business_hours::BusinessHoursStatus;
        SignalSnapshot {
            country: Some("US".into()),
            home_country: Some("ID".into()),
            velocity_window_count: 3,
            business_hours_status: Some(BusinessHoursStatus {
                in_hours: false,
                local_hour: 3,
                offset_hours: 0,
            }),
            device_fingerprint: None,
            mfa_recent: None,
            success_rate: None,
            impossible_travel: None,
        }
    }

    #[test]
    fn construct_records_artifact_size() {
        let scorer = GbdtScorer::new(vec![0u8; 16]);
        assert_eq!(scorer.artifact_len(), 16);
    }

    #[test]
    fn empty_or_invalid_artifact_fails_closed() {
        let cfg = RbaConfig::default();
        let snap = snapshot();
        // Invalid bytes.
        let s = GbdtScorer::new(vec![]).score(&snap, &cfg);
        assert_eq!(s.score, FAIL_CLOSED_SCORE);
        // Valid JSON, but an empty forest (no trees).
        let empty = serde_json::to_vec(&Forest::default()).unwrap();
        assert!(!GbdtScorer::new(empty).has_model());
    }

    #[test]
    fn projects_fixed_arity_in_unit_range() {
        let f = project_features(&snapshot());
        assert_eq!(f.len(), FEATURE_ARITY);
        assert!(f.iter().all(|v| (0.0..=1.0).contains(v)));
        // Geo mismatch (US vs ID) and out-of-hours must read as risky.
        assert_eq!(f[0], 1.0);
        assert_eq!(f[2], 1.0);
    }

    #[test]
    fn real_forest_produces_bounded_score() {
        // A single stump: feature[0] <= 0.5 → leaf 0 (logit -2.0),
        // else → leaf 1 (logit +2.0). logistic(+2) > 50.
        let tree = Tree {
            splits: vec![Split::new(0, 0.5, leaf_pointer(0), leaf_pointer(1))],
            leaves: vec![-2.0, 2.0],
        };
        let forest = Forest::from_trees(vec![tree]);
        let artifact = serde_json::to_vec(&forest).unwrap();
        let scorer = GbdtScorer::new(artifact);
        assert!(scorer.has_model());
        let s = scorer.score(&snapshot(), &RbaConfig::default());
        assert!((0..=100).contains(&s.score));
        // geo mismatch = 1.0 > 0.5 → right leaf (+2.0 logit) → score > 50.
        assert!(s.score > 50, "got {}", s.score);
    }
}
