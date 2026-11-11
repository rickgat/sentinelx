//! End-to-end predictive risk model: scaler + forest + sigmoid.
//!
//! Wraps a [`Forest`] together with a [`FeatureScaler`] so callers can
//! drive inference from a structured [`FindingFeatures`] in a single
//! call. JSON round-trip is supported via `serde` so trained models can
//! be loaded from disk without code changes.

use serde::{Deserialize, Serialize};

use crate::error::MlError;

use super::features::{FindingFeatures, FEATURE_SCHEMA_VERSION, FEATURE_VECTOR_LEN};
use super::gbdt::Forest;

/// Per-feature mean / standard-deviation table used for z-score
/// normalisation.
///
/// Both vectors are expected to be exactly [`FEATURE_VECTOR_LEN`] long.
/// A scaler with empty `mean` and `std` is a no-op (identity transform)
/// — useful for ad-hoc tests and the uninformative-prior path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FeatureScaler {
    /// Per-feature mean.
    #[serde(default)]
    pub mean: Vec<f64>,
    /// Per-feature standard deviation. Slots `<= 0` (i.e. constant
    /// columns) are treated as `1.0` so dividing by zero is impossible.
    #[serde(default)]
    pub std: Vec<f64>,
}

impl FeatureScaler {
    /// Identity scaler — passes features through unmodified.
    #[must_use]
    pub const fn identity() -> Self {
        Self {
            mean: Vec::new(),
            std: Vec::new(),
        }
    }

    /// Build a scaler from explicit `mean` / `std` vectors.
    ///
    /// The vectors must either both be empty (identity) or both be
    /// [`FEATURE_VECTOR_LEN`] long.
    pub fn new(mean: Vec<f64>, std: Vec<f64>) -> Result<Self, MlError> {
        if mean.is_empty() && std.is_empty() {
            return Ok(Self::identity());
        }
        if mean.len() != FEATURE_VECTOR_LEN || std.len() != FEATURE_VECTOR_LEN {
            return Err(MlError::InvalidConfig(format!(
                "scaler mean/std must each be {FEATURE_VECTOR_LEN} long",
            )));
        }
        if mean.iter().any(|v| !v.is_finite()) || std.iter().any(|v| !v.is_finite()) {
            return Err(MlError::Invariant(
                "scaler mean/std entries must be finite".into(),
            ));
        }
        Ok(Self { mean, std })
    }

    /// Apply z-score normalisation in place to a fixed-length feature
    /// vector. NaN / infinite inputs are clamped to zero so downstream
    /// inference stays total.
    #[must_use]
    pub fn transform(&self, features: &[f64; FEATURE_VECTOR_LEN]) -> [f64; FEATURE_VECTOR_LEN] {
        let mut out = *features;
        for (idx, slot) in out.iter_mut().enumerate() {
            if !slot.is_finite() {
                *slot = 0.0;
            }
            if self.mean.is_empty() || self.std.is_empty() {
                continue;
            }
            let mean = self.mean.get(idx).copied().unwrap_or(0.0);
            let std = self.std.get(idx).copied().unwrap_or(1.0);
            let denom = if std.is_finite() && std > f64::EPSILON {
                std
            } else {
                1.0
            };
            *slot = (*slot - mean) / denom;
        }
        out
    }
}

/// Probability-of-risk prediction emitted by [`PredictiveModel::predict`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RiskPrediction {
    /// `P(risk_30d = 1)` in `[0, 1]`.
    pub probability: f64,
    /// Confidence in the prediction in `[0, 1]`.
    ///
    /// Computed as `2 * |probability - 0.5|` so a `0.5` output gives the
    /// minimum confidence (`0.0`) and outputs near the extremes give the
    /// maximum (`1.0`).
    pub confidence: f64,
}

/// End-to-end model: feature scaler + GBDT forest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PredictiveModel {
    /// Feature-schema version this model was trained against. Defaults to
    /// the current [`FEATURE_SCHEMA_VERSION`] when a (legacy) artifact
    /// omits it; [`Self::from_json`] rejects any explicit mismatch so a
    /// model never scores against a layout it was not trained for.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// GBDT forest. An empty forest yields the `0.5` prior.
    #[serde(default)]
    pub forest: Forest,
    /// Z-score scaler applied before forest inference.
    #[serde(default)]
    pub scaler: FeatureScaler,
}

/// Serde default for [`PredictiveModel::schema_version`].
const fn default_schema_version() -> u32 {
    FEATURE_SCHEMA_VERSION
}

impl Default for PredictiveModel {
    fn default() -> Self {
        Self {
            schema_version: FEATURE_SCHEMA_VERSION,
            forest: Forest::default(),
            scaler: FeatureScaler::default(),
        }
    }
}

impl PredictiveModel {
    /// Build a model from its component parts, tagged with the current
    /// feature-schema version.
    #[must_use]
    pub const fn new(forest: Forest, scaler: FeatureScaler) -> Self {
        Self {
            schema_version: FEATURE_SCHEMA_VERSION,
            forest,
            scaler,
        }
    }

    /// Run end-to-end inference on a structured feature record.
    #[must_use]
    pub fn predict(&self, features: &FindingFeatures) -> RiskPrediction {
        let raw = features.to_vector();
        let scaled = self.scaler.transform(&raw);
        let score = self.forest.predict(&scaled);
        let probability = sigmoid(score);
        let confidence = ((probability - 0.5).abs() * 2.0).clamp(0.0, 1.0);
        RiskPrediction {
            probability,
            confidence,
        }
    }

    /// Serialise the model to JSON.
    pub fn to_json(&self) -> Result<String, MlError> {
        Ok(serde_json::to_string(self)?)
    }

    /// Load a model from JSON, rejecting an artifact whose
    /// `schema_version` does not match the feature schema this build was
    /// compiled against.
    pub fn from_json(json: &str) -> Result<Self, MlError> {
        let model: Self = serde_json::from_str(json)?;
        if model.schema_version != FEATURE_SCHEMA_VERSION {
            return Err(MlError::InvalidConfig(format!(
                "model feature-schema version {} != loader version {FEATURE_SCHEMA_VERSION}; \
                 retrain against the current feature layout",
                model.schema_version,
            )));
        }
        Ok(model)
    }
}

fn sigmoid(x: f64) -> f64 {
    if !x.is_finite() {
        return if x.is_sign_positive() { 1.0 } else { 0.0 };
    }
    // Numerically stable sigmoid: avoid `exp` overflow for large |x|.
    if x >= 0.0 {
        let z = (-x).exp();
        1.0 / (1.0 + z)
    } else {
        let z = x.exp();
        z / (1.0 + z)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::super::features::{AssetKindEnum, SeverityEnum};
    use super::*;

    fn features(cvss: f64, kev: bool) -> FindingFeatures {
        FindingFeatures {
            cvss,
            epss: 0.5,
            kev_flag: if kev { 1.0 } else { 0.0 },
            days_since_first_seen: 1.0,
            severity: SeverityEnum::High,
            asset_kind: AssetKindEnum::Host,
            business_impact: 1.0,
            chain_amplifier: 1.0,
        }
    }

    #[test]
    fn empty_model_returns_0_5_probability() {
        let model = PredictiveModel::default();
        let pred = model.predict(&features(7.0, false));
        assert!((pred.probability - 0.5).abs() < f64::EPSILON);
        assert!((pred.confidence - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn sigmoid_handles_extreme_inputs() {
        assert!((sigmoid(f64::INFINITY) - 1.0).abs() < f64::EPSILON);
        assert!(sigmoid(f64::NEG_INFINITY).abs() < f64::EPSILON);
        assert!((sigmoid(0.0) - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn default_and_new_tag_current_schema_version() {
        assert_eq!(
            PredictiveModel::default().schema_version,
            FEATURE_SCHEMA_VERSION
        );
        assert_eq!(
            PredictiveModel::new(Forest::default(), FeatureScaler::identity()).schema_version,
            FEATURE_SCHEMA_VERSION
        );
    }

    #[test]
    fn legacy_artifact_without_version_loads_as_current() {
        // No schema_version field -> serde default -> current -> accepted.
        let json = r#"{"forest":{"trees":[],"bias":0.0},"scaler":{"mean":[],"std":[]}}"#;
        let model = PredictiveModel::from_json(json).expect("legacy artifact loads");
        assert_eq!(model.schema_version, FEATURE_SCHEMA_VERSION);
    }

    #[test]
    fn mismatched_schema_version_is_rejected() {
        let json = r#"{"schema_version":999,"forest":{"trees":[],"bias":0.0},"scaler":{"mean":[],"std":[]}}"#;
        let err = PredictiveModel::from_json(json).expect_err("version mismatch must reject");
        assert!(matches!(err, MlError::InvalidConfig(_)));
    }

    #[test]
    fn round_trip_preserves_version() {
        let model = PredictiveModel::default();
        let json = model.to_json().unwrap();
        assert!(json.contains("schema_version"));
        let back = PredictiveModel::from_json(&json).unwrap();
        assert_eq!(back.schema_version, FEATURE_SCHEMA_VERSION);
    }
}
