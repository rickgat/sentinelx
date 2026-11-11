//! Predictive risk-classifier DTOs — `POST /v1/ml/predict/finding`.
//!
//! These views are the wire shapes consumed and produced by the GBDT
//! predictive risk model exposed at `/v1/ml/predict/finding`. The model
//! itself lives in `sx_ml::predictive`; the controller depends only on the
//! [`crate::port::PredictivePort`] trait so the API crate never imports the
//! concrete model.
//!
//! # Risk-band binning
//!
//! The continuous probability emitted by the model is bucketed into one of
//! four ordinal labels for downstream consumption (UI badges, alert
//! prioritisation, SLA timers). The thresholds are inclusive on the lower
//! bound and exclusive on the upper bound:
//!
//! | Band       | Probability range |
//! |------------|-------------------|
//! | `low`      | `[0.00, 0.25)`    |
//! | `medium`   | `[0.25, 0.50)`    |
//! | `high`     | `[0.50, 0.75)`    |
//! | `critical` | `[0.75, 1.00]`    |
//!
//! Non-finite or out-of-range inputs are clamped to `[0, 1]` before
//! binning so the wire surface is always one of the four canonical labels.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /v1/ml/predict/finding` request body.
///
/// `finding_id` is the only required field — the adapter resolves the
/// finding (plus its asset) through the repository port and projects them
/// into the model's `FindingFeatures` shape internally.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct PredictRequest {
    /// Finding uuid to score. Must be a non-empty string; the adapter is
    /// responsible for the stronger uuid + tenant-boundary check.
    #[validate(length(min = 1))]
    pub finding_id: String,
}

/// `POST /v1/ml/predict/finding` response body.
///
/// `probability` is `P(risk_30d = 1)` in `[0, 1]`. `confidence` is the
/// model's self-reported confidence in `[0, 1]` (`2 * |p - 0.5|`).
/// `risk_band` is one of `low`, `medium`, `high`, or `critical` — see the
/// module-level table for the exact thresholds.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PredictResponse {
    /// Modelled probability of risk materialising within 30 days.
    pub probability: f64,
    /// Model self-confidence in `[0, 1]`.
    pub confidence: f64,
    /// Ordinal label derived from `probability`. Always one of
    /// `{low, medium, high, critical}`.
    pub risk_band: String,
}

/// Compute the canonical `risk_band` for a given probability.
///
/// NaN and out-of-range inputs are clamped to `[0, 1]` before bucketing
/// so the return value is always one of the four canonical labels.
#[must_use]
pub fn risk_band(probability: f64) -> &'static str {
    let p = if probability.is_nan() {
        0.0
    } else {
        probability.clamp(0.0, 1.0)
    };
    if p < 0.25 {
        "low"
    } else if p < 0.5 {
        "medium"
    } else if p < 0.75 {
        "high"
    } else {
        "critical"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_requires_non_empty_finding_id() {
        let r = PredictRequest {
            finding_id: String::new(),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn request_accepts_non_empty_finding_id() {
        let r = PredictRequest {
            finding_id: "f0000001-0000-0000-0000-000000000000".into(),
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn risk_band_buckets_four_canonical_probabilities() {
        // <0.25 -> low, <0.5 -> medium, <0.75 -> high, >=0.75 -> critical
        assert_eq!(risk_band(0.10), "low");
        assert_eq!(risk_band(0.30), "medium");
        assert_eq!(risk_band(0.60), "high");
        assert_eq!(risk_band(0.90), "critical");
    }

    #[test]
    fn risk_band_boundaries_are_inclusive_lower() {
        // Lower bound of each band lives in that band.
        assert_eq!(risk_band(0.00), "low");
        assert_eq!(risk_band(0.25), "medium");
        assert_eq!(risk_band(0.50), "high");
        assert_eq!(risk_band(0.75), "critical");
        assert_eq!(risk_band(1.00), "critical");
    }

    #[test]
    fn risk_band_clamps_non_finite_and_out_of_range() {
        assert_eq!(risk_band(f64::NAN), "low");
        assert_eq!(risk_band(-10.0), "low");
        assert_eq!(risk_band(10.0), "critical");
    }

    #[test]
    fn response_serialises_to_canonical_json() {
        let resp = PredictResponse {
            probability: 0.42,
            confidence: 0.16,
            risk_band: "medium".into(),
        };
        let wire = serde_json::to_string(&resp).unwrap();
        assert!(wire.contains("\"probability\""));
        assert!(wire.contains("\"confidence\""));
        assert!(wire.contains("\"risk_band\":\"medium\""));
    }
}
