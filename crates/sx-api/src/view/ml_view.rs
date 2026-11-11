//! ML triage-prediction DTOs.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /v1/ml/predict/triage` request body.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct MlTriagePredictRequestView {
    /// Registered model identifier.
    #[validate(length(min = 1))]
    pub model_id: String,
    /// Feature row passed through to the model as opaque JSON.
    pub row: serde_json::Value,
}

/// `POST /v1/ml/predict/triage` response body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MlTriagePredictResponseView {
    /// Predicted label: `true_positive`, `false_positive`, or `unknown`.
    pub label: String,
    /// Confidence score in `[0.0, 1.0]`.
    pub probability: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_non_empty_model_id() {
        let r = MlTriagePredictRequestView {
            model_id: String::new(),
            row: serde_json::json!({}),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn accepts_valid_request() {
        let r = MlTriagePredictRequestView {
            model_id: "triage-v1".into(),
            row: serde_json::json!({"severity": "high"}),
        };
        assert!(r.validate().is_ok());
    }
}
