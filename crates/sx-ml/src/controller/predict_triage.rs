//! Predict-triage use case: load current artifact + predict.

use crate::error::MlError;
use crate::model::feature::FeatureVector;
use crate::model::label::Label;
use crate::service::anonymiser::Anonymiser;
use crate::service::decision_tree::CartTree;
use crate::service::registry::ModelRegistry;
use std::sync::Arc;

/// Predict use case.
#[derive(Debug)]
pub struct PredictTriageUseCase {
    anonymiser: Arc<Anonymiser>,
    registry: Arc<dyn ModelRegistry>,
}

impl PredictTriageUseCase {
    /// Build a new use case.
    #[must_use]
    pub const fn new(anonymiser: Arc<Anonymiser>, registry: Arc<dyn ModelRegistry>) -> Self {
        Self {
            anonymiser,
            registry,
        }
    }

    /// Load the current artifact for `model_id` and predict on `row`.
    pub async fn execute(&self, model_id: &str, row: FeatureVector) -> Result<Label, MlError> {
        let artifact = self
            .registry
            .current(model_id)
            .await?
            .ok_or_else(|| MlError::ModelNotFound(model_id.to_string()))?;
        let tree: CartTree = serde_json::from_value(artifact.payload)?;
        let anonymised = self.anonymiser.anonymise(row);
        Ok(tree.predict(&anonymised))
    }

    /// Same as [`Self::execute`] but returns the soft probability of
    /// `FalsePositive`.
    pub async fn execute_proba(&self, model_id: &str, row: FeatureVector) -> Result<f64, MlError> {
        let artifact = self
            .registry
            .current(model_id)
            .await?
            .ok_or_else(|| MlError::ModelNotFound(model_id.to_string()))?;
        let tree: CartTree = serde_json::from_value(artifact.payload)?;
        let anonymised = self.anonymiser.anonymise(row);
        Ok(tree.predict_proba(&anonymised))
    }
}
