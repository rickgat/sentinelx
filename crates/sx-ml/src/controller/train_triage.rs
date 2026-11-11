//! Train-triage use case: anonymise + train + register.

use crate::error::MlError;
use crate::model::artifact::{ArtifactKind, ModelArtifact};
use crate::model::feature::FeatureVector;
use crate::model::label::Label;
use crate::model::metrics::ModelMetrics;
use crate::service::anonymiser::Anonymiser;
use crate::service::decision_tree::CartTree;
use crate::service::registry::ModelRegistry;
use std::sync::Arc;
use tracing::info;

/// Tunables for triage training.
#[derive(Debug, Clone, Copy)]
pub struct TrainTriageConfig {
    /// Tree maximum depth.
    pub max_depth: u8,
    /// Minimum samples needed to attempt a split.
    pub min_samples_split: usize,
    /// Training RNG seed.
    pub seed: u64,
}

impl Default for TrainTriageConfig {
    fn default() -> Self {
        Self {
            max_depth: 8,
            min_samples_split: 2,
            seed: 0,
        }
    }
}

/// `Train` triage use case.
#[derive(Debug)]
pub struct TrainTriageUseCase {
    anonymiser: Arc<Anonymiser>,
    registry: Arc<dyn ModelRegistry>,
    model_id: String,
    version: String,
    config: TrainTriageConfig,
}

impl TrainTriageUseCase {
    /// Build a new use case.
    #[must_use]
    pub fn new(
        anonymiser: Arc<Anonymiser>,
        registry: Arc<dyn ModelRegistry>,
        model_id: impl Into<String>,
        version: impl Into<String>,
        config: TrainTriageConfig,
    ) -> Self {
        Self {
            anonymiser,
            registry,
            model_id: model_id.into(),
            version: version.into(),
            config,
        }
    }

    /// Anonymise + train + register. Returns the registered artifact.
    pub async fn execute(
        &self,
        rows: Vec<(FeatureVector, Label)>,
    ) -> Result<ModelArtifact, MlError> {
        if rows.is_empty() {
            return Err(MlError::EmptyTrainingSet);
        }
        info!(
            model_id = %self.model_id,
            version = %self.version,
            samples = rows.len(),
            "triage training start"
        );

        let anonymised: Vec<(FeatureVector, Label)> = rows
            .into_iter()
            .map(|(row, lbl)| (self.anonymiser.anonymise(row), lbl))
            .collect();

        let tree = CartTree::train(
            &anonymised,
            self.config.seed,
            self.config.max_depth,
            self.config.min_samples_split,
        )?;

        // Cheap in-sample metrics. Real systems should use a held-out set;
        // this is sufficient as a first signal at registration time.
        let pairs: Vec<(Label, Label)> = anonymised
            .iter()
            .map(|(row, actual)| (tree.predict(row), *actual))
            .collect();
        let metrics = ModelMetrics::from_pairs(&pairs);

        let payload = serde_json::to_value(&tree)?;
        let artifact = ModelArtifact::new(
            self.model_id.clone(),
            self.version.clone(),
            ArtifactKind::Triage,
            metrics,
            payload,
        );
        self.registry.register(artifact.clone()).await?;

        info!(
            model_id = %self.model_id,
            version = %self.version,
            precision = metrics.precision,
            recall = metrics.recall,
            f1 = metrics.f1,
            "triage training done"
        );
        Ok(artifact)
    }
}
