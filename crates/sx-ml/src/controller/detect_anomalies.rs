//! Detect-anomalies use case.

use crate::error::MlError;
use crate::model::artifact::{ArtifactKind, ModelArtifact};
use crate::model::feature::FeatureVector;
use crate::model::metrics::ModelMetrics;
use crate::service::anonymiser::Anonymiser;
use crate::service::isolation_forest::IsolationForest;
use crate::service::registry::ModelRegistry;
use std::sync::Arc;
use tracing::info;

/// Tunables for the isolation forest.
#[derive(Debug, Clone, Copy)]
pub struct AnomalyTrainConfig {
    /// How many trees to grow.
    pub n_trees: usize,
    /// Sub-sample size per tree.
    pub sample_size: usize,
    /// Training RNG seed.
    pub seed: u64,
}

impl Default for AnomalyTrainConfig {
    fn default() -> Self {
        Self {
            n_trees: 100,
            sample_size: 256,
            seed: 0,
        }
    }
}

/// Train + register an isolation forest.
#[derive(Debug)]
pub struct TrainAnomaliesUseCase {
    anonymiser: Arc<Anonymiser>,
    registry: Arc<dyn ModelRegistry>,
    model_id: String,
    version: String,
    config: AnomalyTrainConfig,
}

impl TrainAnomaliesUseCase {
    /// Build a new use case.
    #[must_use]
    pub fn new(
        anonymiser: Arc<Anonymiser>,
        registry: Arc<dyn ModelRegistry>,
        model_id: impl Into<String>,
        version: impl Into<String>,
        config: AnomalyTrainConfig,
    ) -> Self {
        Self {
            anonymiser,
            registry,
            model_id: model_id.into(),
            version: version.into(),
            config,
        }
    }

    /// Anonymise + train + register.
    pub async fn execute(&self, rows: Vec<FeatureVector>) -> Result<ModelArtifact, MlError> {
        if rows.is_empty() {
            return Err(MlError::EmptyTrainingSet);
        }
        info!(
            model_id = %self.model_id,
            version = %self.version,
            samples = rows.len(),
            "anomaly training start"
        );
        let anonymised: Vec<FeatureVector> = rows
            .into_iter()
            .map(|r| self.anonymiser.anonymise(r))
            .collect();
        let forest = IsolationForest::train(
            &anonymised,
            self.config.n_trees,
            self.config.sample_size,
            self.config.seed,
        )?;
        let payload = serde_json::to_value(&forest)?;
        #[allow(clippy::cast_possible_truncation)]
        let n_samples_u64 = anonymised.len() as u64;
        let metrics = ModelMetrics {
            samples: n_samples_u64,
            ..ModelMetrics::default()
        };
        let artifact = ModelArtifact::new(
            self.model_id.clone(),
            self.version.clone(),
            ArtifactKind::Anomaly,
            metrics,
            payload,
        );
        self.registry.register(artifact.clone()).await?;
        info!(
            model_id = %self.model_id,
            version = %self.version,
            "anomaly training done"
        );
        Ok(artifact)
    }
}

/// Detect anomalies on a single row by loading the current artifact.
#[derive(Debug)]
pub struct DetectAnomaliesUseCase {
    anonymiser: Arc<Anonymiser>,
    registry: Arc<dyn ModelRegistry>,
}

impl DetectAnomaliesUseCase {
    /// Build a new use case.
    #[must_use]
    pub const fn new(anonymiser: Arc<Anonymiser>, registry: Arc<dyn ModelRegistry>) -> Self {
        Self {
            anonymiser,
            registry,
        }
    }

    /// Return the anomaly score in `[0.0, 1.0]` (higher = more anomalous).
    pub async fn execute(&self, model_id: &str, row: FeatureVector) -> Result<f64, MlError> {
        let artifact = self
            .registry
            .current(model_id)
            .await?
            .ok_or_else(|| MlError::ModelNotFound(model_id.to_string()))?;
        let forest: IsolationForest = serde_json::from_value(artifact.payload)?;
        let anonymised = self.anonymiser.anonymise(row);
        Ok(forest.score(&anonymised))
    }
}
