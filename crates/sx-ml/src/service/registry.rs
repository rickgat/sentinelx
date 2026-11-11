//! Model registry trait + an in-memory implementation.

use crate::error::MlError;
use crate::model::artifact::ModelArtifact;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;

/// A registry that stores trained models keyed by `model_id`. Many
/// versions of the same `model_id` may co-exist; `current` returns the
/// most-recently-registered one.
#[async_trait]
pub trait ModelRegistry: Send + Sync + std::fmt::Debug {
    /// Register (or upsert) an artifact.
    async fn register(&self, artifact: ModelArtifact) -> Result<(), MlError>;
    /// Return the latest registered artifact for `model_id`, if any.
    async fn current(&self, model_id: &str) -> Result<Option<ModelArtifact>, MlError>;
    /// Return every artifact for `model_id`, ordered oldest -> newest.
    async fn list_versions(&self, model_id: &str) -> Result<Vec<ModelArtifact>, MlError>;
}

/// In-process implementation of [`ModelRegistry`].
#[derive(Debug, Default)]
pub struct InMemoryModelRegistry {
    inner: Mutex<HashMap<String, Vec<ModelArtifact>>>,
}

impl InMemoryModelRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ModelRegistry for InMemoryModelRegistry {
    async fn register(&self, artifact: ModelArtifact) -> Result<(), MlError> {
        let model_id = artifact.model_id.clone();
        {
            let mut guard = self
                .inner
                .lock()
                .map_err(|_| MlError::Invariant("registry mutex poisoned".into()))?;
            guard.entry(model_id).or_default().push(artifact);
        }
        Ok(())
    }

    async fn current(&self, model_id: &str) -> Result<Option<ModelArtifact>, MlError> {
        let latest = {
            let guard = self
                .inner
                .lock()
                .map_err(|_| MlError::Invariant("registry mutex poisoned".into()))?;
            guard.get(model_id).and_then(|v| v.last().cloned())
        };
        Ok(latest)
    }

    async fn list_versions(&self, model_id: &str) -> Result<Vec<ModelArtifact>, MlError> {
        let versions = {
            let guard = self
                .inner
                .lock()
                .map_err(|_| MlError::Invariant("registry mutex poisoned".into()))?;
            guard.get(model_id).cloned().unwrap_or_default()
        };
        Ok(versions)
    }
}
