//! Persisted model artifact — the registry's unit of storage.

use crate::model::metrics::ModelMetrics;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// What kind of model an artifact wraps. Used by the registry / API so a
/// consumer can quickly tell a triage classifier from an isolation forest.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// A finding-triage CART classifier.
    Triage,
    /// An Isolation-Forest anomaly detector.
    Anomaly,
}

/// A versioned, serialised model + its metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelArtifact {
    /// Unique artifact id (UUID v7 for sortable creation time).
    pub artifact_id: Uuid,
    /// Logical model id — the registry groups artifacts by this id.
    pub model_id: String,
    /// Semver-style version string. Higher version = newer.
    pub version: String,
    /// What kind of model this is.
    pub kind: ArtifactKind,
    /// Creation timestamp.
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Metrics computed at training time.
    pub metrics: ModelMetrics,
    /// The serialised model payload. Opaque JSON blob.
    pub payload: serde_json::Value,
}

impl ModelArtifact {
    /// Construct a new artifact, generating a v7 UUID and stamping the
    /// current time.
    #[must_use]
    pub fn new(
        model_id: impl Into<String>,
        version: impl Into<String>,
        kind: ArtifactKind,
        metrics: ModelMetrics,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            artifact_id: Uuid::now_v7(),
            model_id: model_id.into(),
            version: version.into(),
            kind,
            created_at: OffsetDateTime::now_utc(),
            metrics,
            payload,
        }
    }
}
