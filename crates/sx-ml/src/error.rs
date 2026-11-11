//! Error type for the `sx-ml` crate.

use thiserror::Error;

/// All errors that may surface from `sx-ml`.
#[derive(Debug, Error)]
pub enum MlError {
    /// The caller passed an empty training set.
    #[error("training set is empty")]
    EmptyTrainingSet,

    /// The caller passed an empty feature row (no features at all).
    #[error("feature row is empty")]
    EmptyFeatureRow,

    /// A numeric input was not finite (NaN or +/- inf).
    #[error("non-finite numeric value in feature `{0}`")]
    NonFiniteValue(String),

    /// A required model artifact was not found in the registry.
    #[error("model `{0}` not found in registry")]
    ModelNotFound(String),

    /// A requested configuration value was invalid.
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    /// JSON (de)serialisation failed.
    #[error("serde_json: {0}")]
    Serde(#[from] serde_json::Error),

    /// An invariant of the model itself was violated. Indicates a bug.
    #[error("model invariant violated: {0}")]
    Invariant(String),
}
