//! Input record for the triage classifier.

use crate::model::feature::FeatureVector;
use crate::model::label::Label;
use serde::{Deserialize, Serialize};

/// A single training row for the finding-triage classifier.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TriageInput {
    /// The feature vector (may still contain PII — the use case will
    /// anonymise it before training).
    pub features: FeatureVector,
    /// The supervised label for this row.
    pub label: Label,
}

impl TriageInput {
    /// Builder.
    #[must_use]
    pub const fn new(features: FeatureVector, label: Label) -> Self {
        Self { features, label }
    }
}
