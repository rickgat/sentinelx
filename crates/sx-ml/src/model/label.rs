//! Triage label for a [`crate::model::feature::FeatureVector`].

use serde::{Deserialize, Serialize};

/// Outcome label for a finding.
///
/// `FalsePositive` is the positive class for the
/// [`crate::service::decision_tree::CartTree`] classifier — that is, the
/// `predict_proba` method returns `P(label = FalsePositive)`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Label {
    /// The finding is a true positive (a real vulnerability).
    TruePositive,
    /// The finding is a false positive (noise).
    FalsePositive,
    /// The finding has not been triaged yet.
    Unknown,
}

impl Label {
    /// Returns `true` when this label is `FalsePositive`.
    #[must_use]
    pub const fn is_false_positive(self) -> bool {
        matches!(self, Self::FalsePositive)
    }

    /// Returns `true` when this label is `TruePositive`.
    #[must_use]
    pub const fn is_true_positive(self) -> bool {
        matches!(self, Self::TruePositive)
    }
}
