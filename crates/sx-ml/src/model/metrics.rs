//! Classification metrics: precision, recall, F1, with a binary confusion
//! matrix.

use crate::model::label::Label;
use serde::{Deserialize, Serialize};

/// Binary confusion matrix where the positive class is
/// [`Label::FalsePositive`].
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfusionMatrix {
    /// Predicted `FalsePositive`, actual `FalsePositive`.
    pub true_positives: u64,
    /// Predicted `FalsePositive`, actual `TruePositive`.
    pub false_positives: u64,
    /// Predicted `TruePositive`, actual `FalsePositive`.
    pub false_negatives: u64,
    /// Predicted `TruePositive`, actual `TruePositive`.
    pub true_negatives: u64,
}

impl ConfusionMatrix {
    /// Build a confusion matrix from paired (predicted, actual) labels.
    ///
    /// `Label::Unknown` rows are skipped.
    #[must_use]
    pub fn from_pairs(pairs: &[(Label, Label)]) -> Self {
        let mut cm = Self::default();
        for &(pred, actual) in pairs {
            match (pred, actual) {
                (Label::FalsePositive, Label::FalsePositive) => cm.true_positives += 1,
                (Label::FalsePositive, Label::TruePositive) => cm.false_positives += 1,
                (Label::TruePositive, Label::FalsePositive) => cm.false_negatives += 1,
                (Label::TruePositive, Label::TruePositive) => cm.true_negatives += 1,
                _ => {}
            }
        }
        cm
    }

    /// Total number of labelled samples reflected in this matrix.
    #[must_use]
    pub const fn samples(&self) -> u64 {
        self.true_positives + self.false_positives + self.false_negatives + self.true_negatives
    }
}

/// Aggregate classification metrics.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub struct ModelMetrics {
    /// Precision = TP / (TP + FP).
    pub precision: f64,
    /// Recall = TP / (TP + FN).
    pub recall: f64,
    /// F1 = 2 * P * R / (P + R).
    pub f1: f64,
    /// Total samples used to compute these metrics.
    pub samples: u64,
}

impl ModelMetrics {
    /// Compute metrics from a confusion matrix.
    ///
    /// When the denominator of either precision or recall is zero, the
    /// corresponding metric is reported as `0.0`. F1 is consequently `0.0`
    /// whenever either precision or recall is zero.
    #[must_use]
    pub fn from_confusion_matrix(cm: &ConfusionMatrix) -> Self {
        let tp = f64::from(u32::try_from(cm.true_positives).unwrap_or(u32::MAX));
        let fp = f64::from(u32::try_from(cm.false_positives).unwrap_or(u32::MAX));
        let fn_ = f64::from(u32::try_from(cm.false_negatives).unwrap_or(u32::MAX));
        let precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
        let recall = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
        let f1 = if precision > 0.0 && recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };
        Self {
            precision,
            recall,
            f1,
            samples: cm.samples(),
        }
    }

    /// Convenience constructor from raw (predicted, actual) pairs.
    #[must_use]
    pub fn from_pairs(pairs: &[(Label, Label)]) -> Self {
        Self::from_confusion_matrix(&ConfusionMatrix::from_pairs(pairs))
    }
}
