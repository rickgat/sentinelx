//! Tests for `ModelMetrics`.

use sx_ml::model::metrics::{ConfusionMatrix, ModelMetrics};
use sx_ml::prelude::*;

#[test]
fn metrics_precision_recall_known_confusion_matrix() {
    let cm = ConfusionMatrix {
        true_positives: 8,
        false_positives: 2,
        false_negatives: 2,
        true_negatives: 8,
    };
    let m = ModelMetrics::from_confusion_matrix(&cm);
    assert!((m.precision - 0.8).abs() < 1e-9);
    assert!((m.recall - 0.8).abs() < 1e-9);
    assert!((m.f1 - 0.8).abs() < 1e-9);
    assert_eq!(m.samples, 20);
}

#[test]
fn metrics_f1_zero_when_precision_zero() {
    // Predicted 0 positives, so precision is undefined → 0; F1 is 0.
    let cm = ConfusionMatrix {
        true_positives: 0,
        false_positives: 0,
        false_negatives: 5,
        true_negatives: 5,
    };
    let m = ModelMetrics::from_confusion_matrix(&cm);
    assert!(m.precision.abs() < 1e-9);
    assert!(m.f1.abs() < 1e-9);
}

#[test]
fn metrics_from_pairs_skips_unknown() {
    let pairs = vec![
        (Label::FalsePositive, Label::FalsePositive),
        (Label::TruePositive, Label::TruePositive),
        (Label::Unknown, Label::FalsePositive),
    ];
    let m = ModelMetrics::from_pairs(&pairs);
    assert_eq!(m.samples, 2);
}
