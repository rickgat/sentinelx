//! Tests for `CartTree`.

// Integration tests: `expect` on Result is a deliberate assertion style.
#![allow(clippy::expect_used)]

use sx_ml::prelude::*;
use sx_ml::service::decision_tree::tree_depth;

fn row_num(name: &str, v: f64) -> (String, FeatureValue) {
    (name.to_string(), FeatureValue::Number(v))
}

fn make_row(features: Vec<(String, FeatureValue)>) -> FeatureVector {
    let mut row = FeatureVector::new();
    for (k, v) in features {
        row.insert(k, v);
    }
    row
}

#[test]
fn cart_tree_perfect_split_predicts_correctly() {
    // Two-feature linearly separable dataset on the `severity` axis.
    let mut samples = Vec::new();
    for v in [0.1_f64, 0.2, 0.3, 0.4] {
        samples.push((
            make_row(vec![row_num("severity", v), row_num("noise", 1.0)]),
            Label::TruePositive,
        ));
    }
    for v in [0.8_f64, 0.9, 1.0, 1.1] {
        samples.push((
            make_row(vec![row_num("severity", v), row_num("noise", 1.0)]),
            Label::FalsePositive,
        ));
    }
    let tree = CartTree::train(&samples, 42, 4, 2).expect("train ok");
    assert_eq!(
        tree.predict(&make_row(vec![row_num("severity", 0.15)])),
        Label::TruePositive
    );
    assert_eq!(
        tree.predict(&make_row(vec![row_num("severity", 1.0)])),
        Label::FalsePositive
    );
}

#[test]
fn cart_tree_respects_max_depth() {
    // Force more splits than depth allows.
    let mut samples = Vec::new();
    for i in 0..32 {
        let v = f64::from(i);
        let lbl = if i % 2 == 0 {
            Label::TruePositive
        } else {
            Label::FalsePositive
        };
        samples.push((make_row(vec![row_num("x", v)]), lbl));
    }
    let tree = CartTree::train(&samples, 7, 2, 2).expect("train ok");
    let depth = tree_depth(&tree.root);
    assert!(depth <= 2, "depth {depth} should be <= 2");
}

#[test]
fn cart_tree_predict_proba_in_unit_interval() {
    let mut samples = Vec::new();
    for i in 0..20 {
        let v = f64::from(i);
        let lbl = if i < 10 {
            Label::TruePositive
        } else {
            Label::FalsePositive
        };
        samples.push((make_row(vec![row_num("x", v)]), lbl));
    }
    let tree = CartTree::train(&samples, 1, 4, 2).expect("train ok");
    for i in 0..50 {
        let row = make_row(vec![row_num("x", f64::from(i) * 0.5)]);
        let p = tree.predict_proba(&row);
        assert!(
            (0.0..=1.0).contains(&p),
            "p={p} should be in [0,1] for i={i}"
        );
    }
}

#[test]
fn cart_tree_serde_round_trip() {
    let mut samples = Vec::new();
    for i in 0..16 {
        let v = f64::from(i);
        let lbl = if i < 8 {
            Label::TruePositive
        } else {
            Label::FalsePositive
        };
        samples.push((make_row(vec![row_num("x", v)]), lbl));
    }
    let tree = CartTree::train(&samples, 0, 3, 2).expect("train ok");
    let json = tree.to_json().expect("to_json");
    let restored = CartTree::from_json(&json).expect("from_json");
    assert_eq!(tree, restored);
    let row = make_row(vec![row_num("x", 12.0)]);
    assert_eq!(tree.predict(&row), restored.predict(&row));
}
