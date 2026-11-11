//! Tests for `IsolationForest`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::suboptimal_flops,
    clippy::missing_panics_doc
)]

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use sx_ml::prelude::*;

fn row_num(v: f64) -> FeatureVector {
    let mut row = FeatureVector::new();
    row.insert("x".to_string(), FeatureValue::Number(v));
    row
}

/// Sample from N(mean, std) via Box-Muller using a seedable RNG.
fn sample_normal(rng: &mut StdRng, mean: f64, std: f64) -> f64 {
    let u1: f64 = rng.gen_range(f64::EPSILON..1.0);
    let u2: f64 = rng.gen::<f64>();
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    mean + std * z
}

#[test]
fn isolation_forest_anomalous_point_scores_higher_than_normal() {
    let mut rng = StdRng::seed_from_u64(123);
    let mut rows: Vec<FeatureVector> = (0..100)
        .map(|_| row_num(sample_normal(&mut rng, 0.0, 1.0)))
        .collect();
    rows.push(row_num(10.0));
    let forest = IsolationForest::train(&rows, 100, 64, 7).expect("train ok");
    let anomalous = forest.score(&row_num(10.0));
    let normal = forest.score(&row_num(0.0));
    assert!(
        anomalous > normal,
        "anomalous={anomalous} should exceed normal={normal}"
    );
    assert!((0.0..=1.0).contains(&anomalous));
    assert!((0.0..=1.0).contains(&normal));
}

#[test]
fn isolation_forest_seeded_runs_are_deterministic() {
    let rows: Vec<FeatureVector> = (0..50).map(|i| row_num(f64::from(i))).collect();
    let f1 = IsolationForest::train(&rows, 16, 16, 42).expect("train ok");
    let f2 = IsolationForest::train(&rows, 16, 16, 42).expect("train ok");
    assert_eq!(f1, f2);
    let probe = row_num(7.5);
    assert!((f1.score(&probe) - f2.score(&probe)).abs() < 1e-12);
}

/// Round-trip a trained forest through JSON and verify behavioural
/// equivalence. We do NOT use derive-Eq on the whole forest: serde's
/// f64 -> shortest-round-trip-string encoding can produce ULP-level
/// drift on split thresholds (e.g. `9.530211141445335` ↔
/// `9.530211141445337`). That drift is a JSON-precision artefact, not
/// a model-correctness defect: a forest with thresholds that differ by
/// one ULP scores every row identically because the split is still
/// honoured the same way. So we assert (1) the deterministic integer
/// parameters survive verbatim, and (2) scores agree to floating
/// tolerance for a battery of probes.
#[test]
fn isolation_forest_serde_round_trip() {
    let rows: Vec<FeatureVector> = (0..32).map(|i| row_num(f64::from(i))).collect();
    let f = IsolationForest::train(&rows, 8, 16, 1).expect("train ok");
    let json = f.to_json().expect("to_json");
    let restored = IsolationForest::from_json(&json).expect("from_json");

    // Exact-match invariants: shape + deterministic integer fields.
    assert_eq!(f.sample_size, restored.sample_size);
    assert_eq!(f.height_limit, restored.height_limit);
    assert_eq!(f.seed, restored.seed);
    assert_eq!(f.trees.len(), restored.trees.len());

    // Behavioural equivalence: scores agree to floating tolerance for a
    // wide span of probe values (including ones inside and outside the
    // training distribution).
    for i in -4..=36 {
        let probe = row_num(f64::from(i));
        let original = f.score(&probe);
        let after = restored.score(&probe);
        assert!(
            (original - after).abs() < 1e-9,
            "score drift at {i}: original={original} restored={after}"
        );
    }
}
