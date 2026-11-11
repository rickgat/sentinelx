//! Integration tests for the predictive risk classifier.
//!
//! The fixture forest below is hand-crafted so every score is
//! reproducible by pencil; assertions pin the exact `sigmoid(sum)` values
//! we expect.

// Integration tests: `expect` / `unwrap` on a known-good fixture is the
// canonical assertion style across this crate.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use sx_ml::predictive::features::{
    AssetKindEnum, AssetViewLike, FindingFeatures, FindingViewLike, SeverityEnum,
    FEATURE_VECTOR_LEN,
};
use sx_ml::predictive::gbdt::{leaf_pointer, Forest, Split, Tree};
use sx_ml::predictive::model::{FeatureScaler, PredictiveModel};

const FIXTURE_FOREST_JSON: &str = r#"{
    "forest": {
        "trees": [
            {
                "splits": [{"feature_idx": 0, "threshold": 7.0, "left": -1, "right": -2}],
                "leaves": [-1.0, 1.5]
            },
            {
                "splits": [{"feature_idx": 2, "threshold": 0.5, "left": -1, "right": -2}],
                "leaves": [0.0, 2.0]
            },
            {
                "splits": [{"feature_idx": 1, "threshold": 0.5, "left": -1, "right": -2}],
                "leaves": [-0.5, 1.0]
            }
        ],
        "bias": 0.0
    },
    "scaler": {"mean": [], "std": []}
}"#;

fn high_risk_finding() -> FindingViewLike {
    FindingViewLike {
        cvss: Some(9.0),
        epss: Some(0.9),
        kev_flag: true,
        severity: "critical".into(),
        days_since_first_seen: 14.0,
        business_impact: 3.0,
        chain_amplifier: 2.0,
    }
}

fn low_risk_finding() -> FindingViewLike {
    FindingViewLike {
        cvss: Some(3.0),
        epss: Some(0.1),
        kev_flag: false,
        severity: "low".into(),
        days_since_first_seen: 1.0,
        business_impact: 1.0,
        chain_amplifier: 1.0,
    }
}

fn host_asset() -> AssetViewLike {
    AssetViewLike {
        kind: "host".into(),
    }
}

fn sigmoid(x: f64) -> f64 {
    if x >= 0.0 {
        let z = (-x).exp();
        1.0 / (1.0 + z)
    } else {
        let z = x.exp();
        z / (1.0 + z)
    }
}

#[test]
fn feature_vector_is_fixed_length() {
    let f = high_risk_finding();
    let a = host_asset();
    let v = FindingFeatures::from_views(&f, &a).to_vector();
    assert_eq!(v.len(), FEATURE_VECTOR_LEN);
}

#[test]
fn feature_extraction_emits_expected_vector() {
    let f = FindingViewLike {
        cvss: Some(8.5),
        epss: Some(0.75),
        kev_flag: true,
        severity: "high".into(),
        days_since_first_seen: 4.0,
        business_impact: 2.5,
        chain_amplifier: 1.25,
    };
    let a = AssetViewLike {
        kind: "container".into(),
    };
    let feats = FindingFeatures::from_views(&f, &a);
    assert_eq!(feats.severity, SeverityEnum::High);
    assert_eq!(feats.asset_kind, AssetKindEnum::Container);
    let v = feats.to_vector();
    assert!((v[0] - 8.5).abs() < f64::EPSILON);
    assert!((v[1] - 0.75).abs() < f64::EPSILON);
    assert!((v[2] - 1.0).abs() < f64::EPSILON);
    assert!((v[3] - 4.0).abs() < f64::EPSILON);
    // severity = high → slot 4 + 3 = 7
    assert!((v[7] - 1.0).abs() < f64::EPSILON);
    // asset_kind = container → slot 4 + 5 + 1 = 10
    assert!((v[10] - 1.0).abs() < f64::EPSILON);
    assert!((v[15] - 2.5).abs() < f64::EPSILON);
    assert!((v[16] - 1.25).abs() < f64::EPSILON);
}

#[test]
fn empty_forest_returns_0_5_probability() {
    let model = PredictiveModel::default();
    let pred = model.predict(&FindingFeatures::from_views(
        &high_risk_finding(),
        &host_asset(),
    ));
    assert!((pred.probability - 0.5).abs() < f64::EPSILON);
}

#[test]
fn single_leaf_tree_returns_leaf_value() {
    let model = PredictiveModel::new(
        Forest::from_trees(vec![Tree::single_leaf(0.0)]),
        FeatureScaler::identity(),
    );
    // single zero-leaf → sigmoid(0) = 0.5
    let pred = model.predict(&FindingFeatures::from_views(
        &high_risk_finding(),
        &host_asset(),
    ));
    assert!((pred.probability - 0.5).abs() < f64::EPSILON);

    // sigmoid(2.0) ≈ 0.8807970779778823
    let model = PredictiveModel::new(
        Forest::from_trees(vec![Tree::single_leaf(2.0)]),
        FeatureScaler::identity(),
    );
    let pred = model.predict(&FindingFeatures::from_views(
        &low_risk_finding(),
        &host_asset(),
    ));
    assert!((pred.probability - 0.880_797_077_977_882_3).abs() < 1e-12);
}

#[test]
fn three_tree_forest_matches_hand_computed_output() {
    let model: PredictiveModel =
        serde_json::from_str(FIXTURE_FOREST_JSON).expect("fixture model parses");
    // High-risk input: trees emit 1.5 + 2.0 + 1.0 = 4.5 → sigmoid(4.5)
    let pred_high = model.predict(&FindingFeatures::from_views(
        &high_risk_finding(),
        &host_asset(),
    ));
    let expected_high = sigmoid(4.5);
    assert!(
        (pred_high.probability - expected_high).abs() < 1e-12,
        "high {:?} vs {expected_high}",
        pred_high.probability,
    );

    // Low-risk input: trees emit -1.0 + 0.0 + -0.5 = -1.5 → sigmoid(-1.5)
    let pred_low = model.predict(&FindingFeatures::from_views(
        &low_risk_finding(),
        &host_asset(),
    ));
    let expected_low = sigmoid(-1.5);
    assert!(
        (pred_low.probability - expected_low).abs() < 1e-12,
        "low {:?} vs {expected_low}",
        pred_low.probability,
    );
}

#[test]
fn high_risk_scores_strictly_higher_than_low_risk() {
    let model: PredictiveModel =
        serde_json::from_str(FIXTURE_FOREST_JSON).expect("fixture model parses");
    let high = model
        .predict(&FindingFeatures::from_views(
            &high_risk_finding(),
            &host_asset(),
        ))
        .probability;
    let low = model
        .predict(&FindingFeatures::from_views(
            &low_risk_finding(),
            &host_asset(),
        ))
        .probability;
    assert!(high > low, "{high} should beat {low}");
    assert!(high > 0.9);
    assert!(low < 0.2);
}

#[test]
fn forest_serde_round_trips_via_json() {
    let forest = Forest::from_trees(vec![
        Tree {
            splits: vec![Split::new(0, 0.5, leaf_pointer(0), leaf_pointer(1))],
            leaves: vec![-0.25, 0.75],
        },
        Tree::single_leaf(0.1),
    ]);
    let json = serde_json::to_string(&forest).expect("serialise");
    let parsed: Forest = serde_json::from_str(&json).expect("deserialise");
    assert_eq!(parsed, forest);
    assert_eq!(parsed.len(), 2);
}

#[test]
fn split_serde_round_trips_via_json() {
    let split = Split::new(3, 1.25, leaf_pointer(0), 7);
    let json = serde_json::to_string(&split).expect("serialise");
    let parsed: Split = serde_json::from_str(&json).expect("deserialise");
    assert_eq!(parsed, split);
}

#[test]
fn tree_serde_round_trips_via_json() {
    let tree = Tree {
        splits: vec![Split::new(0, 0.0, leaf_pointer(0), leaf_pointer(1))],
        leaves: vec![1.5, -1.5],
    };
    let json = serde_json::to_string(&tree).expect("serialise");
    let parsed: Tree = serde_json::from_str(&json).expect("deserialise");
    assert_eq!(parsed, tree);
}

#[test]
fn scaler_zscore_normalises_inputs() {
    let mut mean = vec![0.0_f64; FEATURE_VECTOR_LEN];
    let mut std = vec![1.0_f64; FEATURE_VECTOR_LEN];
    mean[0] = 5.0;
    std[0] = 2.0;
    let scaler = FeatureScaler::new(mean, std).expect("valid scaler");

    let mut input = [0.0_f64; FEATURE_VECTOR_LEN];
    input[0] = 7.0;
    let out = scaler.transform(&input);
    // (7 - 5) / 2 = 1.0
    assert!((out[0] - 1.0).abs() < f64::EPSILON);
    // Other slots unaffected because mean=0, std=1.
    for slot in out.iter().skip(1) {
        assert!(slot.abs() < f64::EPSILON);
    }
}

#[test]
fn scaler_clamps_non_finite_to_zero() {
    let scaler = FeatureScaler::identity();
    let mut input = [0.0_f64; FEATURE_VECTOR_LEN];
    input[0] = f64::NAN;
    input[1] = f64::INFINITY;
    input[2] = f64::NEG_INFINITY;
    let out = scaler.transform(&input);
    assert!(out[0].abs() < f64::EPSILON);
    assert!(out[1].abs() < f64::EPSILON);
    assert!(out[2].abs() < f64::EPSILON);
}

#[test]
fn predictive_model_round_trips_via_json() {
    let model: PredictiveModel = serde_json::from_str(FIXTURE_FOREST_JSON).expect("fixture parses");
    let json = model.to_json().expect("serialise");
    let parsed = PredictiveModel::from_json(&json).expect("deserialise");
    assert_eq!(parsed, model);
}

#[test]
fn high_cvss_kev_outscores_low_cvss_no_kev_on_realistic_model() {
    // Realistic shape: linear-ish boost on cvss, KEV flag, EPSS.
    let trees = vec![
        // CVSS gradient: <=4 → -1.0, >4 → +1.0.
        Tree {
            splits: vec![Split::new(0, 4.0, leaf_pointer(0), leaf_pointer(1))],
            leaves: vec![-1.0, 1.0],
        },
        // KEV bump.
        Tree {
            splits: vec![Split::new(2, 0.5, leaf_pointer(0), leaf_pointer(1))],
            leaves: vec![0.0, 1.5],
        },
        // EPSS bump at the 0.4 mark.
        Tree {
            splits: vec![Split::new(1, 0.4, leaf_pointer(0), leaf_pointer(1))],
            leaves: vec![-0.2, 0.6],
        },
    ];
    let model = PredictiveModel::new(Forest::from_trees(trees), FeatureScaler::identity());

    let scary = FindingFeatures::from_views(
        &FindingViewLike {
            cvss: Some(9.8),
            epss: Some(0.92),
            kev_flag: true,
            severity: "critical".into(),
            days_since_first_seen: 30.0,
            business_impact: 4.0,
            chain_amplifier: 2.5,
        },
        &host_asset(),
    );
    let trivial = FindingFeatures::from_views(
        &FindingViewLike {
            cvss: Some(1.0),
            epss: Some(0.01),
            kev_flag: false,
            severity: "low".into(),
            days_since_first_seen: 0.0,
            business_impact: 1.0,
            chain_amplifier: 1.0,
        },
        &host_asset(),
    );

    let scary_p = model.predict(&scary).probability;
    let trivial_p = model.predict(&trivial).probability;
    assert!(scary_p > 0.9, "scary={scary_p}");
    assert!(trivial_p < 0.3, "trivial={trivial_p}");
    assert!(scary_p > trivial_p);
    // The KEV + high-CVSS combo must beat the no-KEV + low-CVSS row by a
    // wide margin.
    assert!(scary_p - trivial_p > 0.6);
}

#[test]
fn confidence_is_zero_at_midpoint_and_one_at_extremes() {
    // Midpoint: empty forest → 0.5 → confidence 0.
    let model = PredictiveModel::default();
    let pred = model.predict(&FindingFeatures::from_views(
        &high_risk_finding(),
        &host_asset(),
    ));
    assert!((pred.confidence - 0.0).abs() < f64::EPSILON);

    // Strong tree → near 1.
    let strong = PredictiveModel::new(
        Forest::from_trees(vec![Tree::single_leaf(20.0)]),
        FeatureScaler::identity(),
    );
    let pred = strong.predict(&FindingFeatures::from_views(
        &low_risk_finding(),
        &host_asset(),
    ));
    assert!(pred.confidence > 0.999);
}

#[test]
fn nan_features_get_clamped_inside_inference() {
    let model: PredictiveModel = serde_json::from_str(FIXTURE_FOREST_JSON).expect("fixture parses");
    let nan_features = FindingFeatures {
        cvss: f64::NAN,
        epss: f64::INFINITY,
        kev_flag: f64::NEG_INFINITY,
        days_since_first_seen: f64::NAN,
        severity: SeverityEnum::Critical,
        asset_kind: AssetKindEnum::Service,
        business_impact: f64::NAN,
        chain_amplifier: f64::INFINITY,
    };
    // Inference is total — must not panic, must return a finite probability.
    let pred = model.predict(&nan_features);
    assert!(pred.probability.is_finite());
    assert!((0.0..=1.0).contains(&pred.probability));
}
