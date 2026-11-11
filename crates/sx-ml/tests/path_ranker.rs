//! Tests for `AttackPathRanker`.

// Integration test file: short binding names (`short`, `long`, `ranked`) read
// most naturally here.
#![allow(clippy::similar_names)]

use sx_ml::prelude::*;

#[test]
fn path_ranker_orders_higher_max_first() {
    let ranker = AttackPathRanker::default();
    let paths = vec![
        PathInput {
            id: "low".to_string(),
            risk_scores: vec![1.0, 1.0, 1.0],
            length: 3,
        },
        PathInput {
            id: "high".to_string(),
            risk_scores: vec![9.0, 1.0, 1.0],
            length: 3,
        },
    ];
    let ranked = ranker.rank(paths);
    assert_eq!(ranked.first().map(|p| p.id.as_str()), Some("high"));
}

#[test]
fn path_ranker_penalises_longer_paths() {
    let ranker = AttackPathRanker::default();
    let short = PathInput {
        id: "short".to_string(),
        risk_scores: vec![5.0, 5.0],
        length: 2,
    };
    let long = PathInput {
        id: "long".to_string(),
        risk_scores: vec![5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0, 5.0],
        length: 8,
    };
    let ranked = ranker.rank(vec![short, long]);
    assert_eq!(ranked.first().map(|p| p.id.as_str()), Some("short"));
}

#[test]
fn path_ranker_default_weights_are_documented() {
    let r = AttackPathRanker::default();
    assert!((r.w_max - 0.6).abs() < 1e-9);
    assert!((r.w_sum - 0.3).abs() < 1e-9);
    assert!((r.w_len - 0.1).abs() < 1e-9);
}

#[test]
fn path_ranker_ties_broken_by_id() {
    let ranker = AttackPathRanker::default();
    let a = PathInput {
        id: "b".to_string(),
        risk_scores: vec![1.0],
        length: 1,
    };
    let b = PathInput {
        id: "a".to_string(),
        risk_scores: vec![1.0],
        length: 1,
    };
    let ranked = ranker.rank(vec![a, b]);
    assert_eq!(ranked.first().map(|p| p.id.as_str()), Some("a"));
}
