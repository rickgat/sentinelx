//! Tests for the rule engine.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use serde_json::json;
use sx_soc::{Condition, Rule, RuleEngine, Severity};

#[tokio::test]
async fn engine_with_zero_rules_emits_nothing() {
    let engine = RuleEngine::new(vec![]);
    let alerts = engine.evaluate(&json!({"any": "event"})).await;
    assert!(alerts.is_empty());
}

#[tokio::test]
async fn engine_with_one_matching_rule_emits_one_alert() {
    let rule = Rule::new(
        "r1",
        "rule one",
        Severity::High,
        Condition::Eq("kind".into(), json!("hit")),
        None,
    );
    let engine = RuleEngine::new(vec![rule]);
    let alerts = engine
        .evaluate(&json!({"kind": "hit", "tenant_id": "t-1"}))
        .await;
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].kind, "r1");
    assert_eq!(alerts[0].tenant_id.as_deref(), Some("t-1"));
    assert_eq!(alerts[0].severity, Severity::High);
}

#[tokio::test]
async fn engine_with_two_rules_only_matching_one_emits_one() {
    let r1 = Rule::new(
        "r1",
        "rule 1",
        Severity::High,
        Condition::Eq("kind".into(), json!("hit")),
        None,
    );
    let r2 = Rule::new(
        "r2",
        "rule 2",
        Severity::Low,
        Condition::Eq("kind".into(), json!("nope")),
        None,
    );
    let engine = RuleEngine::new(vec![r1, r2]);
    let alerts = engine.evaluate(&json!({"kind": "hit"})).await;
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].kind, "r1");
}

#[tokio::test]
async fn engine_with_two_matching_rules_emits_two() {
    let r1 = Rule::new(
        "r1",
        "first",
        Severity::Info,
        Condition::Eq("kind".into(), json!("hit")),
        None,
    );
    let r2 = Rule::new(
        "r2",
        "second",
        Severity::Medium,
        Condition::Contains("kind".into(), "hi".into()),
        None,
    );
    let engine = RuleEngine::new(vec![r1, r2]);
    let alerts = engine.evaluate(&json!({"kind": "hit"})).await;
    assert_eq!(alerts.len(), 2);
}
