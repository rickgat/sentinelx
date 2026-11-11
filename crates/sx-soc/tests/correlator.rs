//! Tests for the Correlator, including throttling semantics and channel
//! shutdown behaviour.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use sx_soc::{AlertSink, BufferAlertSink, Condition, Correlator, Rule, RuleEngine, Severity};
use tokio::sync::mpsc;

fn rule_with_throttle(throttle: Option<Duration>) -> Rule {
    Rule::new(
        "auth.bruteforce",
        "5 failed logins in 1min",
        Severity::High,
        Condition::Eq("kind".into(), json!("auth.login_failure_window")),
        throttle,
    )
}

#[tokio::test]
async fn correlator_throttles_within_window_same_key() {
    let rule = rule_with_throttle(Some(Duration::from_secs(5)));
    let engine = RuleEngine::new(vec![rule]);
    let buf: Arc<BufferAlertSink> = Arc::new(BufferAlertSink::new(16));
    let sinks: Vec<Arc<dyn AlertSink>> = vec![buf.clone()];
    let corr = Correlator::new(engine, sinks);

    let (tx, rx) = mpsc::channel(16);
    let handle = tokio::spawn(async move { corr.run(rx).await });

    tx.send(json!({"kind": "auth.login_failure_window", "tenant_id": "t-1"}))
        .await
        .unwrap();
    tx.send(json!({"kind": "auth.login_failure_window", "tenant_id": "t-1"}))
        .await
        .unwrap();
    drop(tx);

    let stats = handle.await.unwrap();
    assert_eq!(stats.events, 2);
    assert_eq!(stats.alerts_raw, 2);
    assert_eq!(stats.alerts_forwarded, 1);
    assert_eq!(buf.len().await, 1);
}

#[tokio::test]
async fn correlator_does_not_throttle_across_tenants() {
    let rule = rule_with_throttle(Some(Duration::from_secs(30)));
    let engine = RuleEngine::new(vec![rule]);
    let buf: Arc<BufferAlertSink> = Arc::new(BufferAlertSink::new(16));
    let sinks: Vec<Arc<dyn AlertSink>> = vec![buf.clone()];
    let corr = Correlator::new(engine, sinks);

    let (tx, rx) = mpsc::channel(16);
    let handle = tokio::spawn(async move { corr.run(rx).await });

    tx.send(json!({"kind": "auth.login_failure_window", "tenant_id": "t-1"}))
        .await
        .unwrap();
    tx.send(json!({"kind": "auth.login_failure_window", "tenant_id": "t-2"}))
        .await
        .unwrap();
    drop(tx);

    let stats = handle.await.unwrap();
    assert_eq!(stats.alerts_forwarded, 2);
    assert_eq!(buf.len().await, 2);
}

#[tokio::test]
async fn correlator_drains_remaining_events_then_exits_on_sender_drop() {
    // No throttle so every match counts.
    let rule = rule_with_throttle(None);
    let engine = RuleEngine::new(vec![rule]);
    let buf: Arc<BufferAlertSink> = Arc::new(BufferAlertSink::new(16));
    let sinks: Vec<Arc<dyn AlertSink>> = vec![buf.clone()];
    let corr = Correlator::new(engine, sinks);

    let (tx, rx) = mpsc::channel(16);
    let handle = tokio::spawn(async move { corr.run(rx).await });

    for _ in 0..3_u8 {
        tx.send(json!({"kind": "auth.login_failure_window", "tenant_id": "t-x"}))
            .await
            .unwrap();
    }
    drop(tx);

    let stats = handle.await.unwrap();
    assert_eq!(stats.events, 3);
    assert_eq!(stats.alerts_forwarded, 3);
    assert_eq!(buf.len().await, 3);
}

#[tokio::test]
async fn correlator_forwards_to_multiple_sinks() {
    let rule = rule_with_throttle(None);
    let engine = RuleEngine::new(vec![rule]);
    let buf_a: Arc<BufferAlertSink> = Arc::new(BufferAlertSink::new(4));
    let buf_b: Arc<BufferAlertSink> = Arc::new(BufferAlertSink::new(4));
    let sinks: Vec<Arc<dyn AlertSink>> = vec![buf_a.clone(), buf_b.clone()];
    let corr = Correlator::new(engine, sinks);

    let (tx, rx) = mpsc::channel(4);
    let handle = tokio::spawn(async move { corr.run(rx).await });

    tx.send(json!({"kind": "auth.login_failure_window"}))
        .await
        .unwrap();
    drop(tx);

    let _ = handle.await.unwrap();
    assert_eq!(buf_a.len().await, 1);
    assert_eq!(buf_b.len().await, 1);
}
