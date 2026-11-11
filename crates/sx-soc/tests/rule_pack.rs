//! Fixture-driven tests proving each rule in the starter pack fires on at
//! least one canonical event.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use serde_json::{json, Value};
use sx_soc::{starter_pack, RuleEngine};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc().format(&Rfc3339).unwrap()
}

#[tokio::test]
async fn starter_pack_has_six_rules() {
    let rules = starter_pack();
    assert_eq!(rules.len(), 6);
    let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(
        ids,
        vec![
            "auth.bruteforce",
            "core.kill_switch.tripped",
            "audit.chain.verify_failed",
            "bas.run.unapproved",
            "oidc.verify.burst",
            "auth.impossible_travel",
        ]
    );
}

async fn assert_fires(rule_id: &str, event: Value) {
    let engine = RuleEngine::new(starter_pack());
    let alerts = engine.evaluate(&event).await;
    assert!(
        alerts.iter().any(|a| a.kind == rule_id),
        "rule '{rule_id}' did not fire on event: {event}"
    );
}

#[tokio::test]
async fn bruteforce_fires_on_window_with_high_count() {
    assert_fires(
        "auth.bruteforce",
        json!({
            "kind": "auth.login_failure_window",
            "count": 5,
            "ts": now_rfc3339(),
            "tenant_id": "t-1",
        }),
    )
    .await;
}

#[tokio::test]
async fn kill_switch_fires_when_active() {
    assert_fires(
        "core.kill_switch.tripped",
        json!({ "kind": "core.kill_switch", "state": "active", "tenant_id": "t-1" }),
    )
    .await;
}

#[tokio::test]
async fn audit_chain_fires_when_verify_failed() {
    assert_fires(
        "audit.chain.verify_failed",
        json!({ "kind": "audit.chain.verify", "ok": false }),
    )
    .await;
}

#[tokio::test]
async fn bas_unapproved_fires_when_no_approvers() {
    assert_fires(
        "bas.run.unapproved",
        json!({ "kind": "bas.run.executed", "approvers_count": 0 }),
    )
    .await;
}

#[tokio::test]
async fn oidc_burst_fires_via_count_branch() {
    assert_fires(
        "oidc.verify.burst",
        json!({ "kind": "oidc.verify_failed_window", "count": 12 }),
    )
    .await;
}

#[tokio::test]
async fn oidc_burst_fires_via_jwks_rotated_branch() {
    assert_fires(
        "oidc.verify.burst",
        json!({ "error": "kid mismatch; jwks_rotated; retrying" }),
    )
    .await;
}

#[tokio::test]
async fn impossible_travel_fires_on_geoip_anomaly_event() {
    // Shape produced by the (future) IAM login hook: a precomputed
    // anomaly summary is dropped onto the SOC event stream.
    assert_fires(
        "auth.impossible_travel",
        json!({
            "kind": "auth.impossible_travel",
            "user_id": "alice",
            "distance_km": 11700.0,
            "elapsed_secs": 3600.0,
            "computed_kmh": 11700.0,
            "threshold_kmh": 800.0,
            "tenant_id": "t-1",
            "ts": now_rfc3339(),
        }),
    )
    .await;
}
