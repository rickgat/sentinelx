//! Integration tests for `sx-webhooks`.
//!
//! Tests are deliberately oblivious to network IO: they exercise the
//! pure signature-verification + payload-projection surface that every
//! provider entry point relies on. Each test computes a fresh HMAC
//! against a known secret + body and asserts that flipping a single
//! byte trips [`sx_webhooks::WebhookError::InvalidSignature`].

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use hmac::{Hmac, Mac};
use secrecy::SecretString;
use sha2::Sha256;
use sx_webhooks::error::WebhookError;
use sx_webhooks::{github, jira, slack};

type HmacSha256 = Hmac<Sha256>;

fn hmac_hex(secret: &str, message: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}

fn secret(value: &str) -> SecretString {
    SecretString::from(value.to_owned())
}

// ---------------------------------------------------------------------
// GitHub
// ---------------------------------------------------------------------

#[test]
fn github_verify_signature_valid() {
    let key = "test-secret";
    let body = br#"{"action":"opened","number":42}"#;
    let header = format!("sha256={}", hmac_hex(key, body));
    github::verify_signature(&secret(key), Some(&header), body).unwrap();
}

#[test]
fn github_verify_signature_invalid_hmac() {
    let key = "test-secret";
    let body = br#"{"action":"opened"}"#;
    let mut digest = hmac_hex(key, body);
    // Flip one hex char.
    digest.replace_range(0..1, "0");
    let header = format!("sha256={digest}");
    let err = github::verify_signature(&secret(key), Some(&header), body).unwrap_err();
    assert_eq!(err, WebhookError::InvalidSignature);
}

#[test]
fn github_verify_signature_missing_header() {
    let err = github::verify_signature(&secret("k"), None, b"{}").unwrap_err();
    assert_eq!(err, WebhookError::InvalidSignature);
}

#[test]
fn github_verify_signature_missing_prefix() {
    let key = "k";
    let body = b"{}";
    let digest = hmac_hex(key, body);
    let err = github::verify_signature(&secret(key), Some(&digest), body).unwrap_err();
    assert_eq!(err, WebhookError::InvalidSignature);
}

#[test]
fn github_parse_event_extracts_kind() {
    let key = "k";
    let body = br#"{"action":"opened","number":1}"#;
    let header = format!("sha256={}", hmac_hex(key, body));
    let event =
        github::verify_and_parse(&secret(key), Some(&header), Some("pull_request"), body).unwrap();
    assert_eq!(event.provider, "github");
    assert_eq!(event.kind, "pull_request.opened");
    assert_eq!(event.payload["number"], 1);
}

#[test]
fn github_parse_event_bad_json_is_bad_payload() {
    let key = "k";
    let body: &[u8] = b"not-json";
    let header = format!("sha256={}", hmac_hex(key, body));
    let err =
        github::verify_and_parse(&secret(key), Some(&header), Some("push"), body).unwrap_err();
    assert_eq!(err, WebhookError::BadPayload);
}

#[test]
fn github_parse_event_missing_event_header() {
    let key = "k";
    let body = br#"{"x":1}"#;
    let header = format!("sha256={}", hmac_hex(key, body));
    let err = github::verify_and_parse(&secret(key), Some(&header), None, body).unwrap_err();
    match err {
        WebhookError::Unsupported(_) => {}
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Slack
// ---------------------------------------------------------------------

fn slack_signature(secret_val: &str, ts: i64, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret_val.as_bytes()).unwrap();
    mac.update(b"v0:");
    mac.update(ts.to_string().as_bytes());
    mac.update(b":");
    mac.update(body);
    format!("v0={}", hex::encode(mac.finalize().into_bytes()))
}

#[test]
fn slack_verify_signature_valid_within_window() {
    let key = "slack-secret";
    let ts: i64 = 1_700_000_000;
    let body = br#"{"type":"event_callback"}"#;
    let sig = slack_signature(key, ts, body);
    slack::verify_signature(&secret(key), ts, body, Some(&sig), ts + 60).unwrap();
}

#[test]
fn slack_verify_signature_invalid_hmac() {
    let key = "slack-secret";
    let ts: i64 = 1_700_000_000;
    let body = br#"{"type":"event_callback"}"#;
    let bad = "v0=deadbeef".to_owned();
    let err = slack::verify_signature(&secret(key), ts, body, Some(&bad), ts).unwrap_err();
    assert_eq!(err, WebhookError::InvalidSignature);
}

#[test]
fn slack_verify_signature_replay_outside_window() {
    let key = "slack-secret";
    let ts: i64 = 1_700_000_000;
    let body = br#"{"type":"event_callback"}"#;
    let sig = slack_signature(key, ts, body);
    // 301s after the timestamp — just outside the 5-minute window.
    let err = slack::verify_signature(&secret(key), ts, body, Some(&sig), ts + 301).unwrap_err();
    assert_eq!(err, WebhookError::ReplayWindowExceeded);
}

#[test]
fn slack_verify_signature_replay_far_future_rejected() {
    let key = "slack-secret";
    let ts: i64 = 1_700_000_000;
    let body = br#"{"type":"event_callback"}"#;
    let sig = slack_signature(key, ts, body);
    let err = slack::verify_signature(&secret(key), ts, body, Some(&sig), ts - 600).unwrap_err();
    assert_eq!(err, WebhookError::ReplayWindowExceeded);
}

#[test]
fn slack_parse_event_extracts_nested_kind() {
    let key = "slack-secret";
    let ts: i64 = 1_700_000_000;
    let body = br#"{"type":"event_callback","event":{"type":"message"}}"#;
    let sig = slack_signature(key, ts, body);
    let event = slack::verify_and_parse(&secret(key), ts, body, Some(&sig), ts + 1).unwrap();
    assert_eq!(event.provider, "slack");
    assert_eq!(event.kind, "event_callback.message");
}

#[test]
fn slack_parse_event_bad_json_is_bad_payload() {
    let key = "slack-secret";
    let ts: i64 = 1_700_000_000;
    let body: &[u8] = b"<<not json>>";
    let sig = slack_signature(key, ts, body);
    let err = slack::verify_and_parse(&secret(key), ts, body, Some(&sig), ts).unwrap_err();
    assert_eq!(err, WebhookError::BadPayload);
}

// ---------------------------------------------------------------------
// Jira
// ---------------------------------------------------------------------

#[test]
fn jira_verify_signature_valid() {
    let key = "jira-secret";
    let body = br#"{"webhookEvent":"jira:issue_created"}"#;
    let header = format!("sha256={}", hmac_hex(key, body));
    jira::verify_signature(&secret(key), Some(&header), body).unwrap();
}

#[test]
fn jira_verify_signature_invalid_hmac() {
    let key = "jira-secret";
    let body = br#"{"webhookEvent":"jira:issue_updated"}"#;
    let header = format!("sha256={}", "0".repeat(64));
    let err = jira::verify_signature(&secret(key), Some(&header), body).unwrap_err();
    assert_eq!(err, WebhookError::InvalidSignature);
}

#[test]
fn jira_parse_event_extracts_kind() {
    let key = "jira-secret";
    let body = br#"{"webhookEvent":"jira:issue_created","issue":{"key":"SEC-1"}}"#;
    let header = format!("sha256={}", hmac_hex(key, body));
    let event = jira::verify_and_parse(&secret(key), Some(&header), body).unwrap();
    assert_eq!(event.provider, "jira");
    assert_eq!(event.kind, "jira:issue_created");
    assert_eq!(event.payload["issue"]["key"], "SEC-1");
}

#[test]
fn jira_parse_event_bad_json_is_bad_payload() {
    let key = "jira-secret";
    let body: &[u8] = b"definitely-not-json";
    let header = format!("sha256={}", hmac_hex(key, body));
    let err = jira::verify_and_parse(&secret(key), Some(&header), body).unwrap_err();
    assert_eq!(err, WebhookError::BadPayload);
}

#[test]
fn jira_parse_event_missing_webhook_event_field() {
    let key = "jira-secret";
    let body = br#"{"unrelated":true}"#;
    let header = format!("sha256={}", hmac_hex(key, body));
    let err = jira::verify_and_parse(&secret(key), Some(&header), body).unwrap_err();
    match err {
        WebhookError::Unsupported(_) => {}
        other => panic!("expected Unsupported, got {other:?}"),
    }
}
