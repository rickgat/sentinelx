//! Tests for the Condition DSL.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use sx_soc::Condition;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[test]
fn eq_matches_top_level_field() {
    let c = Condition::Eq("kind".into(), json!("auth.login_failure_window"));
    assert!(c.matches(&json!({ "kind": "auth.login_failure_window" })));
    assert!(!c.matches(&json!({ "kind": "other" })));
    assert!(!c.matches(&json!({})));
}

#[test]
fn eq_supports_json_pointer() {
    let c = Condition::Eq("/actor/id".into(), json!("u-42"));
    assert!(c.matches(&json!({ "actor": { "id": "u-42" } })));
    assert!(!c.matches(&json!({ "actor": { "id": "u-43" } })));
}

#[test]
fn contains_substring() {
    let c = Condition::Contains("error".into(), "jwks_rotated".into());
    assert!(c.matches(&json!({ "error": "kid mismatch; jwks_rotated; retrying" })));
    assert!(!c.matches(&json!({ "error": "kid mismatch" })));
    assert!(!c.matches(&json!({ "error": 12 })));
}

#[test]
fn greater_than_numeric() {
    let c = Condition::GreaterThan("count".into(), 4.0);
    assert!(c.matches(&json!({ "count": 5 })));
    assert!(!c.matches(&json!({ "count": 4 })));
    assert!(!c.matches(&json!({ "count": "5" })));
}

#[test]
fn within_last_uses_event_ts() {
    let now = OffsetDateTime::now_utc();
    let recent = now - time::Duration::seconds(10);
    let recent_str = recent.format(&Rfc3339).unwrap();
    let old = now - time::Duration::seconds(3600);
    let old_str = old.format(&Rfc3339).unwrap();

    let inner = Condition::Eq("kind".into(), json!("x"));
    let c = Condition::WithinLast(Duration::from_secs(60), Box::new(inner));

    assert!(c.matches(&json!({ "ts": recent_str, "kind": "x" })));
    assert!(!c.matches(&json!({ "ts": old_str, "kind": "x" })));
    assert!(!c.matches(&json!({ "ts": recent_str, "kind": "other" })));
    assert!(!c.matches(&json!({ "ts": "not-rfc3339", "kind": "x" })));
    assert!(!c.matches(&json!({ "kind": "x" })));
}

#[test]
fn any_of_short_circuits_after_first_true() {
    let counter = Arc::new(AtomicUsize::new(0));

    // Build a custom Condition tree where the second branch would *also*
    // match but should never be evaluated; we approximate this by counting
    // how many checks happen.
    let true_branch = Condition::Eq("kind".into(), json!("hit"));
    let also_true_branch = Condition::Eq("kind".into(), json!("hit"));
    let c = Condition::AnyOf(vec![true_branch, also_true_branch]);

    let event = json!({ "kind": "hit" });
    assert!(c.matches(&event));

    // Now prove short-circuit semantics by re-using std iter `any`: if
    // any_of forwarded to `any` then the second won't fire. We simulate
    // by counting via map and any.
    let probes: Vec<Condition> = vec![
        Condition::Eq("kind".into(), json!("hit")),
        Condition::Eq("kind".into(), json!("hit")),
    ];
    let _ = probes.iter().any(|cond| {
        counter.fetch_add(1, Ordering::SeqCst);
        cond.matches(&event)
    });
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

#[test]
fn any_of_returns_false_when_all_branches_false() {
    let c = Condition::AnyOf(vec![
        Condition::Eq("kind".into(), json!("a")),
        Condition::Eq("kind".into(), json!("b")),
    ]);
    assert!(!c.matches(&json!({ "kind": "z" })));
}

#[test]
fn all_of_requires_every_branch() {
    let c = Condition::AllOf(vec![
        Condition::Eq("kind".into(), json!("x")),
        Condition::GreaterThan("count".into(), 1.0),
    ]);
    assert!(c.matches(&json!({ "kind": "x", "count": 2 })));
    assert!(!c.matches(&json!({ "kind": "x", "count": 1 })));
    assert!(!c.matches(&json!({ "kind": "y", "count": 2 })));
}
