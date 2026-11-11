//! Starter rule pack.
//!
//! The pack ships six opinionated [`Rule`]s covering the `SentinelX`
//! threat-model primitives: brute-force auth, kill-switch trips, audit
//! tampering, unsupervised BAS runs, OIDC verification storms, and
//! geographically impossible logins.
//!
//! The pack is meant as a *default*: operators are expected to extend or
//! override entries to suit their environment.
//!
//! ## Pack overview
//!
//! | id                          | severity | throttle  |
//! |-----------------------------|----------|-----------|
//! | `auth.bruteforce`           | High     | 5 min     |
//! | `core.kill_switch.tripped`  | Critical | 1 min     |
//! | `audit.chain.verify_failed` | Critical | 10 min    |
//! | `bas.run.unapproved`        | High     | 15 min    |
//! | `oidc.verify.burst`         | Medium   | 5 min     |
//! | `auth.impossible_travel`    | High     | 5 min     |

use std::time::Duration;

use serde_json::json;

use crate::alert::Severity;
use crate::rule::{Condition, Rule};

/// Returns the six starter rules. Order is stable for tests.
#[must_use]
pub fn starter_pack() -> Vec<Rule> {
    vec![
        bruteforce_logins(),
        kill_switch_tripped(),
        audit_chain_verify_failed(),
        bas_run_no_approvals(),
        oidc_verify_burst(),
        impossible_travel(),
    ]
}

/// "5 failed logins in 1 minute" — surfaces password-spray and credential
/// stuffing patterns. We rely on an upstream aggregator to emit an event
/// shaped `{ kind: "auth.login_failure_window", count: N, ts, tenant_id }`.
fn bruteforce_logins() -> Rule {
    Rule::new(
        "auth.bruteforce",
        "5 failed logins in 1min",
        Severity::High,
        Condition::AllOf(vec![
            Condition::Eq("kind".into(), json!("auth.login_failure_window")),
            Condition::GreaterThan("count".into(), 4.0),
            Condition::WithinLast(
                Duration::from_secs(60),
                Box::new(Condition::Eq(
                    "kind".into(),
                    json!("auth.login_failure_window"),
                )),
            ),
        ]),
        Some(Duration::from_secs(300)),
    )
}

/// "Kill switch tripped" — fires whenever the autonomy kill switch flips
/// to active. Critical because it implies a manual intervention or a
/// safety-rail trigger.
fn kill_switch_tripped() -> Rule {
    Rule::new(
        "core.kill_switch.tripped",
        "kill switch tripped",
        Severity::Critical,
        Condition::AllOf(vec![
            Condition::Eq("kind".into(), json!("core.kill_switch")),
            Condition::Eq("state".into(), json!("active")),
        ]),
        Some(Duration::from_secs(60)),
    )
}

/// "Audit chain verify failed" — emitted by `sx-audit` after a chain
/// verification run uncovers tampering or a sequence gap.
fn audit_chain_verify_failed() -> Rule {
    Rule::new(
        "audit.chain.verify_failed",
        "audit chain verify failed",
        Severity::Critical,
        Condition::AllOf(vec![
            Condition::Eq("kind".into(), json!("audit.chain.verify")),
            Condition::Eq("ok".into(), json!(false)),
        ]),
        Some(Duration::from_secs(600)),
    )
}

/// "BAS run with no approvals" — Breach & Attack Simulation runs that
/// reached the execute stage without a recorded approver. Indicates a
/// process / IAM-control failure.
fn bas_run_no_approvals() -> Rule {
    Rule::new(
        "bas.run.unapproved",
        "BAS run with no approvals",
        Severity::High,
        Condition::AllOf(vec![
            Condition::Eq("kind".into(), json!("bas.run.executed")),
            Condition::Eq("approvers_count".into(), json!(0)),
        ]),
        Some(Duration::from_secs(900)),
    )
}

/// "Impossible travel" — emitted by the IAM login hook (a later phase) when
/// two successive logins for the same principal imply a ground speed beyond
/// what is physically plausible. The geometric computation lives in
/// [`crate::rule::impossible_travel`]; this rule simply listens for the
/// upstream `auth.impossible_travel` event shape:
///
/// ```json
/// { "kind": "auth.impossible_travel",
///   "user_id": "...",
///   "computed_kmh": 11700.0,
///   "threshold_kmh": 800.0,
///   "distance_km": 11700.0,
///   "elapsed_secs": 3600.0,
///   "ts": "..." }
/// ```
///
/// Throttled to the same 5-minute window as `auth.bruteforce` so that a
/// flapping `GeoIP` feed cannot drown the SOC channel.
fn impossible_travel() -> Rule {
    Rule::new(
        "auth.impossible_travel",
        "geographically impossible login",
        Severity::High,
        Condition::AllOf(vec![
            Condition::Eq("kind".into(), json!("auth.impossible_travel")),
            // The upstream emitter already enforces this, but we re-check
            // defensively so a misconfigured producer cannot spam alerts.
            Condition::GreaterThan("computed_kmh".into(), 0.0),
        ]),
        Some(Duration::from_secs(300)),
    )
}

/// "OIDC verify failure burst" — bursts of failed OIDC token verifications,
/// typically because of a key-rotation mismatch or a malicious token replay.
fn oidc_verify_burst() -> Rule {
    Rule::new(
        "oidc.verify.burst",
        "OIDC verify failure burst",
        Severity::Medium,
        Condition::AnyOf(vec![
            Condition::AllOf(vec![
                Condition::Eq("kind".into(), json!("oidc.verify_failed_window")),
                Condition::GreaterThan("count".into(), 9.0),
            ]),
            Condition::Contains("error".into(), "jwks_rotated".into()),
        ]),
        Some(Duration::from_secs(300)),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rule_pack_has_six_entries() {
        let pack = starter_pack();
        assert_eq!(
            pack.len(),
            6,
            "starter pack must contain exactly 6 rules, got {}",
            pack.len()
        );
    }

    #[test]
    fn rule_pack_contains_impossible_travel() {
        let pack = starter_pack();
        let found = pack.iter().find(|r| r.id == "auth.impossible_travel");
        let rule = found.expect("auth.impossible_travel must be in the starter pack");
        // Same 5-minute throttle window as auth.bruteforce per spec.
        assert_eq!(rule.throttle, Some(Duration::from_secs(300)));
        assert_eq!(rule.severity, Severity::High);
    }

    #[test]
    fn rule_pack_ids_are_unique() {
        let pack = starter_pack();
        let mut ids: Vec<&str> = pack.iter().map(|r| r.id.as_str()).collect();
        ids.sort_unstable();
        let len_before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), len_before, "rule ids must be unique");
    }
}
