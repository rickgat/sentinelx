//! Policy engine trait and the default [`JsonPolicyEngine`] implementation.

use std::time::Duration;

use async_trait::async_trait;
use regex::Regex;
use serde_json::Value;
use tokio::time::timeout;

use crate::decision::Decision;
use crate::error::PolicyError;
use crate::policy::{JsonPolicy, Policy, PolicyRule, PolicySource, RuleOp, RuleValue};

/// Hard upper bound on a single [`PolicyEngine::evaluate`] call.
///
/// All engines wrap their inner work in `tokio::time::timeout(EVALUATE_TIMEOUT, ...)`
/// so a malicious or buggy backend (notably future WASM/Rego ones) cannot stall
/// the request pipeline.
pub const EVALUATE_TIMEOUT: Duration = Duration::from_millis(100);

/// Pluggable policy backend.
///
/// Implementations evaluate a [`Policy`] against a `serde_json::Value` input
/// document and return a [`Decision`]. The default implementation is
/// [`JsonPolicyEngine`].
#[async_trait]
pub trait PolicyEngine: Send + Sync {
    /// Evaluate `policy` against `input`. Bounded by [`EVALUATE_TIMEOUT`].
    async fn evaluate(&self, policy: &Policy, input: &Value) -> Result<Decision, PolicyError>;
}

/// Default engine: pure-Rust evaluator for [`crate::policy::JsonPolicy`].
#[derive(Debug, Default, Clone, Copy)]
pub struct JsonPolicyEngine;

impl JsonPolicyEngine {
    /// Construct a fresh engine. Stateless; cheap to clone.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PolicyEngine for JsonPolicyEngine {
    async fn evaluate(&self, policy: &Policy, input: &Value) -> Result<Decision, PolicyError> {
        match &policy.source {
            PolicySource::Json(json) => {
                let json = json.clone();
                let input = input.clone();
                let fut = async move { evaluate_json(&json, &input) };
                timeout(EVALUATE_TIMEOUT, fut)
                    .await
                    .map_or(Err(PolicyError::Timeout), |res| res)
            }
            PolicySource::Rego(_) => Err(PolicyError::Evaluate(
                "Rego backend not enabled in this build".to_owned(),
            )),
        }
    }
}

fn evaluate_json(policy: &JsonPolicy, input: &Value) -> Result<Decision, PolicyError> {
    let mut reasons = Vec::new();
    let mut rule_ids = Vec::new();

    for rule in &policy.deny_if {
        if rule_matches(rule, input)? {
            reasons.push(
                rule.reason
                    .clone()
                    .unwrap_or_else(|| format!("rule {} fired", rule.id)),
            );
            rule_ids.push(rule.id.clone());
        }
    }

    if rule_ids.is_empty() {
        Ok(Decision::allow())
    } else {
        Ok(Decision::deny(reasons, rule_ids))
    }
}

fn rule_matches(rule: &PolicyRule, input: &Value) -> Result<bool, PolicyError> {
    let Some(field_value) = lookup(input, &rule.field) else {
        // Missing field → rule does not fire. This matches the contract spelled
        // out in the crate-level tests.
        return Ok(false);
    };

    match (rule.op, &rule.value) {
        (RuleOp::Eq, RuleValue::Str(s)) => Ok(field_value.as_str() == Some(s.as_str())),
        (RuleOp::Eq, RuleValue::Int(n)) => Ok(field_value.as_i64() == Some(*n)),
        (RuleOp::Eq, RuleValue::Bool(b)) => Ok(field_value.as_bool() == Some(*b)),
        (RuleOp::In, RuleValue::StrList(list)) => Ok(field_value
            .as_str()
            .is_some_and(|v| list.iter().any(|x| x == v))),
        (RuleOp::In, RuleValue::IntList(list)) => {
            Ok(field_value.as_i64().is_some_and(|v| list.contains(&v)))
        }
        (RuleOp::Match, RuleValue::Str(pattern)) => {
            let re = Regex::new(pattern).map_err(|e| {
                PolicyError::Evaluate(format!("invalid regex in rule {}: {e}", rule.id))
            })?;
            let Some(s) = field_value.as_str() else {
                return Ok(false);
            };
            Ok(re.is_match(s))
        }
        // All other operator/value combinations are type errors at the DSL
        // level — surface them as evaluation errors so callers can flag bad
        // policy authoring rather than silently misbehaving.
        (op, val) => Err(PolicyError::Evaluate(format!(
            "rule {}: operator {:?} incompatible with value {:?}",
            rule.id, op, val
        ))),
    }
}

/// Resolve a dot-separated path against a JSON document. Returns `None` if any
/// segment is missing or traverses through a non-object.
fn lookup<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cursor = root;
    for segment in path.split('.') {
        cursor = cursor.get(segment)?;
    }
    Some(cursor)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests favour terseness over the defence-in-depth required of production code"
)]
mod tests {
    use super::*;
    use crate::policy::{JsonPolicy, PolicyRule, RuleOp, RuleValue};
    use serde_json::json;
    use std::sync::Arc;

    fn rule(id: &str, field: &str, op: RuleOp, value: RuleValue) -> PolicyRule {
        PolicyRule {
            id: id.to_owned(),
            field: field.to_owned(),
            op,
            value,
            reason: None,
        }
    }

    fn rule_with_reason(
        id: &str,
        field: &str,
        op: RuleOp,
        value: RuleValue,
        reason: &str,
    ) -> PolicyRule {
        PolicyRule {
            id: id.to_owned(),
            field: field.to_owned(),
            op,
            value,
            reason: Some(reason.to_owned()),
        }
    }

    #[tokio::test]
    async fn equality_deny_rule_fires() {
        let policy = Policy::from_json(
            "p1".to_owned(),
            JsonPolicy {
                deny_if: vec![rule(
                    "no_root",
                    "user.name",
                    RuleOp::Eq,
                    RuleValue::Str("root".to_owned()),
                )],
            },
        );
        let input = json!({ "user": { "name": "root" } });
        let decision = JsonPolicyEngine::new()
            .evaluate(&policy, &input)
            .await
            .expect("engine ok");
        assert!(!decision.allow);
        assert_eq!(decision.rule_ids, vec!["no_root".to_owned()]);
    }

    #[tokio::test]
    async fn in_list_deny_rule_fires() {
        let policy = Policy::from_json(
            "p2".to_owned(),
            JsonPolicy {
                deny_if: vec![rule(
                    "no_test_envs",
                    "env",
                    RuleOp::In,
                    RuleValue::StrList(vec!["dev".to_owned(), "qa".to_owned()]),
                )],
            },
        );
        let input = json!({ "env": "qa" });
        let decision = JsonPolicyEngine::new()
            .evaluate(&policy, &input)
            .await
            .expect("engine ok");
        assert!(!decision.allow);
        assert_eq!(decision.rule_ids, vec!["no_test_envs".to_owned()]);
    }

    #[tokio::test]
    async fn regex_match_deny_rule_fires() {
        let policy = Policy::from_json(
            "p3".to_owned(),
            JsonPolicy {
                deny_if: vec![rule(
                    "no_admin_paths",
                    "path",
                    RuleOp::Match,
                    RuleValue::Str("^/admin/.*".to_owned()),
                )],
            },
        );
        let input = json!({ "path": "/admin/users" });
        let decision = JsonPolicyEngine::new()
            .evaluate(&policy, &input)
            .await
            .expect("engine ok");
        assert!(!decision.allow);
        assert_eq!(decision.rule_ids, vec!["no_admin_paths".to_owned()]);
    }

    #[tokio::test]
    async fn multiple_rules_combine_in_order() {
        let policy = Policy::from_json(
            "p4".to_owned(),
            JsonPolicy {
                deny_if: vec![
                    rule(
                        "no_root",
                        "user.name",
                        RuleOp::Eq,
                        RuleValue::Str("root".to_owned()),
                    ),
                    rule(
                        "no_admin_paths",
                        "path",
                        RuleOp::Match,
                        RuleValue::Str("^/admin/.*".to_owned()),
                    ),
                ],
            },
        );
        let input = json!({ "user": { "name": "root" }, "path": "/admin/x" });
        let decision = JsonPolicyEngine::new()
            .evaluate(&policy, &input)
            .await
            .expect("engine ok");
        assert!(!decision.allow);
        assert_eq!(
            decision.rule_ids,
            vec!["no_root".to_owned(), "no_admin_paths".to_owned()]
        );
        assert_eq!(decision.reasons.len(), 2);
    }

    #[tokio::test]
    async fn empty_policy_allows() {
        let policy = Policy::from_json("p5".to_owned(), JsonPolicy::default());
        let input = json!({ "anything": "goes" });
        let decision = JsonPolicyEngine::new()
            .evaluate(&policy, &input)
            .await
            .expect("engine ok");
        assert!(decision.allow);
        assert!(decision.rule_ids.is_empty());
        assert!(decision.reasons.is_empty());
    }

    #[tokio::test]
    async fn rule_ids_reflect_fired_rules_only() {
        let policy = Policy::from_json(
            "p6".to_owned(),
            JsonPolicy {
                deny_if: vec![
                    rule(
                        "fires",
                        "env",
                        RuleOp::Eq,
                        RuleValue::Str("prod".to_owned()),
                    ),
                    rule(
                        "does_not_fire",
                        "env",
                        RuleOp::Eq,
                        RuleValue::Str("dev".to_owned()),
                    ),
                ],
            },
        );
        let input = json!({ "env": "prod" });
        let decision = JsonPolicyEngine::new()
            .evaluate(&policy, &input)
            .await
            .expect("engine ok");
        assert_eq!(decision.rule_ids, vec!["fires".to_owned()]);
    }

    #[tokio::test]
    async fn reasons_are_human_readable() {
        let policy = Policy::from_json(
            "p7".to_owned(),
            JsonPolicy {
                deny_if: vec![
                    rule_with_reason(
                        "no_root",
                        "user.name",
                        RuleOp::Eq,
                        RuleValue::Str("root".to_owned()),
                        "root login is forbidden in production",
                    ),
                    rule(
                        "no_test_envs",
                        "env",
                        RuleOp::In,
                        RuleValue::StrList(vec!["dev".to_owned()]),
                    ),
                ],
            },
        );
        let input = json!({ "user": { "name": "root" }, "env": "dev" });
        let decision = JsonPolicyEngine::new()
            .evaluate(&policy, &input)
            .await
            .expect("engine ok");
        assert_eq!(decision.reasons[0], "root login is forbidden in production");
        // Default-synthesised reason for the second rule:
        assert_eq!(decision.reasons[1], "rule no_test_envs fired");
    }

    #[tokio::test]
    async fn evaluate_enforces_timeout() {
        // Build a synthetic engine that sleeps longer than EVALUATE_TIMEOUT to
        // prove the bound is enforced.
        struct SlowEngine;
        #[async_trait]
        impl PolicyEngine for SlowEngine {
            async fn evaluate(
                &self,
                _policy: &Policy,
                _input: &Value,
            ) -> Result<Decision, PolicyError> {
                let fut = async {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    Decision::allow()
                };
                timeout(EVALUATE_TIMEOUT, fut)
                    .await
                    .map_or(Err(PolicyError::Timeout), Ok)
            }
        }

        let engine: Arc<dyn PolicyEngine> = Arc::new(SlowEngine);
        let policy = Policy::from_json("slow".to_owned(), JsonPolicy::default());
        let input = json!({});
        let err = engine
            .evaluate(&policy, &input)
            .await
            .expect_err("must time out");
        assert!(matches!(err, PolicyError::Timeout));
    }

    #[tokio::test]
    async fn malformed_json_yields_parse_error() {
        let err = JsonPolicy::from_json_str("{ not json").expect_err("must fail");
        assert!(matches!(err, PolicyError::Parse(_)));
    }

    #[tokio::test]
    async fn missing_field_does_not_fire_deny() {
        let policy = Policy::from_json(
            "p8".to_owned(),
            JsonPolicy {
                deny_if: vec![rule(
                    "no_root",
                    "user.name",
                    RuleOp::Eq,
                    RuleValue::Str("root".to_owned()),
                )],
            },
        );
        // `user.name` is absent — rule must NOT fire.
        let input = json!({ "request": { "id": "abc" } });
        let decision = JsonPolicyEngine::new()
            .evaluate(&policy, &input)
            .await
            .expect("engine ok");
        assert!(decision.allow);
        assert!(decision.rule_ids.is_empty());
    }

    #[tokio::test]
    async fn rego_source_reports_evaluate_error() {
        let policy = Policy::from_rego("rego1".to_owned(), "package x\nallow = true".to_owned());
        let err = JsonPolicyEngine::new()
            .evaluate(&policy, &json!({}))
            .await
            .expect_err("rego unsupported");
        assert!(matches!(err, PolicyError::Evaluate(_)));
    }

    #[tokio::test]
    async fn int_equality_rule_fires() {
        let policy = Policy::from_json(
            "p9".to_owned(),
            JsonPolicy {
                deny_if: vec![rule(
                    "no_zero_quota",
                    "quota",
                    RuleOp::Eq,
                    RuleValue::Int(0),
                )],
            },
        );
        let input = json!({ "quota": 0 });
        let decision = JsonPolicyEngine::new()
            .evaluate(&policy, &input)
            .await
            .expect("engine ok");
        assert!(!decision.allow);
        assert_eq!(decision.rule_ids, vec!["no_zero_quota".to_owned()]);
    }
}
