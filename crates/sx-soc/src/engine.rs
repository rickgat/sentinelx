//! The rule engine.
//!
//! The engine is a passive owner of [`Rule`]s; it has no I/O of its own. The
//! [`crate::correlator::Correlator`] supplies events and forwards the produced
//! [`Alert`]s onward to [`crate::sink::AlertSink`]s.

use serde_json::Value;

use crate::alert::{Alert, EvidenceRef};
use crate::rule::Rule;

/// Stateless rule evaluator.
#[derive(Debug, Default, Clone)]
pub struct RuleEngine {
    rules: Vec<Rule>,
}

impl RuleEngine {
    /// Build an engine from the given rules.
    #[must_use]
    pub const fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    /// Returns the number of rules registered.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Borrow the rule list (used by tests and introspection).
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Evaluate `event` against every registered rule.
    ///
    /// Returns one [`Alert`] per matching rule. The function is `async` so
    /// that future rule kinds (e.g. external lookups) can integrate cleanly;
    /// today's implementation completes synchronously.
    #[allow(clippy::unused_async)]
    pub async fn evaluate(&self, event: &Value) -> Vec<Alert> {
        let mut out = Vec::new();
        for rule in &self.rules {
            if rule.when.matches(event) {
                let tenant_id = event
                    .get("tenant_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let mut alert = Alert::new(
                    rule.severity,
                    rule.id.clone(),
                    rule.name.clone(),
                    format!("Rule '{}' matched event.", rule.id),
                    tenant_id,
                );
                if let Some(eid) = event.get("event_id").and_then(Value::as_str) {
                    alert = alert.with_evidence(EvidenceRef::new("event_id", eid));
                }
                out.push(alert);
            }
        }
        out
    }
}
