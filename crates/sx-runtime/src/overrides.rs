//! Per-tenant Falco rule override model + evaluator (HIGH-006).
//!
//! Falco emits a fixed catalogue of rules ("Terminal shell in container",
//! "Write below etc", ...). A noisy or low-value rule will flood a
//! tenant with alerts; conversely a high-value finding may need to be
//! escalated to `Critical` regardless of Falco's `priority` field.
//! HIGH-006 introduces a per-tenant `(rule_name, subkey, action)`
//! override table the normaliser consults before emitting a finding.
//!
//! ## Decision matrix
//!
//! Given the set of overrides for a tenant and an incoming alert with
//! `(rule, subkey)`:
//!
//! - **Exact match** — `(rule_name == alert.rule, subkey == alert_subkey)`:
//!   the row's `action` is applied.
//! - **Rule-wide match** — `(rule_name == alert.rule, subkey IS NULL)`:
//!   applied when no exact match exists. The `NULL` subkey is encoded on
//!   the wire / in memory as [`SUBKEY_WILDCARD`] (a single `"*"`) so the
//!   storage layer can treat the `(tenant_id, rule_name, subkey)` tuple
//!   as the primary key without a nullable column.
//! - **No match** — no override row applies; the alert passes through
//!   with its Falco-derived priority.
//!
//! ## Actions
//!
//! - [`OverrideAction::Allow`] — pass the alert through unchanged. This
//!   is the default behaviour and only useful as an explicit
//!   "exempt-this-rule-from-an-allowlist" toggle in a future allow-list
//!   mode; today it is a no-op.
//! - [`OverrideAction::Deny`] — suppress the alert entirely. The
//!   normaliser drops it before the finding is emitted; the audit row
//!   records the suppression.
//! - [`OverrideAction::Escalate`] — bump the severity one tier (e.g.
//!   `Medium → High`).
//! - [`OverrideAction::Downgrade`] — drop the severity one tier (e.g.
//!   `High → Medium`).
//!
//! Escalate and downgrade saturate at the ladder ends — `Critical` cannot
//! escalate further, `Info` cannot downgrade further.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::alert::FalcoAlert;
use crate::finding::RuntimeSeverity;

/// Wire / storage encoding of "this override applies to every subkey
/// under this rule". Stored as the literal `"*"` so the primary key
/// remains a non-nullable `(tenant_id, rule_name, subkey)` triple.
pub const SUBKEY_WILDCARD: &str = "*";

/// Per-tenant override action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OverrideAction {
    /// Pass the alert through unchanged. Reserved for future allow-list
    /// mode; today it is a no-op identical to "no override".
    Allow,
    /// Suppress the alert — no finding is emitted, the suppression is
    /// audited.
    Deny,
    /// Bump severity one tier (saturates at `Critical`).
    Escalate,
    /// Drop severity one tier (saturates at `Info`).
    Downgrade,
}

impl OverrideAction {
    /// Stable wire / database string. The variant names already
    /// lowercase-serialise to the same values via `#[serde(rename_all =
    /// "lowercase")]` — this helper is for tracing fields, log labels,
    /// and SQL bindings where a borrowed `&'static str` is convenient.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Escalate => "escalate",
            Self::Downgrade => "downgrade",
        }
    }

    /// Parse the stable wire string. Unknown values return `None`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            "escalate" => Some(Self::Escalate),
            "downgrade" => Some(Self::Downgrade),
            _ => None,
        }
    }
}

/// A single per-tenant override row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleOverride {
    /// Owning tenant (UUID-stringified).
    pub tenant_id: String,
    /// Matched Falco rule name, mirrored verbatim from `FalcoAlert::rule`.
    pub rule_name: String,
    /// Subkey within the rule. Stored as [`SUBKEY_WILDCARD`] (`"*"`)
    /// when the override applies to every subkey under `rule_name`.
    pub subkey: String,
    /// Action to apply.
    pub action: OverrideAction,
    /// Operator-supplied justification. Persisted in the audit row.
    pub reason: String,
    /// UUID of the operator who set the row.
    pub set_by: String,
    /// When the row was last mutated.
    #[serde(with = "time::serde::rfc3339")]
    pub set_at: OffsetDateTime,
}

/// Outcome of consulting the override table for one alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverrideDecision {
    /// No matching override — leave the alert alone.
    PassThrough,
    /// Override row matched. Carries the resolved post-override severity
    /// (or `None` when the action is `Deny`) plus the rationale string
    /// for the audit row.
    Applied {
        /// Action that fired.
        action: OverrideAction,
        /// Subkey value that matched — either the exact subkey or the
        /// wildcard `"*"` for a rule-wide override.
        matched_subkey: String,
        /// Resolved severity AFTER the action is applied. `None` for
        /// [`OverrideAction::Deny`] (the alert is dropped).
        resolved_severity: Option<RuntimeSeverity>,
    },
}

impl OverrideDecision {
    /// True iff the alert should be suppressed.
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        matches!(
            self,
            Self::Applied {
                action: OverrideAction::Deny,
                ..
            }
        )
    }
}

/// Best-effort projection of the Falco alert's subkey.
///
/// Falco rules do not expose a stable "subkey" field on the wire; the
/// closest analogue is the `evt.type` output field (syscall name for
/// the syscall source, audit `verb` for `k8s_audit`). Where present we
/// use it verbatim; otherwise we fall back to `proc.name` (process
/// activity) or the source label. The function is total — it always
/// returns *some* non-empty string, defaulting to [`SUBKEY_WILDCARD`].
#[must_use]
pub fn alert_subkey(alert: &FalcoAlert) -> String {
    if let Some(v) = alert.field_str("evt.type") {
        if !v.is_empty() {
            return v.to_owned();
        }
    }
    if let Some(v) = alert.field_str("ka.verb") {
        if !v.is_empty() {
            return v.to_owned();
        }
    }
    if let Some(v) = alert.field_str("proc.name") {
        if !v.is_empty() {
            return v.to_owned();
        }
    }
    SUBKEY_WILDCARD.to_owned()
}

/// Evaluate the override table against `alert` for `tenant_id`.
///
/// `rows` is the pre-loaded set of overrides for the tenant — the caller
/// is responsible for RLS scoping before invoking this evaluator so it
/// remains a pure synchronous function suitable for unit tests.
///
/// `base_severity` is the Falco-derived severity (before any override).
#[must_use]
pub fn evaluate(
    rows: &[RuleOverride],
    alert: &FalcoAlert,
    base_severity: RuntimeSeverity,
) -> OverrideDecision {
    let subkey = alert_subkey(alert);

    let mut exact: Option<&RuleOverride> = None;
    let mut rule_wide: Option<&RuleOverride> = None;

    for row in rows {
        if row.rule_name != alert.rule {
            continue;
        }
        if row.subkey == subkey {
            exact = Some(row);
            // Exact match always wins — no need to keep scanning for
            // a wildcard.
            break;
        }
        if row.subkey == SUBKEY_WILDCARD {
            rule_wide = Some(row);
        }
    }

    let Some(row) = exact.or(rule_wide) else {
        return OverrideDecision::PassThrough;
    };

    let resolved = match row.action {
        OverrideAction::Allow => Some(base_severity),
        OverrideAction::Deny => None,
        OverrideAction::Escalate => Some(base_severity.escalate()),
        OverrideAction::Downgrade => Some(base_severity.downgrade()),
    };

    OverrideDecision::Applied {
        action: row.action,
        matched_subkey: row.subkey.clone(),
        resolved_severity: resolved,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn alert_with(rule: &str, subkey_evt_type: &str) -> FalcoAlert {
        let v = serde_json::json!({
            "rule": rule,
            "priority": "Warning",
            "output": "x",
            "source": "syscall",
            "output_fields": {
                "evt.type": subkey_evt_type,
                "proc.name": "bash",
            }
        });
        serde_json::from_value(v).unwrap()
    }

    fn row(rule: &str, subkey: &str, action: OverrideAction) -> RuleOverride {
        RuleOverride {
            tenant_id: "t1".into(),
            rule_name: rule.into(),
            subkey: subkey.into(),
            action,
            reason: "test".into(),
            set_by: "u1".into(),
            set_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn action_round_trips_through_str() {
        for a in [
            OverrideAction::Allow,
            OverrideAction::Deny,
            OverrideAction::Escalate,
            OverrideAction::Downgrade,
        ] {
            assert_eq!(OverrideAction::parse(a.as_str()), Some(a));
        }
        assert!(OverrideAction::parse("nope").is_none());
    }

    #[test]
    fn action_serde_uses_lowercase() {
        let s = serde_json::to_string(&OverrideAction::Escalate).unwrap();
        assert_eq!(s, r#""escalate""#);
        let back: OverrideAction = serde_json::from_str(&s).unwrap();
        assert_eq!(back, OverrideAction::Escalate);
    }

    #[test]
    fn rule_override_round_trips_through_serde() {
        let r = row("Terminal shell", "execve", OverrideAction::Deny);
        let s = serde_json::to_string(&r).unwrap();
        let back: RuleOverride = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn empty_overrides_pass_through() {
        let a = alert_with("Terminal shell in container", "execve");
        let d = evaluate(&[], &a, RuntimeSeverity::Medium);
        assert_eq!(d, OverrideDecision::PassThrough);
    }

    #[test]
    fn deny_for_exact_subkey_suppresses() {
        let a = alert_with("Terminal shell in container", "execve");
        let rows = vec![row(
            "Terminal shell in container",
            "execve",
            OverrideAction::Deny,
        )];
        let d = evaluate(&rows, &a, RuntimeSeverity::High);
        assert!(d.is_deny());
        match d {
            OverrideDecision::Applied {
                action,
                matched_subkey,
                resolved_severity,
            } => {
                assert_eq!(action, OverrideAction::Deny);
                assert_eq!(matched_subkey, "execve");
                assert!(resolved_severity.is_none());
            }
            OverrideDecision::PassThrough => panic!("expected applied"),
        }
    }

    #[test]
    fn deny_rule_wide_suppresses_when_no_exact_match() {
        let a = alert_with("Write below etc", "openat");
        let rows = vec![row(
            "Write below etc",
            SUBKEY_WILDCARD,
            OverrideAction::Deny,
        )];
        let d = evaluate(&rows, &a, RuntimeSeverity::Low);
        assert!(d.is_deny());
    }

    #[test]
    fn exact_subkey_beats_rule_wide_wildcard() {
        let a = alert_with("Noisy rule", "execve");
        // Rule-wide denies; exact subkey says allow → exact wins.
        let rows = vec![
            row("Noisy rule", SUBKEY_WILDCARD, OverrideAction::Deny),
            row("Noisy rule", "execve", OverrideAction::Allow),
        ];
        let d = evaluate(&rows, &a, RuntimeSeverity::Medium);
        match d {
            OverrideDecision::Applied {
                action,
                resolved_severity,
                ..
            } => {
                assert_eq!(action, OverrideAction::Allow);
                assert_eq!(resolved_severity, Some(RuntimeSeverity::Medium));
            }
            OverrideDecision::PassThrough => panic!("exact override should have applied"),
        }
    }

    #[test]
    fn escalate_bumps_severity_one_tier() {
        let a = alert_with("Privileged container", "execve");
        let rows = vec![row(
            "Privileged container",
            "execve",
            OverrideAction::Escalate,
        )];
        let d = evaluate(&rows, &a, RuntimeSeverity::Medium);
        match d {
            OverrideDecision::Applied {
                resolved_severity, ..
            } => assert_eq!(resolved_severity, Some(RuntimeSeverity::High)),
            OverrideDecision::PassThrough => panic!("expected applied"),
        }
    }

    #[test]
    fn escalate_saturates_at_critical() {
        let a = alert_with("Whatever", "execve");
        let rows = vec![row("Whatever", "execve", OverrideAction::Escalate)];
        let d = evaluate(&rows, &a, RuntimeSeverity::Critical);
        match d {
            OverrideDecision::Applied {
                resolved_severity, ..
            } => assert_eq!(resolved_severity, Some(RuntimeSeverity::Critical)),
            OverrideDecision::PassThrough => panic!("expected applied"),
        }
    }

    #[test]
    fn downgrade_reduces_severity_one_tier() {
        let a = alert_with("Write below etc", "openat");
        let rows = vec![row("Write below etc", "openat", OverrideAction::Downgrade)];
        let d = evaluate(&rows, &a, RuntimeSeverity::High);
        match d {
            OverrideDecision::Applied {
                resolved_severity, ..
            } => assert_eq!(resolved_severity, Some(RuntimeSeverity::Medium)),
            OverrideDecision::PassThrough => panic!("expected applied"),
        }
    }

    #[test]
    fn downgrade_saturates_at_info() {
        let a = alert_with("Noisy rule", "execve");
        let rows = vec![row("Noisy rule", "execve", OverrideAction::Downgrade)];
        let d = evaluate(&rows, &a, RuntimeSeverity::Info);
        match d {
            OverrideDecision::Applied {
                resolved_severity, ..
            } => assert_eq!(resolved_severity, Some(RuntimeSeverity::Info)),
            OverrideDecision::PassThrough => panic!("expected applied"),
        }
    }

    #[test]
    fn allow_is_a_no_op_on_severity() {
        let a = alert_with("Some rule", "execve");
        let rows = vec![row("Some rule", "execve", OverrideAction::Allow)];
        let d = evaluate(&rows, &a, RuntimeSeverity::Low);
        match d {
            OverrideDecision::Applied {
                action,
                resolved_severity,
                ..
            } => {
                assert_eq!(action, OverrideAction::Allow);
                assert_eq!(resolved_severity, Some(RuntimeSeverity::Low));
            }
            OverrideDecision::PassThrough => panic!("expected applied"),
        }
    }

    #[test]
    fn override_for_other_rule_does_not_apply() {
        let a = alert_with("Rule A", "execve");
        let rows = vec![row("Rule B", "execve", OverrideAction::Deny)];
        let d = evaluate(&rows, &a, RuntimeSeverity::High);
        assert_eq!(d, OverrideDecision::PassThrough);
    }

    #[test]
    fn alert_subkey_falls_back_through_evt_type_then_proc_name() {
        let with_evt = alert_with("r", "execve");
        assert_eq!(alert_subkey(&with_evt), "execve");

        let mut without_evt = with_evt;
        without_evt.output_fields.remove("evt.type");
        // proc.name still present → "bash".
        assert_eq!(alert_subkey(&without_evt), "bash");

        without_evt.output_fields.remove("proc.name");
        // Nothing left → wildcard.
        assert_eq!(alert_subkey(&without_evt), SUBKEY_WILDCARD);
    }

    #[test]
    fn alert_subkey_uses_k8s_audit_verb() {
        let v = serde_json::json!({
            "rule": "Create privileged role-binding",
            "priority": "Critical",
            "source": "k8s_audit",
            "output_fields": {
                "ka.verb": "create"
            }
        });
        let a: FalcoAlert = serde_json::from_value(v).unwrap();
        assert_eq!(alert_subkey(&a), "create");
    }
}
