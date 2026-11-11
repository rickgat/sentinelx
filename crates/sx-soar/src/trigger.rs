//! Trigger predicate + the event payload it fires on.
//!
//! A workflow fires when an inbound [`TriggerEvent`] matches the workflow's
//! [`Trigger`] node predicate. Matching is structural and totally pure —
//! every predicate is evaluated on the event's tagged value with no I/O.

use serde::{Deserialize, Serialize};

/// Coarse severity scale used by the `FindingCreated` predicate.
///
/// The enum order is intentionally ascending so the comparison operators
/// (`<=`, `>=`) can be derived. A finding fires the trigger when its
/// severity satisfies `event_severity >= trigger.min_severity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational, no action required.
    Info,
    /// Low — worth knowing about.
    Low,
    /// Medium — investigate during business hours.
    Medium,
    /// High — investigate now.
    High,
    /// Critical — page on-call.
    Critical,
}

impl Severity {
    /// Stable machine label (lowercase) used in logs and serialised wire
    /// shapes.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Workflow trigger — the event-shape predicate carried by every
/// [`crate::graph::Node::Trigger`] node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Trigger {
    /// Fire on `finding_created` events whose severity ≥ `min_severity`.
    FindingCreated {
        /// Minimum severity (inclusive) that triggers the workflow.
        min_severity: Severity,
    },
    /// Fire on `bas_failed` events.
    BasFailed,
    /// Fire on `soc_alert_opened` events.
    SocAlertOpened,
    /// Fire on any inbound event — useful for global-fan-out workflows
    /// and tests.
    Any,
}

/// Inbound event the SOAR subsystem receives from the rest of the platform.
///
/// Each variant carries a small structured payload as `serde_json::Value`
/// so condition predicates and action templates can interpolate fields
/// without the trigger schema knowing what every action consumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TriggerEvent {
    /// A new finding has been created.
    FindingCreated {
        /// Finding uuid as a string.
        finding_id: String,
        /// Severity of the new finding.
        severity: Severity,
        /// Free-form payload (asset id, category, etc.).
        payload: serde_json::Value,
    },
    /// A BAS run failed.
    BasFailed {
        /// Run uuid (as string).
        run_id: String,
        /// Technique id that failed.
        technique_id: String,
        /// Free-form payload (engagement id, mode, error reason, ...).
        payload: serde_json::Value,
    },
    /// The SOC correlator opened a new alert.
    SocAlertOpened {
        /// Alert id.
        alert_id: String,
        /// Free-form payload (rule id, severity, fields, ...).
        payload: serde_json::Value,
    },
    /// Generic / out-of-band event. Useful for marketplace-style triggers
    /// dispatched from arbitrary event buses.
    Generic {
        /// Caller-defined event kind label (e.g. `"manual_dispatch"`).
        label: String,
        /// Free-form payload.
        payload: serde_json::Value,
    },
}

impl TriggerEvent {
    /// Stable, lowercase event-kind label used by the executor's run log
    /// and the dashboard. Mirrors the serde tag.
    #[must_use]
    pub fn kind(&self) -> &str {
        match self {
            Self::FindingCreated { .. } => "finding_created",
            Self::BasFailed { .. } => "bas_failed",
            Self::SocAlertOpened { .. } => "soc_alert_opened",
            Self::Generic { label, .. } => label.as_str(),
        }
    }

    /// Project the event onto a flat JSON object suitable for condition
    /// evaluation and template substitution. Every variant exposes
    /// `kind`, `id`, `severity?`, and the original `payload`.
    #[must_use]
    pub fn to_context(&self) -> serde_json::Value {
        match self {
            Self::FindingCreated {
                finding_id,
                severity,
                payload,
            } => serde_json::json!({
                "kind": "finding_created",
                "id": finding_id,
                "severity": severity.label(),
                "payload": payload,
            }),
            Self::BasFailed {
                run_id,
                technique_id,
                payload,
            } => serde_json::json!({
                "kind": "bas_failed",
                "id": run_id,
                "technique_id": technique_id,
                "payload": payload,
            }),
            Self::SocAlertOpened { alert_id, payload } => serde_json::json!({
                "kind": "soc_alert_opened",
                "id": alert_id,
                "payload": payload,
            }),
            Self::Generic { label, payload } => serde_json::json!({
                "kind": label,
                "id": serde_json::Value::Null,
                "payload": payload,
            }),
        }
    }
}

impl Trigger {
    /// `true` iff the trigger fires on the given event.
    ///
    /// Pure structural predicate — no I/O, no side effects.
    #[must_use]
    pub fn matches(&self, event: &TriggerEvent) -> bool {
        match (self, event) {
            (
                Self::FindingCreated { min_severity },
                TriggerEvent::FindingCreated { severity, .. },
            ) => severity >= min_severity,
            (Self::BasFailed, TriggerEvent::BasFailed { .. })
            | (Self::SocAlertOpened, TriggerEvent::SocAlertOpened { .. })
            | (Self::Any, _) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_ascending() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn finding_trigger_matches_at_or_above_threshold() {
        let t = Trigger::FindingCreated {
            min_severity: Severity::High,
        };
        assert!(t.matches(&TriggerEvent::FindingCreated {
            finding_id: "f1".into(),
            severity: Severity::High,
            payload: serde_json::Value::Null,
        }));
        assert!(t.matches(&TriggerEvent::FindingCreated {
            finding_id: "f2".into(),
            severity: Severity::Critical,
            payload: serde_json::Value::Null,
        }));
        assert!(!t.matches(&TriggerEvent::FindingCreated {
            finding_id: "f3".into(),
            severity: Severity::Medium,
            payload: serde_json::Value::Null,
        }));
    }

    #[test]
    fn any_trigger_matches_everything() {
        let t = Trigger::Any;
        assert!(t.matches(&TriggerEvent::BasFailed {
            run_id: "r".into(),
            technique_id: "t".into(),
            payload: serde_json::Value::Null,
        }));
        assert!(t.matches(&TriggerEvent::Generic {
            label: "manual".into(),
            payload: serde_json::Value::Null,
        }));
    }

    #[test]
    fn to_context_exposes_well_known_fields() {
        let ev = TriggerEvent::FindingCreated {
            finding_id: "F-1".into(),
            severity: Severity::Critical,
            payload: serde_json::json!({ "asset_id": "A-1" }),
        };
        let ctx = ev.to_context();
        assert_eq!(ctx["kind"], "finding_created");
        assert_eq!(ctx["id"], "F-1");
        assert_eq!(ctx["severity"], "critical");
        assert_eq!(ctx["payload"]["asset_id"], "A-1");
    }
}
