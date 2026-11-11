//! Rule definition and the Condition DSL.
//!
//! A [`Rule`] is the *unit of configuration* for the SOC engine. It pairs an
//! id and a severity with a [`Condition`] tree that is evaluated against
//! incoming JSON events.
//!
//! # Condition DSL grammar (small-step)
//!
//! ```text
//!   condition ::= Eq           (field, value)
//!               | Contains     (field, substring)
//!               | GreaterThan  (field, number)
//!               | WithinLast   (duration, condition)
//!               | AnyOf        ([condition, ...])      -- short-circuit OR
//!               | AllOf        ([condition, ...])      -- short-circuit AND
//!
//!   field     ::= JSON pointer ("/" segment ("/" segment)*) | bare key
//!   value     ::= serde_json::Value (scalar)
//!   duration  ::= std::time::Duration
//! ```
//!
//! ## Field addressing
//!
//! Fields may be addressed either as a bare top-level key (`"actor"`) or
//! as a JSON pointer (`"/actor/id"`). Bare keys without a leading `/` are
//! treated as a single top-level segment; pointers traverse nested objects.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::alert::Severity;

pub mod impossible_travel;

pub use impossible_travel::{
    evaluate as evaluate_impossible_travel,
    evaluate_with_allowlist as evaluate_impossible_travel_with_allowlist, haversine_km,
    InMemoryLoginHistoryRepo, LoginHistoryRepo, LoginRecord, TenantVpnAllowlist, TravelAnomaly,
    TravelDecision,
};

/// A SOC rule.
///
/// Equality on `Rule` is structural and excludes the throttle window (since
/// runtime instances may have different throttles for the same logical rule).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Stable rule id; used for correlation throttling and audit trails.
    pub id: String,
    /// Human-readable name, surfaced in [`crate::alert::Alert::title`].
    pub name: String,
    /// Severity to stamp on alerts produced by this rule.
    pub severity: Severity,
    /// Predicate evaluated against incoming events.
    pub when: Condition,
    /// Minimum interval between two alerts with the same
    /// `(rule_id, tenant_id, kind)` triple. `None` means no throttling.
    pub throttle: Option<Duration>,
}

impl Rule {
    /// Build a rule with the given parts.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        severity: Severity,
        when: Condition,
        throttle: Option<Duration>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            severity,
            when,
            throttle,
        }
    }
}

/// The Condition DSL. See the module docs for the grammar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Condition {
    /// `Eq(field, value)` — the field equals the scalar value.
    Eq(String, Value),
    /// `Contains(field, substring)` — the field is a string and contains the
    /// given substring.
    Contains(String, String),
    /// `GreaterThan(field, n)` — the field is a number greater than `n`.
    GreaterThan(String, f64),
    /// `WithinLast(duration, inner)` — the event's RFC3339 `ts` is no older
    /// than `now - duration`, AND the inner condition holds.
    WithinLast(Duration, Box<Self>),
    /// `AnyOf(...)` — short-circuiting logical OR.
    AnyOf(Vec<Self>),
    /// `AllOf(...)` — short-circuiting logical AND.
    AllOf(Vec<Self>),
}

impl Condition {
    /// Evaluate this condition against `event`.
    ///
    /// Pure / total: never panics, never allocates more than the DSL tree.
    /// Returns `false` on any structural mismatch (e.g. asking for
    /// `GreaterThan` on a string field).
    #[must_use]
    pub fn matches(&self, event: &Value) -> bool {
        match self {
            Self::Eq(field, expected) => lookup(event, field).is_some_and(|v| v == expected),
            Self::Contains(field, needle) => lookup(event, field)
                .and_then(Value::as_str)
                .is_some_and(|s| s.contains(needle.as_str())),
            Self::GreaterThan(field, threshold) => lookup(event, field)
                .and_then(Value::as_f64)
                .is_some_and(|n| n > *threshold),
            Self::WithinLast(window, inner) => within_last(event, *window) && inner.matches(event),
            Self::AnyOf(conditions) => conditions.iter().any(|c| c.matches(event)),
            Self::AllOf(conditions) => conditions.iter().all(|c| c.matches(event)),
        }
    }
}

/// Resolve a `field` reference (bare key or JSON pointer) inside `event`.
fn lookup<'a>(event: &'a Value, field: &str) -> Option<&'a Value> {
    if field.starts_with('/') {
        event.pointer(field)
    } else {
        event.get(field)
    }
}

/// Check that the event's RFC3339 `ts` is no older than `now - window`.
///
/// If the event has no `ts` field, or it cannot be parsed, the predicate
/// returns `false` — i.e. malformed time excludes the event from the window.
fn within_last(event: &Value, window: Duration) -> bool {
    let Some(ts_str) = event.get("ts").and_then(Value::as_str) else {
        return false;
    };
    let Ok(ts) =
        time::OffsetDateTime::parse(ts_str, &time::format_description::well_known::Rfc3339)
    else {
        return false;
    };
    let Ok(window) = time::Duration::try_from(window) else {
        return false;
    };
    let now = time::OffsetDateTime::now_utc();
    let oldest_allowed = now - window;
    ts >= oldest_allowed
}
