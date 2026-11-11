//! Evaluation result returned by [`crate::engine::PolicyEngine`].

use serde::{Deserialize, Serialize};

/// Outcome of a single policy evaluation.
///
/// A decision is `allow == true` iff *no* deny rule fired. When at least one
/// rule fires, `reasons` carries human-readable explanations (one per fired
/// rule) and `rule_ids` carries the canonical id of each fired rule so callers
/// can correlate with audit logs and dashboards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// `true` when the input is permitted (no deny rule matched).
    pub allow: bool,
    /// Human-readable rationale, one entry per fired rule. Empty on allow.
    pub reasons: Vec<String>,
    /// Identifiers of fired rules in the order they were evaluated. Empty on allow.
    pub rule_ids: Vec<String>,
}

impl Decision {
    /// Construct an unconditional allow decision (no rules fired).
    #[must_use]
    pub const fn allow() -> Self {
        Self {
            allow: true,
            reasons: Vec::new(),
            rule_ids: Vec::new(),
        }
    }

    /// Construct a deny decision from a non-empty collection of fired rules.
    ///
    /// `reasons` and `rule_ids` must be the same length and ordered
    /// correspondingly. The function does not enforce this at the type level
    /// because the caller (the engine) always populates them in lock-step.
    #[must_use]
    pub const fn deny(reasons: Vec<String>, rule_ids: Vec<String>) -> Self {
        Self {
            allow: false,
            reasons,
            rule_ids,
        }
    }
}

impl Default for Decision {
    fn default() -> Self {
        Self::allow()
    }
}
