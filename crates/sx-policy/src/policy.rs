//! Policy data model: top-level [`Policy`] plus the [`JsonPolicy`] DSL.
//!
//! The DSL is intentionally minimal. Each [`JsonPolicy`] is a list of
//! `deny_if` rules — if any rule matches the input, the [`crate::Decision`] is
//! deny. Three operators are supported:
//!
//! * `eq` — strict equality against a scalar (string, number, bool, null).
//! * `in` — membership in an array of scalars.
//! * `match` — regex match against the string form of the field.
//!
//! Fields are addressed by dot-separated JSON Pointer-ish paths
//! (e.g. `"user.name"`, `"request.headers.authorization"`). Array indexing is
//! not currently supported; if needed later it should be added as an explicit
//! `[N]` segment to keep the path language unambiguous.

use serde::{Deserialize, Serialize};

use crate::error::PolicyError;

/// Top-level policy as stored / transmitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Stable identifier — typically a slug or UUID assigned by the policy
    /// store. The engine does not interpret this beyond echoing it in logs.
    pub id: String,
    /// Backend-specific source.
    pub source: PolicySource,
}

impl Policy {
    /// Build a `Policy` carrying a JSON DSL document.
    #[must_use]
    pub const fn from_json(id: String, json: JsonPolicy) -> Self {
        Self {
            id,
            source: PolicySource::Json(json),
        }
    }

    /// Build a `Policy` carrying a Rego source string. Note: the default
    /// engine cannot evaluate Rego; supply a backend that handles
    /// [`PolicySource::Rego`] before calling
    /// [`crate::engine::PolicyEngine::evaluate`].
    #[must_use]
    pub const fn from_rego(id: String, rego: String) -> Self {
        Self {
            id,
            source: PolicySource::Rego(rego),
        }
    }
}

/// Discriminated union of supported policy languages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicySource {
    /// Rego source string (OPA). Reserved — see crate-level docs.
    Rego(String),
    /// In-process JSON DSL — see [`JsonPolicy`].
    Json(JsonPolicy),
}

/// JSON DSL document: a list of deny-if rules.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonPolicy {
    /// Rules evaluated in declaration order. Empty list = unconditional allow.
    #[serde(default)]
    pub deny_if: Vec<PolicyRule>,
}

impl JsonPolicy {
    /// Parse a JSON document into a [`JsonPolicy`]. Bubbles `serde_json`
    /// errors up as [`PolicyError::Parse`].
    pub fn from_json_str(src: &str) -> Result<Self, PolicyError> {
        serde_json::from_str(src).map_err(|e| PolicyError::Parse(e.to_string()))
    }
}

/// Operator namespace for [`PolicyRule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleOp {
    /// Equality against a scalar.
    Eq,
    /// Membership in a list of scalars.
    In,
    /// Regex match against the string form of the field.
    #[serde(rename = "match")]
    Match,
}

/// Value carried by a rule. The shape depends on the operator; the engine
/// validates the pairing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RuleValue {
    /// String literal — used by `eq` (against string scalars) and `match`.
    Str(String),
    /// Integer literal — used by `eq`.
    Int(i64),
    /// Boolean literal — used by `eq`.
    Bool(bool),
    /// List of strings — used by `in`.
    StrList(Vec<String>),
    /// List of integers — used by `in`.
    IntList(Vec<i64>),
}

/// A single deny-if rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Stable identifier. Surfaced in [`crate::Decision::rule_ids`] when the rule fires.
    pub id: String,
    /// Dot-separated path into the input document (e.g. `"user.name"`).
    pub field: String,
    /// Operator to apply.
    pub op: RuleOp,
    /// Operand for the operator.
    pub value: RuleValue,
    /// Optional human-readable explanation. When absent the engine
    /// synthesises one of the form `"rule <id> fired"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
