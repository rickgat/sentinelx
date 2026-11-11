//! Runtime (Falco) admin DTOs (HIGH-006).
//!
//! Backs the per-tenant Falco rule override admin surface:
//!
//! - `GET    /v1/admin/runtime/falco/overrides`
//! - `PUT    /v1/admin/runtime/falco/overrides`
//! - `DELETE /v1/admin/runtime/falco/overrides`
//!
//! Every mutation is audit-logged at the adapter layer; this module
//! only carries the wire shapes.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// One Falco rule override row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FalcoOverrideView {
    /// Falco rule name, mirrored verbatim from the alert wire
    /// (`rule`). Case-sensitive.
    pub rule_name: String,
    /// Within-rule discriminator. `"*"` is the wildcard (rule-wide).
    pub subkey: String,
    /// One of `allow`, `deny`, `escalate`, `downgrade`.
    pub action: String,
    /// Operator-supplied justification.
    pub reason: String,
    /// UUID of the operator who set the row.
    pub set_by: String,
    /// RFC 3339 / ISO-8601 timestamp.
    pub set_at: String,
}

/// `GET /v1/admin/runtime/falco/overrides` response — every row for the
/// caller's tenant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FalcoOverrideListResponse {
    /// Override rows for the tenant. Order is unspecified — the
    /// runtime evaluator handles wildcard-vs-exact precedence
    /// independently of insertion order.
    pub rows: Vec<FalcoOverrideView>,
}

/// `PUT /v1/admin/runtime/falco/overrides` request body.
///
/// Upserts one row keyed by `(rule_name, subkey)`. The body intentionally
/// carries the key so a single endpoint serves both create and update; the
/// implementation runs an `INSERT … ON CONFLICT … DO UPDATE`.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct PutFalcoOverrideRequest {
    /// Falco rule name. Length-bounded to match the Postgres CHECK.
    #[validate(length(min = 1, max = 256))]
    pub rule_name: String,
    /// Within-rule subkey. `"*"` for rule-wide. Length-bounded to
    /// match the Postgres CHECK.
    #[validate(length(min = 1, max = 128))]
    pub subkey: String,
    /// One of `allow`, `deny`, `escalate`, `downgrade`. Action
    /// validity is re-checked at the adapter so a malformed string
    /// never reaches the SQL bind.
    #[validate(length(min = 1, max = 16))]
    pub action: String,
    /// Operator-supplied justification — capped here to match the
    /// Postgres CHECK and surfaced verbatim in every audit row.
    #[validate(length(min = 1, max = 1024))]
    pub reason: String,
}

/// `DELETE /v1/admin/runtime/falco/overrides` request body — identifies
/// the row by `(rule_name, subkey)`. Idempotent: missing rows return
/// `200 OK` with `removed: false`.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct DeleteFalcoOverrideRequest {
    /// Falco rule name.
    #[validate(length(min = 1, max = 256))]
    pub rule_name: String,
    /// Within-rule subkey.
    #[validate(length(min = 1, max = 128))]
    pub subkey: String,
}

/// `DELETE /v1/admin/runtime/falco/overrides` response — true iff the
/// row was present (and is now gone), false on a no-op delete.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeleteFalcoOverrideResponse {
    /// True if a row was removed; false on a no-op delete (the row
    /// did not exist for the caller's tenant).
    pub removed: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use validator::Validate;

    #[test]
    fn put_request_validates_lengths() {
        let ok = PutFalcoOverrideRequest {
            rule_name: "Terminal shell in container".into(),
            subkey: "execve".into(),
            action: "deny".into(),
            reason: "noisy".into(),
        };
        ok.validate().unwrap();

        let bad_empty_rule = PutFalcoOverrideRequest {
            rule_name: String::new(),
            ..ok.clone()
        };
        assert!(bad_empty_rule.validate().is_err());

        let bad_long_subkey = PutFalcoOverrideRequest {
            subkey: "x".repeat(129),
            ..ok.clone()
        };
        assert!(bad_long_subkey.validate().is_err());

        let bad_long_reason = PutFalcoOverrideRequest {
            reason: "x".repeat(1025),
            ..ok
        };
        assert!(bad_long_reason.validate().is_err());
    }

    #[test]
    fn delete_request_validates_lengths() {
        let ok = DeleteFalcoOverrideRequest {
            rule_name: "Write below etc".into(),
            subkey: "*".into(),
        };
        ok.validate().unwrap();

        let bad = DeleteFalcoOverrideRequest {
            rule_name: String::new(),
            subkey: "x".into(),
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn view_round_trips_through_serde() {
        let v = FalcoOverrideView {
            rule_name: "r".into(),
            subkey: "execve".into(),
            action: "escalate".into(),
            reason: "MITRE T1611".into(),
            set_by: "00000000-0000-0000-0000-000000000001".into(),
            set_at: "2026-06-15T00:00:00Z".into(),
        };
        let s = serde_json::to_string(&v).unwrap();
        let back: FalcoOverrideView = serde_json::from_str(&s).unwrap();
        assert_eq!(back, v);
    }
}
