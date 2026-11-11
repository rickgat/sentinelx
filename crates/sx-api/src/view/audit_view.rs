//! Audit log search + export DTOs.
//!
//! These views back the two audit-read endpoints exposed by
//! [`crate::controller::audit`]:
//!
//! - `GET /v1/audit/search` — paginated search filtered by `since` / `action`
//!   / `actor`. RBAC: `audit:read`.
//! - `GET /v1/audit/export?format=ndjson` — streams audit rows as NDJSON
//!   (one JSON object per line). RBAC: `audit:read`. Capped at
//!   [`MAX_EXPORT_ENTRIES`] entries per request — audit chains can be
//!   arbitrarily large and exporters must page.
//!
//! ## Wire shape
//!
//! ```json
//! // GET /v1/audit/search?action=login&limit=20
//! {
//!   "data": {
//!     "items": [
//!       {
//!         "ts": "2026-05-30T12:00:00Z",
//!         "action": "login",
//!         "actor": "user:01HW…",
//!         "resource_kind": "session",
//!         "resource_id": "ses-1",
//!         "request_id": "abcd…",
//!         "tenant_id": "01010101-0101-0101-0101-010101010101"
//!       }
//!     ],
//!     "has_more": false
//!   },
//!   "meta": {"...": "..."}
//! }
//! ```
//!
//! The export endpoint does NOT use the standard JSON envelope: each line
//! is exactly one [`AuditEntryView`] serialised as compact JSON, terminated
//! by `\n`. The body's `Content-Type` is `application/x-ndjson`.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Default page size for [`AuditSearchQuery::effective_limit`].
pub const DEFAULT_SEARCH_LIMIT: u32 = 50;

/// Hard cap on [`AuditSearchQuery::effective_limit`].
///
/// 1000 is the largest page the API will return in a single response. Past
/// that, callers MUST page via `since`.
pub const MAX_SEARCH_LIMIT: u32 = 1_000;

/// Hard cap on the number of entries [`crate::controller::audit::export_ndjson`]
/// will stream in one response.
///
/// Audit chains can grow to millions of entries; this cap keeps a single
/// HTTP response bounded in size and CPU. Operators who need a full
/// snapshot must page by advancing `since`.
pub const MAX_EXPORT_ENTRIES: usize = 10_000;

/// Wire projection of a single audit entry.
///
/// This view intentionally omits the SHA-256 / HMAC chain fields from
/// [`sx_audit::model::entry::AuditEntry`]: the search/export endpoints are
/// for **operator triage**, not forensic chain verification. Use the
/// dedicated verify endpoint for tamper-evidence reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntryView {
    /// RFC 3339 timestamp the action occurred at.
    pub ts: String,
    /// Snake-case action code (e.g. `login`, `engagement_created`).
    pub action: String,
    /// Actor identifier. Format is `kind:id` where `kind` is one of
    /// `user`, `service`, `system`.
    pub actor: String,
    /// Coarse resource kind, e.g. `engagement`, `session`, `finding`.
    pub resource_kind: String,
    /// Resource identifier (usually a uuid string).
    pub resource_id: String,
    /// Correlation id of the originating HTTP request.
    pub request_id: String,
    /// Tenant scope. Stored as a string so the wire shape is stable across
    /// tenant-id encoding changes upstream.
    pub tenant_id: String,
}

/// `GET /v1/audit/search` query string.
///
/// All fields are optional. `limit` defaults to [`DEFAULT_SEARCH_LIMIT`]
/// and is capped at [`MAX_SEARCH_LIMIT`] (see
/// [`Self::effective_limit`]).
#[derive(Debug, Clone, Default, Deserialize, Serialize, Validate)]
pub struct AuditSearchQuery {
    /// Lower-bound RFC 3339 timestamp (inclusive). Only entries whose `ts`
    /// is `>= since` are returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    /// Exact action filter (snake_case code). Matched against
    /// [`AuditEntryView::action`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Exact actor filter. Matched against [`AuditEntryView::actor`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Page size, defaults to [`DEFAULT_SEARCH_LIMIT`]; max
    /// [`MAX_SEARCH_LIMIT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[validate(range(min = 1, max = 1_000))]
    pub limit: Option<u32>,
}

impl AuditSearchQuery {
    /// Effective page size: defaults to [`DEFAULT_SEARCH_LIMIT`] when
    /// missing, capped to [`MAX_SEARCH_LIMIT`].
    #[must_use]
    pub fn effective_limit(&self) -> u32 {
        self.limit
            .unwrap_or(DEFAULT_SEARCH_LIMIT)
            .min(MAX_SEARCH_LIMIT)
    }
}

/// `GET /v1/audit/search` response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditSearchResponse {
    /// Matching entries, newest-first (the adapter sorts).
    pub items: Vec<AuditEntryView>,
    /// `true` when more entries match the filter past the returned page.
    /// Callers should advance `since` to continue.
    pub has_more: bool,
}

/// `GET /v1/audit/export` query string.
///
/// Currently only `format=ndjson` is accepted (validated at the controller
/// layer). `since` filters the same way as
/// [`AuditSearchQuery::since`].
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AuditExportQuery {
    /// Export format. Only `ndjson` is supported at this revision.
    #[serde(default)]
    pub format: Option<String>,
    /// Lower-bound RFC 3339 timestamp (inclusive).
    #[serde(default)]
    pub since: Option<String>,
}

// ---------------------------------------------------------------------------
// Audit replay (time-travel) DTOs — P3-009
// ---------------------------------------------------------------------------

/// `GET /v1/audit/replay` query string.
///
/// Reconstructs the ordered mutation timeline for a single entity scoped
/// to the authenticated tenant.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditReplayQuery {
    /// Snake-case aggregate kind. One of `engagement`, `finding`, `user`,
    /// `asset`.
    pub entity_type: String,
    /// Aggregate identifier — usually a UUID rendered as a string.
    pub entity_id: String,
    /// Optional RFC 3339 lower bound (inclusive) on event `ts`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Optional RFC 3339 upper bound (inclusive) on event `ts`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

/// `GET /v1/audit/diff` query string.
///
/// Both endpoints share the same entity-keying parameters; only the
/// timestamp semantics differ — diff requires both endpoints.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuditDiffQuery {
    /// Snake-case aggregate kind.
    pub entity_type: String,
    /// Aggregate identifier.
    pub entity_id: String,
    /// Required RFC 3339 lower endpoint.
    pub from: String,
    /// Required RFC 3339 upper endpoint.
    pub to: String,
}

/// Single event in the replay timeline.
///
/// Mirrors `sx_audit::TimelineEvent` but the `ts` field is rendered as a
/// string for ergonomic JSON consumption from the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditTimelineEventView {
    /// Sequence number of the underlying entry.
    pub seq: u64,
    /// RFC 3339 timestamp the action occurred at.
    pub ts: String,
    /// Snake-case action code.
    pub action: String,
    /// Pre-image snapshot (when present).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<serde_json::Value>,
    /// Post-image snapshot (when present).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<serde_json::Value>,
}

/// `GET /v1/audit/replay` response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditReplayResponse {
    /// Echoed back for client convenience.
    pub entity_type: String,
    /// Echoed back for client convenience.
    pub entity_id: String,
    /// `true` when the audit chain verified end-to-end across this
    /// tenant. **Clients MUST surface a warning when this is `false`** —
    /// the events may be tampered.
    pub chain_verified: bool,
    /// Verification failure description when `chain_verified` is
    /// `false`. `None` on the happy path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_error: Option<String>,
    /// Ordered mutations (oldest-first).
    pub events: Vec<AuditTimelineEventView>,
}

/// `GET /v1/audit/diff` response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditDiffResponse {
    /// Echoed back for client convenience.
    pub entity_type: String,
    /// Echoed back for client convenience.
    pub entity_id: String,
    /// RFC 3339 lower endpoint.
    pub from_ts: String,
    /// RFC 3339 upper endpoint.
    pub to_ts: String,
    /// State at `from_ts`. `None` if the entity did not yet exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<serde_json::Value>,
    /// State at `to_ts`. `None` if the entity was already deleted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<serde_json::Value>,
    /// `true` when the audit chain verified.
    pub chain_verified: bool,
    /// Verification failure description when `chain_verified` is
    /// `false`. `None` on the happy path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_error: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample_view() -> AuditEntryView {
        AuditEntryView {
            ts: "2026-05-30T12:00:00Z".into(),
            action: "login".into(),
            actor: "user:01HW".into(),
            resource_kind: "session".into(),
            resource_id: "ses-1".into(),
            request_id: "req-1".into(),
            tenant_id: "01010101-0101-0101-0101-010101010101".into(),
        }
    }

    #[test]
    fn entry_view_round_trips_through_json() {
        let v = sample_view();
        let s = serde_json::to_string(&v).unwrap();
        let back: AuditEntryView = serde_json::from_str(&s).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn search_query_default_limit_is_fifty() {
        let q = AuditSearchQuery::default();
        assert_eq!(q.effective_limit(), DEFAULT_SEARCH_LIMIT);
    }

    #[test]
    fn search_query_caps_limit_at_thousand() {
        let q = AuditSearchQuery {
            limit: Some(9_999),
            ..AuditSearchQuery::default()
        };
        // `Validate` would reject 9_999, but `effective_limit` is a
        // defence-in-depth clamp for callers that bypass the validator.
        assert_eq!(q.effective_limit(), MAX_SEARCH_LIMIT);
    }

    #[test]
    fn search_query_validates_limit_below_max() {
        let q = AuditSearchQuery {
            limit: Some(1_000),
            ..AuditSearchQuery::default()
        };
        assert!(q.validate().is_ok());
    }

    #[test]
    fn search_query_rejects_limit_above_max() {
        let q = AuditSearchQuery {
            limit: Some(1_001),
            ..AuditSearchQuery::default()
        };
        assert!(q.validate().is_err());
    }

    #[test]
    fn search_query_rejects_zero_limit() {
        let q = AuditSearchQuery {
            limit: Some(0),
            ..AuditSearchQuery::default()
        };
        assert!(q.validate().is_err());
    }

    #[test]
    fn search_response_serialises_empty_items() {
        let r = AuditSearchResponse {
            items: Vec::new(),
            has_more: false,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"items\""));
        assert!(s.contains("\"has_more\""));
    }

    #[test]
    fn export_query_round_trips() {
        let q = AuditExportQuery {
            format: Some("ndjson".into()),
            since: Some("2026-05-01T00:00:00Z".into()),
        };
        let s = serde_json::to_string(&q).unwrap();
        let back: AuditExportQuery = serde_json::from_str(&s).unwrap();
        assert_eq!(back.format.as_deref(), Some("ndjson"));
        assert_eq!(back.since.as_deref(), Some("2026-05-01T00:00:00Z"));
    }

    #[test]
    fn max_export_entries_is_ten_thousand() {
        assert_eq!(MAX_EXPORT_ENTRIES, 10_000);
    }

    #[test]
    fn replay_query_round_trips_through_json() {
        let q = AuditReplayQuery {
            entity_type: "user".into(),
            entity_id: "u-1".into(),
            from: Some("2026-01-01T00:00:00Z".into()),
            to: Some("2026-02-01T00:00:00Z".into()),
        };
        let s = serde_json::to_string(&q).unwrap();
        let back: AuditReplayQuery = serde_json::from_str(&s).unwrap();
        assert_eq!(back.entity_type, "user");
        assert_eq!(back.entity_id, "u-1");
        assert!(back.from.is_some());
        assert!(back.to.is_some());
    }

    #[test]
    fn replay_response_serialises_with_chain_flag() {
        let r = AuditReplayResponse {
            entity_type: "engagement".into(),
            entity_id: "e-1".into(),
            chain_verified: true,
            chain_error: None,
            events: vec![AuditTimelineEventView {
                seq: 1,
                ts: "2026-05-30T12:00:00Z".into(),
                action: "engagement_created".into(),
                before: None,
                after: Some(serde_json::json!({"name": "v1"})),
            }],
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"chain_verified\":true"));
        assert!(s.contains("\"events\""));
        // `chain_error` omitted when `None`.
        assert!(!s.contains("chain_error"));
    }

    #[test]
    fn diff_response_includes_before_and_after_keys() {
        let d = AuditDiffResponse {
            entity_type: "finding".into(),
            entity_id: "f-1".into(),
            from_ts: "2026-01-01T00:00:00Z".into(),
            to_ts: "2026-02-01T00:00:00Z".into(),
            before: Some(serde_json::json!({"status": "open"})),
            after: Some(serde_json::json!({"status": "triaged"})),
            chain_verified: true,
            chain_error: None,
        };
        let s = serde_json::to_string(&d).unwrap();
        assert!(s.contains("\"before\""));
        assert!(s.contains("\"after\""));
    }
}
