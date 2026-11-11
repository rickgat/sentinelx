//! SOC alert + event-submission DTOs.
//!
//! These views back the two Phase-3.5 SOC endpoints exposed by
//! [`crate::controller::soc`]:
//!
//! - `GET  /v1/soc/alerts`  — list recent alerts from the in-memory
//!   `BufferAlertSink` projected to [`SocAlertView`].
//! - `POST /v1/soc/events`  — operators pump a single JSON event into the
//!   correlator for testing rule packs.
//!
//! ## Wire shape
//!
//! ```json
//! // GET /v1/soc/alerts
//! {
//!   "data": {
//!     "items": [
//!       {
//!         "id": "9c2c…",
//!         "severity": "high",
//!         "kind": "auth.bruteforce",
//!         "title": "5 failed logins in 1min",
//!         "fired_at": "2026-05-30T12:00:00Z",
//!         "tenant_id": null
//!       }
//!     ]
//!   },
//!   "meta": {"...": "..."}
//! }
//!
//! // POST /v1/soc/events
//! { "event": { "kind": "auth.login_failure_window", "count": 5 } }
//! ```

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Wire projection of a single buffered SOC alert.
///
/// This view intentionally omits the full `description` + `evidence` vector
/// from [`sx_soc::Alert`]: the list endpoint is a notification-row stream,
/// not a forensic dump.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocAlertView {
    /// Stable alert id (UUID v4 string).
    pub id: String,
    /// Severity bucket: `critical`, `high`, `medium`, `low`, `info`.
    pub severity: String,
    /// Coarse alert kind, e.g. `auth.bruteforce`.
    pub kind: String,
    /// Short single-line title.
    pub title: String,
    /// RFC 3339 timestamp the alert was constructed.
    pub fired_at: String,
    /// Tenant scope. `None` means "global" / not bound to a tenant.
    pub tenant_id: Option<String>,
}

/// `POST /v1/soc/events` request body.
///
/// `event` is forwarded into the correlator's mpsc sender verbatim, so any
/// JSON shape the registered rules understand is acceptable. The endpoint
/// is operator-only (RBAC: `soc:write`).
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct SubmitSocEventRequest {
    /// The raw event payload to push into the correlator channel.
    pub event: serde_json::Value,
}

/// `GET /v1/soc/alerts` response body — a buffered snapshot of alerts.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListSocAlertsResponse {
    /// Buffered alerts, oldest-first (matches `BufferAlertSink::snapshot`).
    pub items: Vec<SocAlertView>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn alert_view_round_trips_through_json() {
        let v = SocAlertView {
            id: "9c2c8b5e-…".into(),
            severity: "high".into(),
            kind: "auth.bruteforce".into(),
            title: "5 failed logins".into(),
            fired_at: "2026-05-30T12:00:00Z".into(),
            tenant_id: Some("tenant-7".into()),
        };
        let s = serde_json::to_string(&v).unwrap();
        let back: SocAlertView = serde_json::from_str(&s).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn submit_request_accepts_any_event_shape() {
        let r = SubmitSocEventRequest {
            event: serde_json::json!({"kind": "auth.login_failure_window", "count": 5}),
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn list_response_serialises_with_empty_items() {
        let r = ListSocAlertsResponse { items: Vec::new() };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"items\""));
    }

    #[test]
    fn alert_view_omits_no_fields() {
        let v = SocAlertView {
            id: "x".into(),
            severity: "info".into(),
            kind: "k".into(),
            title: "t".into(),
            fired_at: "1970-01-01T00:00:00Z".into(),
            tenant_id: None,
        };
        let s = serde_json::to_string(&v).unwrap();
        // Even null tenant_id should appear (default serde behaviour) so
        // clients can distinguish "global" from "missing".
        assert!(s.contains("\"tenant_id\""));
    }
}
