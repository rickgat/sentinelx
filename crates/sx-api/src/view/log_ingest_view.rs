//! Log-ingest DTOs.
//!
//! These views back the two log-ingestion endpoints exposed by
//! [`crate::controller::log_ingest`]:
//!
//! - `POST /v1/logs/ingest` — submit one raw payload + source-type token
//!   for parsing into a canonical OCSF event.
//! - `GET  /v1/logs?limit=N` — list the most-recent ingested events for
//!   the caller's tenant.
//!
//! ## Wire shape
//!
//! ```json
//! // POST /v1/logs/ingest
//! { "source": "cloudtrail", "payload": "{...raw CloudTrail JSON...}" }
//!
//! // GET /v1/logs?limit=50
//! {
//!   "data": {
//!     "items": [
//!       {
//!         "class_uid": 6003,
//!         "category_uid": 6,
//!         "time": "2026-06-12T10:30:01Z",
//!         "severity_id": 3,
//!         "raw": "{...}",
//!         "metadata": {
//!           "version": "1.1.0",
//!           "product": "AWS CloudTrail (us-east-1)",
//!           "source_type": "cloudtrail",
//!           "tenant_id": "01010101-…"
//!         },
//!         "observables": [
//!           { "name": "src_ip", "type": "ip", "value": "203.0.113.5" }
//!         ]
//!       }
//!     ]
//!   }
//! }
//! ```

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Max byte length of the raw payload accepted by the ingest endpoint.
/// Mirrors the per-event cap enforced by the parser layer.
pub const INGEST_MAX_PAYLOAD_BYTES: usize = 16 * 1024;

/// Maximum value the `limit` query parameter may take.
pub const LIST_MAX_LIMIT: u32 = 500;

/// `POST /v1/logs/ingest` request body.
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct IngestLogRequest {
    /// Parser source-type token (e.g. `"cloudtrail"`, `"syslog_rfc5424"`,
    /// `"suricata_eve"`).
    #[validate(length(min = 1, max = 64))]
    pub source: String,
    /// Raw payload bytes (must be valid UTF-8). Capped by
    /// [`INGEST_MAX_PAYLOAD_BYTES`] at the controller boundary.
    #[validate(length(min = 1, max = 16384))]
    pub payload: String,
}

/// `POST /v1/logs/ingest` response body.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IngestLogResponse {
    /// Always `1` for the single-event MVP surface.
    pub accepted: u32,
}

/// OCSF metadata projection (mirror of
/// [`sx_log_ingest::schema::OcsfMetadata`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OcsfMetadataView {
    /// OCSF schema version, e.g. `"1.1.0"`.
    pub version: String,
    /// Origin product label.
    pub product: String,
    /// Parser source-type token.
    pub source_type: String,
    /// Owning tenant id (UUID string).
    pub tenant_id: String,
}

/// OCSF observable projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservableView {
    /// Field name (e.g. `"src_ip"`).
    pub name: String,
    /// Type label (e.g. `"ip"`).
    #[serde(rename = "type")]
    pub kind: String,
    /// Value.
    pub value: String,
}

/// `GET /v1/logs` item projection — mirrors
/// [`sx_log_ingest::schema::OcsfEvent`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OcsfEventView {
    /// OCSF class id (e.g. `6003` API Activity).
    pub class_uid: i32,
    /// OCSF category id (e.g. `6` Application Activity).
    pub category_uid: i32,
    /// Event timestamp in RFC 3339.
    pub time: String,
    /// Canonical severity id 0..6.
    pub severity_id: i32,
    /// Raw payload (capped server-side).
    pub raw: String,
    /// Provenance + tenant metadata.
    pub metadata: OcsfMetadataView,
    /// Typed observables.
    pub observables: Vec<ObservableView>,
}

/// `GET /v1/logs` response envelope.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListLogsResponse {
    /// Newest-first projection.
    pub items: Vec<OcsfEventView>,
}

/// `PUT /v1/admin/log-ingest/tiers/{tenant_id}` request body (MED-001).
///
/// Sets the per-tenant ingest tier. `override_rate_per_sec` is optional;
/// when omitted the tier's default steady-state from `sx-config` is used.
/// When supplied, it takes precedence over the tier default and
/// proportionally scales burst headroom (so burst remains `2×` the
/// effective steady-state).
#[derive(Debug, Clone, Deserialize, Serialize, Validate)]
pub struct SetTenantTierRequest {
    /// One of `free`, `pro`, `enterprise`.
    #[validate(length(min = 1, max = 32))]
    pub tier: String,
    /// Optional per-tenant steady-state override (events/sec). When
    /// supplied, must be strictly positive.
    #[validate(range(min = 1))]
    pub override_rate_per_sec: Option<u32>,
}

/// `PUT /v1/admin/log-ingest/tiers/{tenant_id}` response body.
///
/// Echoes the effective rates after the mutation so the operator (or
/// dashboard) can confirm the change without an extra round-trip.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct TenantTierResponse {
    /// Tenant id (UUID string).
    pub tenant_id: String,
    /// Active tier (`free`, `pro`, `enterprise`).
    pub tier: String,
    /// Override applied (if any).
    pub override_rate_per_sec: Option<u32>,
    /// Effective steady-state events/sec used by the bucket.
    pub effective_per_sec_rate: u32,
    /// Effective burst ceiling used by the bucket.
    pub effective_burst: u32,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn ingest_request_validates_minimum_lengths() {
        let r = IngestLogRequest {
            source: String::new(),
            payload: "x".into(),
        };
        assert!(r.validate().is_err());

        let r2 = IngestLogRequest {
            source: "cloudtrail".into(),
            payload: String::new(),
        };
        assert!(r2.validate().is_err());

        let r3 = IngestLogRequest {
            source: "cloudtrail".into(),
            payload: "{}".into(),
        };
        assert!(r3.validate().is_ok());
    }

    #[test]
    fn ingest_request_rejects_oversized_payload() {
        let r = IngestLogRequest {
            source: "cloudtrail".into(),
            payload: "x".repeat(INGEST_MAX_PAYLOAD_BYTES + 1),
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn event_view_round_trips_through_json() {
        let v = OcsfEventView {
            class_uid: 6003,
            category_uid: 6,
            time: "2026-06-12T10:30:01Z".into(),
            severity_id: 3,
            raw: "{}".into(),
            metadata: OcsfMetadataView {
                version: "1.1.0".into(),
                product: "AWS CloudTrail".into(),
                source_type: "cloudtrail".into(),
                tenant_id: "t".into(),
            },
            observables: vec![ObservableView {
                name: "src_ip".into(),
                kind: "ip".into(),
                value: "203.0.113.5".into(),
            }],
        };
        let s = serde_json::to_string(&v).unwrap();
        let back: OcsfEventView = serde_json::from_str(&s).unwrap();
        assert_eq!(v, back);
        // type label is renamed via serde — confirm wire shape.
        assert!(s.contains("\"type\":\"ip\""));
    }

    #[test]
    fn list_response_serialises_with_empty_items() {
        let r = ListLogsResponse { items: Vec::new() };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"items\""));
    }
}
