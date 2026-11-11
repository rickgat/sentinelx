//! API DAST (P2-013) view layer.
//!
//! Wire shapes accepted and returned by:
//!
//! * `POST /v1/discovery/dast/scan` — multipart upload carrying
//!   the Postman v2.1 collection, the target base URL, an optional
//!   bearer token, and an optional comma-separated list of IDOR probe
//!   ids. The response is an [`ApiDastScanResponse`] wrapping the
//!   projected scan result.
//! * `GET /v1/discovery/dast/scans` — newest-first list of previously
//!   persisted scans for the caller's tenant.
//!
//! Multipart parts accepted by `POST /v1/discovery/dast/scan`:
//!
//! * `postman` (alias: `collection`) — required. The bytes of the
//!   Postman v2.1 JSON collection.
//! * `base_url` (alias: `target` / `base-url`) — required. The
//!   `http(s)://...` URL the scanner substitutes for `{{baseUrl}}`.
//! * `bearer` (alias: `token` / `authorization`) — optional. Forwarded
//!   to every replayed request and stripped for the auth-bypass shadow
//!   probe. The value is **never** logged.
//! * `idor_probe_ids` (alias: `probe_ids`) — optional comma-separated
//!   list of known other-tenant ids the scanner is permitted to swap
//!   into resource-id segments.
//!
//! The view layer never owns scan logic — it only projects the port
//! shapes onto a stable wire schema.

use serde::{Deserialize, Serialize};

use crate::port::ApiDastScanResultView;

/// `POST /v1/discovery/dast/scan` response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiDastScanResponse {
    /// Projected scan result.
    pub result: ApiDastScanResultView,
}

/// `GET /v1/discovery/dast/scans` response body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiDastListResponse {
    /// Persisted scans for the caller's tenant, newest-first.
    pub items: Vec<ApiDastScanResultView>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::port::ApiDastFindingView;

    fn sample() -> ApiDastScanResultView {
        ApiDastScanResultView {
            scan_id: "01J0000000000000000000000".into(),
            tenant_id: "t1".into(),
            collection_name: "demo".into(),
            base_url: "https://api.example.com".into(),
            started_at: "1970-01-01T00:00:00Z".into(),
            ended_at: "1970-01-01T00:00:01Z".into(),
            requests_sent: 1,
            findings: vec![ApiDastFindingView {
                check_id: "auth-bypass".into(),
                severity: "high".into(),
                method: "GET".into(),
                url: "https://api.example.com/users/42".into(),
                message: "no Authorization required".into(),
                remediation: None,
                source_item: None,
            }],
        }
    }

    #[test]
    fn scan_response_round_trips() {
        let resp = ApiDastScanResponse { result: sample() };
        let raw = serde_json::to_string(&resp).unwrap();
        let back: ApiDastScanResponse = serde_json::from_str(&raw).unwrap();
        assert_eq!(back, resp);
    }

    #[test]
    fn list_response_round_trips() {
        let resp = ApiDastListResponse {
            items: vec![sample()],
        };
        let raw = serde_json::to_string(&resp).unwrap();
        let back: ApiDastListResponse = serde_json::from_str(&raw).unwrap();
        assert_eq!(back, resp);
    }
}
