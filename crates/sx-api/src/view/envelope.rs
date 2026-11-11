//! Standard JSON envelopes.
//!
//! Every successful response is wrapped in [`ApiResponse<T>`]:
//!
//! ```json
//! {
//!   "data": {"...": "..."},
//!   "meta": {"request_id": "...", "ts": "2026-05-29T12:00:00Z"}
//! }
//! ```
//!
//! Every error response uses [`ApiErrorEnvelope`]:
//!
//! ```json
//! {
//!   "error": {
//!     "code": "FORBIDDEN",
//!     "message": "forbidden",
//!     "request_id": "...",
//!     "details": null
//!   }
//! }
//! ```

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Successful-response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Inner payload.
    pub data: T,
    /// Response metadata: request id and server timestamp.
    pub meta: ResponseMeta,
}

impl<T> ApiResponse<T> {
    /// Build an envelope with an empty request id (the request-id middleware
    /// rewrites it after `IntoResponse` runs).
    pub fn ok(data: T) -> Self {
        Self {
            data,
            meta: ResponseMeta::new(String::new()),
        }
    }

    /// Build an envelope bound to a specific request id. Useful in unit
    /// tests where the middleware is not involved.
    pub fn with_request_id(data: T, request_id: impl Into<String>) -> Self {
        Self {
            data,
            meta: ResponseMeta::new(request_id.into()),
        }
    }
}

/// Per-response metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMeta {
    /// Echoed request id (hex, no hyphens — see `sx_telemetry::new_request_id`).
    pub request_id: String,
    /// Server timestamp in RFC 3339 (UTC).
    pub ts: String,
}

impl ResponseMeta {
    /// Construct meta with the current UTC time.
    pub fn new(request_id: String) -> Self {
        let ts = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"));
        Self { request_id, ts }
    }
}

/// Wrapper for the error envelope so the JSON has a top-level `error` key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorEnvelope {
    /// Error payload.
    pub error: ApiErrorBody,
}

/// Inner payload of an error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorBody {
    /// Stable, machine-readable error code (e.g. `FORBIDDEN`).
    pub code: String,
    /// Human-readable, public message. Never contains internal details.
    pub message: String,
    /// Request id correlating the response with server logs.
    pub request_id: String,
    /// Optional structured details (e.g. per-field validation errors).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn ok_envelope_serialises() {
        let env = ApiResponse::with_request_id(serde_json::json!({"x": 1}), "rid-1");
        let v = serde_json::to_value(&env).unwrap();
        assert_eq!(v["data"]["x"], 1);
        assert_eq!(v["meta"]["request_id"], "rid-1");
        assert!(v["meta"]["ts"].as_str().is_some());
    }

    #[test]
    fn error_envelope_omits_null_details() {
        let env = ApiErrorEnvelope {
            error: ApiErrorBody {
                code: "BAD_REQUEST".into(),
                message: "bad".into(),
                request_id: "rid".into(),
                details: None,
            },
        };
        let s = serde_json::to_string(&env).unwrap();
        assert!(
            !s.contains("details"),
            "details should be omitted when None: {s}"
        );
    }

    #[test]
    fn error_envelope_keeps_details_when_present() {
        let env = ApiErrorEnvelope {
            error: ApiErrorBody {
                code: "UNPROCESSABLE_ENTITY".into(),
                message: "validation failed".into(),
                request_id: "rid".into(),
                details: Some(serde_json::json!({"email": "invalid"})),
            },
        };
        let s = serde_json::to_string(&env).unwrap();
        assert!(s.contains("details"));
        assert!(s.contains("email"));
    }
}
