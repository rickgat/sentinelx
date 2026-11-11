//! Request-id middleware.
//!
//! Looks for `X-Request-Id` on the inbound request. If absent, generates a
//! UUID v7 (mirrors the helper exposed by `sx-telemetry`, re-implemented
//! locally so this crate compiles without that sibling). The id is inserted
//! into the request extensions as [`RequestId`] and echoed onto the
//! outgoing response.
//!
//! Down-stream `IntoResponse` impls (notably [`crate::ApiError`]) emit an
//! empty `request_id` field; this middleware rewrites the field in the
//! response body when the response is JSON. Doing so means handlers do not
//! need to reach into the request extensions to embed the id manually.

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderName, HeaderValue, Response};
use axum::middleware::Next;
use uuid::Uuid;

/// HTTP header name for the request id (read in & echoed out).
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");

/// Typed wrapper inserted into request/response extensions.
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

impl RequestId {
    /// Borrow the inner string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Generate a fresh, hyphen-less, lowercase-hex UUID v7.
#[must_use]
pub fn new_request_id() -> String {
    Uuid::now_v7().simple().to_string()
}

/// `axum::middleware::from_fn` callback.
pub async fn request_id_middleware(mut req: Request, next: Next) -> Response<Body> {
    let request_id = req
        .headers()
        .get(&REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map_or_else(new_request_id, ToOwned::to_owned);

    req.extensions_mut().insert(RequestId(request_id.clone()));
    if let Ok(hv) = HeaderValue::from_str(&request_id) {
        req.headers_mut().insert(&REQUEST_ID_HEADER, hv);
    }

    let mut res = next.run(req).await;
    if let Ok(hv) = HeaderValue::from_str(&request_id) {
        res.headers_mut().insert(&REQUEST_ID_HEADER, hv);
    }
    if is_json_response(&res) {
        res = rewrite_json_request_id(res, &request_id).await;
    }
    res
}

fn is_json_response(res: &Response<Body>) -> bool {
    res.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"))
}

async fn rewrite_json_request_id(res: Response<Body>, request_id: &str) -> Response<Body> {
    // Cap at 1 MiB to avoid buffering arbitrarily large responses.
    const MAX_REWRITE_BYTES: usize = 1024 * 1024;
    let (parts, body) = res.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, MAX_REWRITE_BYTES).await else {
        return Response::from_parts(parts, Body::empty());
    };
    let rewritten = serde_json::from_slice::<serde_json::Value>(&bytes).map_or_else(
        |_| bytes.to_vec(),
        |mut v| {
            inject_request_id(&mut v, request_id);
            serde_json::to_vec(&v).unwrap_or_else(|_| bytes.to_vec())
        },
    );
    Response::from_parts(parts, Body::from(rewritten))
}

fn inject_request_id(value: &mut serde_json::Value, request_id: &str) {
    if let serde_json::Value::Object(map) = value {
        if let Some(meta) = map.get_mut("meta").and_then(|v| v.as_object_mut()) {
            if let Some(rid) = meta.get_mut("request_id") {
                if rid.as_str().is_none_or(str::is_empty) {
                    *rid = serde_json::Value::String(request_id.to_owned());
                }
            }
        }
        if let Some(err) = map.get_mut("error").and_then(|v| v.as_object_mut()) {
            if let Some(rid) = err.get_mut("request_id") {
                if rid.as_str().is_none_or(str::is_empty) {
                    *rid = serde_json::Value::String(request_id.to_owned());
                }
            } else {
                err.insert(
                    "request_id".to_owned(),
                    serde_json::Value::String(request_id.to_owned()),
                );
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn new_request_id_is_lowercase_hex_32() {
        let id = new_request_id();
        assert_eq!(id.len(), 32);
        assert!(id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn inject_into_meta_overwrites_empty() {
        let mut v = serde_json::json!({"data": 1, "meta": {"request_id": "", "ts": "x"}});
        inject_request_id(&mut v, "abc");
        assert_eq!(v["meta"]["request_id"], "abc");
    }

    #[test]
    fn inject_into_error_overwrites_empty() {
        let mut v = serde_json::json!({"error": {"code": "X", "message": "x", "request_id": ""}});
        inject_request_id(&mut v, "abc");
        assert_eq!(v["error"]["request_id"], "abc");
    }

    #[test]
    fn inject_preserves_existing_non_empty() {
        let mut v = serde_json::json!({"meta": {"request_id": "keep", "ts": "x"}});
        inject_request_id(&mut v, "new");
        assert_eq!(v["meta"]["request_id"], "keep");
    }
}
