//! Mark security-relevant headers as sensitive so they cannot accidentally
//! end up in structured logs.
//!
//! Wraps `tower_http::sensitive_headers::SetSensitiveHeadersLayer` and
//! pins the header list to a vetted set.

use axum::http::header::{HeaderName, AUTHORIZATION, COOKIE};
use std::sync::OnceLock;
use tower_http::sensitive_headers::SetSensitiveHeadersLayer;

const X_API_KEY: HeaderName = HeaderName::from_static("x-api-key");
const PROXY_AUTHORIZATION: HeaderName = HeaderName::from_static("proxy-authorization");
const SET_COOKIE: HeaderName = HeaderName::from_static("set-cookie");

fn sensitive_headers() -> &'static [HeaderName] {
    static HEADERS: OnceLock<Vec<HeaderName>> = OnceLock::new();
    HEADERS.get_or_init(|| {
        vec![
            AUTHORIZATION,
            COOKIE,
            SET_COOKIE,
            PROXY_AUTHORIZATION,
            X_API_KEY,
        ]
    })
}

/// Build a layer that marks the headers above as sensitive on both the
/// request and response paths.
#[must_use]
pub fn layer() -> SetSensitiveHeadersLayer {
    SetSensitiveHeadersLayer::new(sensitive_headers().iter().cloned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{HeaderValue, Request, Response, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    #[test]
    fn header_list_contains_authorization_and_cookie() {
        let names = sensitive_headers();
        assert!(names.contains(&AUTHORIZATION));
        assert!(names.contains(&COOKIE));
        assert!(names.contains(&X_API_KEY));
    }

    // The layer is applied transparently — the test verifies it does not
    // break request handling. Actual redaction in log lines is a property
    // of the http::HeaderValue::is_sensitive flag and is exercised by
    // tower-http's own test suite; we just ensure the layer is wired up
    // and that requests with secret-bearing headers still produce a 200.
    #[tokio::test]
    async fn layer_does_not_break_request_handling() {
        let app = Router::new()
            .route("/x", get(|| async { Response::new(Body::from("ok")) }))
            .layer(layer());

        let mut req = Request::builder().uri("/x").body(Body::empty()).unwrap();
        // Insert a fake bearer token.
        req.headers_mut()
            .insert(AUTHORIZATION, HeaderValue::from_static("Bearer secret"));
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
