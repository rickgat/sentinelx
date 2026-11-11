//! Prometheus scrape endpoint: `GET /metrics`.
//!
//! Returns the contents of the process-wide registry encoded in the
//! Prometheus text exposition format (`text/plain; version=0.0.4`). The
//! route is registered on the **public** sub-router and is therefore
//! reachable without a bearer token; deployments that want to gate the
//! endpoint can do so at the ingress / service mesh layer.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::metrics::render_text_exposition;

/// `GET /metrics` — render the Prometheus registry.
pub async fn scrape() -> Response {
    let (body, content_type) = render_text_exposition();
    (StatusCode::OK, [(header::CONTENT_TYPE, content_type)], body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn scrape_returns_text_plain_with_version() {
        let resp = scrape().await;
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(ct, "text/plain; version=0.0.4");
        let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
        let s = String::from_utf8(body.to_vec()).unwrap();
        // Body may be empty on a freshly initialised registry, but it
        // must be a valid UTF-8 string and not include a leading newline
        // surprise.
        assert!(s.is_empty() || s.contains("# HELP") || s.contains("sx_"));
    }
}
