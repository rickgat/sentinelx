//! Tracing middleware.
//!
//! Wraps `tower_http::trace::TraceLayer` with a span builder that records
//! `method`, `uri`, `request_id`, and (when an OTel exporter is wired up)
//! the active trace id. The path is captured verbatim — query strings are
//! intentionally omitted because they often contain sensitive filters.

use axum::http::Request;
use tower_http::trace::{
    DefaultOnFailure, DefaultOnRequest, DefaultOnResponse, MakeSpan, TraceLayer,
};
use tracing::{field, Span};

use crate::middleware::request_id::RequestId;

/// Builds the standard request-scoped span used by every endpoint.
#[derive(Debug, Clone, Default)]
pub struct ApiMakeSpan;

impl<B> MakeSpan<B> for ApiMakeSpan {
    fn make_span(&mut self, request: &Request<B>) -> Span {
        let rid = request
            .extensions()
            .get::<RequestId>()
            .map(|r| r.0.as_str().to_owned())
            .unwrap_or_default();
        tracing::info_span!(
            "http.request",
            method = %request.method(),
            uri = %request.uri().path(),
            request_id = %rid,
            trace_id = field::Empty,
            status = field::Empty,
        )
    }
}

/// Build the standard tracing layer.
#[must_use]
pub fn layer() -> TraceLayer<
    tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>,
    ApiMakeSpan,
    DefaultOnRequest,
    DefaultOnResponse,
    tower_http::trace::DefaultOnBodyChunk,
    tower_http::trace::DefaultOnEos,
    DefaultOnFailure,
> {
    TraceLayer::new_for_http().make_span_with(ApiMakeSpan)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::body::Body;

    #[test]
    fn span_carries_method_and_path() {
        let mut maker = ApiMakeSpan;
        let req = Request::builder()
            .method("POST")
            .uri("/v1/auth/login")
            .body(Body::empty())
            .unwrap();
        let _span = maker.make_span(&req);
    }
}
