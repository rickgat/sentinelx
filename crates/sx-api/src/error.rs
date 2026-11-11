//! Public error type for HTTP handlers.
//!
//! `ApiError` is the only error type any handler is allowed to return.
//! `axum` uses [`IntoResponse`] to turn it into an HTTP response carrying
//! the standard JSON error envelope (see [`crate::view::envelope::ApiErrorBody`]).
//!
//! ## Status mapping
//!
//! | Variant            | HTTP | Code (string)           |
//! |--------------------|------|-------------------------|
//! | `BadRequest`       | 400  | `BAD_REQUEST`           |
//! | `Unauthorized`     | 401  | `UNAUTHORIZED`          |
//! | `Forbidden`        | 403  | `FORBIDDEN`             |
//! | `NotFound`         | 404  | `NOT_FOUND`             |
//! | `Conflict`         | 409  | `CONFLICT`              |
//! | `Unprocessable`    | 422  | `UNPROCESSABLE_ENTITY`  |
//! | `TooMany`          | 429  | `TOO_MANY_REQUESTS`     |
//! | `Dependency`       | 503  | `SERVICE_UNAVAILABLE`   |
//! | `Internal`         | 500  | `INTERNAL_ERROR`        |
//!
//! Internal error detail strings are **never** sent to the client. They are
//! logged at `error` level with the request id and the public message is
//! replaced with a generic `"an internal error occurred"`.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use thiserror::Error;

use crate::view::envelope::{ApiErrorBody, ApiErrorEnvelope};

/// HTTP-level error type returned by every controller.
///
/// Variants are intentionally coarse — they represent the categories of
/// outcomes the HTTP envelope cares about, not the underlying domain error.
/// Map domain errors into these via dedicated `From` impls so that callers
/// of a use case do not have to remember the wire mapping at each call
/// site.
#[derive(Debug, Error)]
pub enum ApiError {
    /// 400 Bad Request — the request was malformed (bad JSON, missing
    /// header, unparseable id, etc.).
    #[error("bad request: {0}")]
    BadRequest(String),

    /// 401 Unauthorized — the request did not carry valid credentials.
    #[error("unauthorized")]
    Unauthorized,

    /// 403 Forbidden — credentials were valid but lacked the required
    /// permission. `required` is logged but not sent to the client.
    #[error("forbidden")]
    Forbidden,

    /// 404 Not Found — the addressed resource does not exist (or the caller
    /// is not allowed to know whether it does).
    #[error("not found")]
    NotFound,

    /// 409 Conflict — the request collided with the resource's current
    /// state (e.g. a duplicate slug).
    #[error("conflict: {0}")]
    Conflict(String),

    /// 422 Unprocessable Entity — the request was syntactically valid but
    /// failed business validation (e.g. `validator::Validate`).
    #[error("unprocessable: {0}")]
    Unprocessable(String),

    /// 429 Too Many Requests — the per-(tenant, route) or per-IP bucket
    /// has been exhausted.
    #[error("too many requests")]
    TooMany,

    /// 503 Service Unavailable — a dependency (db, kill-switch, queue, …)
    /// is degraded or refusing requests.
    #[error("dependency unavailable: {0}")]
    Dependency(String),

    /// 500 Internal — programmer error or an unhandled domain error.
    /// The `String` payload is logged and stripped from the public response.
    #[error("internal error: {0}")]
    Internal(String),
}

impl ApiError {
    /// Status the HTTP layer should emit for this error.
    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::TooMany => StatusCode::TOO_MANY_REQUESTS,
            Self::Dependency(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Stable wire code surfaced inside the JSON error envelope. Clients may
    /// rely on these strings — they are part of the public contract.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::BadRequest(_) => "BAD_REQUEST",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::Forbidden => "FORBIDDEN",
            Self::NotFound => "NOT_FOUND",
            Self::Conflict(_) => "CONFLICT",
            Self::Unprocessable(_) => "UNPROCESSABLE_ENTITY",
            Self::TooMany => "TOO_MANY_REQUESTS",
            Self::Dependency(_) => "SERVICE_UNAVAILABLE",
            Self::Internal(_) => "INTERNAL_ERROR",
        }
    }

    /// The message the client is allowed to see.
    ///
    /// Internal errors are scrubbed to a generic sentence; all other variants
    /// pass their `Display` form through unchanged because their messages are
    /// already vetted (e.g. validation summaries, "not found").
    #[must_use]
    pub fn public_message(&self) -> String {
        match self {
            Self::BadRequest(m) => format!("bad request: {m}"),
            Self::Unauthorized => "unauthorized".to_owned(),
            Self::Forbidden => "forbidden".to_owned(),
            Self::NotFound => "not found".to_owned(),
            Self::Conflict(m) => format!("conflict: {m}"),
            Self::Unprocessable(m) => format!("unprocessable: {m}"),
            Self::TooMany => "too many requests".to_owned(),
            Self::Dependency(_) => "dependency unavailable".to_owned(),
            Self::Internal(_) => "an internal error occurred".to_owned(),
        }
    }

    /// Whether logging this error at `error` level is appropriate. Client
    /// errors (4xx other than 429 starvation) are noisy — log them at
    /// `warn` instead.
    #[must_use]
    pub const fn is_internal(&self) -> bool {
        matches!(self, Self::Internal(_) | Self::Dependency(_))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // The request id is propagated into the response by the
        // `request_id` middleware — by the time IntoResponse runs we
        // do not have direct access to the request extensions, so we
        // emit a placeholder here and let the middleware overwrite it
        // with the real value.
        let body = ApiErrorEnvelope {
            error: ApiErrorBody {
                code: self.code().to_owned(),
                message: self.public_message(),
                request_id: String::new(),
                details: None,
            },
        };

        if self.is_internal() {
            tracing::error!(error.code = self.code(), error.detail = %self, "internal api error");
        } else {
            tracing::warn!(error.code = self.code(), "client api error");
        }

        let status = self.status();
        let mut res = (status, Json(body)).into_response();
        // Always include content-type even if axum already sets it; this
        // makes the response stable for downstream proxies that strip
        // unknown headers.
        res.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        res
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[test]
    fn status_mapping_is_exhaustive() {
        assert_eq!(
            ApiError::BadRequest("x".into()).status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(ApiError::Unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(ApiError::Forbidden.status(), StatusCode::FORBIDDEN);
        assert_eq!(ApiError::NotFound.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            ApiError::Conflict("x".into()).status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            ApiError::Unprocessable("x".into()).status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(ApiError::TooMany.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            ApiError::Dependency("db".into()).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            ApiError::Internal("boom".into()).status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn codes_are_stable_strings() {
        assert_eq!(ApiError::Unauthorized.code(), "UNAUTHORIZED");
        assert_eq!(ApiError::TooMany.code(), "TOO_MANY_REQUESTS");
        assert_eq!(ApiError::Internal("x".into()).code(), "INTERNAL_ERROR");
    }

    #[test]
    fn internal_message_is_scrubbed() {
        let e = ApiError::Internal("password=hunter2".to_owned());
        let pub_msg = e.public_message();
        assert!(!pub_msg.contains("hunter2"));
        assert_eq!(pub_msg, "an internal error occurred");
    }

    #[test]
    fn dependency_message_is_scrubbed() {
        let e = ApiError::Dependency("postgres at 10.0.0.5:5432 down".to_owned());
        let pub_msg = e.public_message();
        assert!(!pub_msg.contains("10.0.0.5"));
        assert_eq!(pub_msg, "dependency unavailable");
    }

    #[test]
    fn is_internal_partitions_correctly() {
        assert!(ApiError::Internal("x".into()).is_internal());
        assert!(ApiError::Dependency("x".into()).is_internal());
        assert!(!ApiError::Unauthorized.is_internal());
        assert!(!ApiError::BadRequest("x".into()).is_internal());
    }

    #[tokio::test]
    async fn into_response_renders_envelope() {
        let res = ApiError::Forbidden.into_response();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        let ct = res
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(ct.starts_with("application/json"));
        let body_bytes = to_bytes(res.into_body(), 64 * 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(v["error"]["code"], "FORBIDDEN");
        assert_eq!(v["error"]["message"], "forbidden");
    }
}
