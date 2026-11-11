//! Extractor that returns the request id (set by
//! [`crate::middleware::request_id::RequestIdLayer`]).
//!
//! Falls back to an empty string when no middleware has injected one. Handlers
//! that need a guaranteed non-empty id should pull it out of the response
//! envelope after the middleware has rewritten it.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use std::convert::Infallible;

use crate::middleware::request_id::RequestId;

/// Newtype around the request id string for handler use.
#[derive(Debug, Clone, Default)]
pub struct RequestIdExt(pub String);

#[axum::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for RequestIdExt {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let v = parts
            .extensions
            .get::<RequestId>()
            .map(|r| r.0.clone())
            .unwrap_or_default();
        Ok(Self(v))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::http::Request;

    #[tokio::test]
    async fn extracts_when_present() {
        let mut req: Request<()> = Request::builder().uri("/").body(()).unwrap();
        req.extensions_mut().insert(RequestId("abc".into()));
        let (mut parts, _body) = req.into_parts();
        let r = <RequestIdExt as FromRequestParts<()>>::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        assert_eq!(r.0, "abc");
    }

    #[tokio::test]
    async fn defaults_to_empty_when_absent() {
        let req: Request<()> = Request::builder().uri("/").body(()).unwrap();
        let (mut parts, _body) = req.into_parts();
        let r = <RequestIdExt as FromRequestParts<()>>::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        assert!(r.0.is_empty());
    }
}
