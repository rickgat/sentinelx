//! `FromRequestParts` extractor that pulls the authenticated user off the
//! request extensions.
//!
//! Returns [`ApiError::Unauthorized`] when no
//! [`crate::middleware::auth::AuthenticatedUser`] is present — which can
//! only happen on routes that wrap the [`crate::middleware::auth::AuthLayer`]
//! and bypassed authentication (a programming error).

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::error::ApiError;
use crate::middleware::auth::AuthenticatedUser;

#[axum::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for AuthenticatedUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .cloned()
            .ok_or(ApiError::Unauthorized)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::http::Request;
    use sx_iam::model::claims::{AccessClaims, TokenType};

    #[tokio::test]
    async fn missing_extension_yields_unauthorized() {
        let req: Request<()> = Request::builder().uri("/v1/things").body(()).unwrap();
        let (mut parts, _body) = req.into_parts();
        let err = <AuthenticatedUser as FromRequestParts<()>>::from_request_parts(&mut parts, &())
            .await
            .unwrap_err();
        assert!(matches!(err, ApiError::Unauthorized));
    }

    #[tokio::test]
    async fn extension_yields_claims() {
        let claims = AccessClaims {
            sub: "u".into(),
            tenant_id: "t".into(),
            iss: "i".into(),
            aud: "a".into(),
            iat: 0,
            nbf: 0,
            exp: 0,
            jti: "j".into(),
            sid: "s".into(),
            token_type: TokenType::Access,
            roles: vec![],
            permissions: vec![],

            cred_id: None,
        };
        let mut req: Request<()> = Request::builder().uri("/v1/things").body(()).unwrap();
        req.extensions_mut().insert(AuthenticatedUser { claims });
        let (mut parts, _body) = req.into_parts();
        let extracted =
            <AuthenticatedUser as FromRequestParts<()>>::from_request_parts(&mut parts, &())
                .await
                .unwrap();
        assert_eq!(extracted.claims.sub, "u");
    }
}
