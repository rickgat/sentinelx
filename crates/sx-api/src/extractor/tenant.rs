//! `TenantScope` extractor — resolves the tenant uuid from the
//! [`AuthenticatedUser`] claims.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::error::ApiError;
use crate::middleware::auth::AuthenticatedUser;

/// Tenant scope resolved from the bearer token.
#[derive(Debug, Clone)]
pub struct TenantScope {
    /// Tenant uuid as carried in the `tenant_id` claim.
    pub tenant_id: String,
}

#[axum::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for TenantScope {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let user: &AuthenticatedUser = parts
            .extensions
            .get::<AuthenticatedUser>()
            .ok_or(ApiError::Unauthorized)?;
        Ok(Self {
            tenant_id: user.claims.tenant_id.clone(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::http::Request;
    use sx_iam::model::claims::{AccessClaims, TokenType};

    #[tokio::test]
    async fn resolves_tenant_from_claims() {
        let claims = AccessClaims {
            sub: "u".into(),
            tenant_id: "tenant-7".into(),
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
        let mut req: Request<()> = Request::builder().uri("/v1/x").body(()).unwrap();
        req.extensions_mut().insert(AuthenticatedUser { claims });
        let (mut parts, _body) = req.into_parts();
        let scope = <TenantScope as FromRequestParts<()>>::from_request_parts(&mut parts, &())
            .await
            .unwrap();
        assert_eq!(scope.tenant_id, "tenant-7");
    }
}
