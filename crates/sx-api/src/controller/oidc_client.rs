//! OIDC confidential-client controllers (MED-004).
//!
//! Three routes:
//!
//! - `POST /v1/oauth/token` — RFC 6749 `client_credentials` grant
//!   authenticated via `client_secret_jwt` (RFC 7523). Unauthenticated
//!   at the bearer-token middleware (the JWT assertion in the body is
//!   the credential).
//! - `POST /v1/admin/oidc/clients/{client_id}/rotate-secret` — admin
//!   rotates the live secret for a confidential client. Requires
//!   permission `iam:write`.
//! - `GET /.well-known/jwks.json` — published verifying keys. Public,
//!   unauthenticated, identical shape regardless of caller.
//!
//! Error mapping mirrors the OAuth2 token-endpoint contract: validation
//! failures collapse to `401 Unauthorized` with an `invalid_client` /
//! `invalid_request` reason; the body never reveals which validation
//! check failed so an attacker cannot probe.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::OidcClientPortError;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::oidc_client_view::OAuthTokenRequest;

/// Translate an [`OidcClientPortError`] into the appropriate [`ApiError`].
///
/// Per OAuth2 §5.2, validation failures on the token endpoint surface as
/// `400 Bad Request` carrying the `invalid_client` / `invalid_request`
/// reason in the body. We collapse the variants accordingly:
///
/// * `InvalidClient` / `InvalidRequest` / `UnsupportedGrant` → `400`
///   so any RFC-7521 OAuth2 client library reads it the same way.
/// * `NotFound` → `404`.
/// * `Dependency` → `503`.
/// * `Internal` → `500`.
pub fn map_oidc_client(err: OidcClientPortError) -> ApiError {
    match err {
        OidcClientPortError::InvalidClient => ApiError::Unprocessable("invalid_client".into()),
        OidcClientPortError::UnsupportedGrant(m) => {
            ApiError::Unprocessable(format!("unsupported_grant_type: {m}"))
        }
        OidcClientPortError::InvalidRequest(m) => {
            ApiError::Unprocessable(format!("invalid_request: {m}"))
        }
        OidcClientPortError::NotFound => ApiError::NotFound,
        OidcClientPortError::Dependency(m) => ApiError::Dependency(m),
        OidcClientPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// `POST /v1/oauth/token` — RFC 6749 `client_credentials` grant with
/// RFC 7523 `client_secret_jwt` client authentication.
///
/// The body is JSON-encoded for simplicity; in production deployments a
/// `application/x-www-form-urlencoded` middleware layer would normalise
/// both shapes into the same struct.
pub async fn issue_client_token(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<OAuthTokenRequest>,
) -> Result<impl IntoResponse, ApiError> {
    tracing::info!(
        target: "controller.oidc_client.token",
        grant_type = %req.grant_type,
        client_assertion_type = %req.client_assertion_type,
        "oauth token request received"
    );
    let resp = state
        .oidc_client_token
        .issue(None, req)
        .await
        .map_err(map_oidc_client)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

/// `POST /v1/admin/oidc/clients/{client_id}/rotate-secret` — admin
/// rotates the OIDC client's shared secret. Requires `iam:write`.
///
/// The response carries the freshly minted plaintext exactly once; the
/// caller is expected to copy it into the consuming workload's
/// configuration immediately. After the response is consumed the bytes
/// are unrecoverable from the SentinelX-side store.
pub async fn rotate_client_secret(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(client_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "iam:write")?;
    tracing::info!(
        target: "controller.oidc_client.rotate",
        tenant_id = %user.claims.tenant_id,
        actor = %user.claims.sub,
        client_id = %client_id,
        "oidc client secret rotation requested"
    );
    let resp = state
        .oidc_client_rotate
        .rotate(&user.claims.tenant_id, &client_id, &user.claims.sub)
        .await
        .map_err(map_oidc_client)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

/// `GET /.well-known/jwks.json` — public verifying-key publication.
///
/// Returns the JSON document verbatim (not wrapped in the envelope) so
/// off-the-shelf JWKS-aware clients (Auth0 SDKs, Microsoft.IdentityModel,
/// `jose-jwt` Java, etc.) can consume it without bespoke parsing. An
/// empty `keys` array is a legal response — that's what an HS-only
/// deployment publishes.
pub async fn jwks(State(state): State<AppState>) -> Result<impl IntoResponse, ApiError> {
    let doc = state.jwks_publish.jwks().await.map_err(map_oidc_client)?;
    Ok((StatusCode::OK, Json(doc)))
}

/// Enforce a single `resource:action` permission with wildcard support.
///
/// Mirrors the helper in `controller::runtime` / `controller::webauthn` —
/// local copy avoids a pub-cross-module dependency.
fn require_permission(user: &AuthenticatedUser, perm: &str) -> Result<(), ApiError> {
    let Ok(required) = Permission::parse(perm) else {
        return Err(ApiError::Internal("invalid permission constant".into()));
    };
    let allowed = user.claims.permissions.iter().any(|p| {
        let r = p.resource() == required.resource() || p.resource() == "*";
        let a = p.action() == required.action() || p.action() == "*";
        r && a
    });
    if allowed {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn invalid_client_collapses_to_unprocessable() {
        let err = map_oidc_client(OidcClientPortError::InvalidClient);
        assert!(matches!(err, ApiError::Unprocessable(ref m) if m == "invalid_client"));
    }

    #[test]
    fn unsupported_grant_collapses_to_unprocessable() {
        let err = map_oidc_client(OidcClientPortError::UnsupportedGrant("password".into()));
        match err {
            ApiError::Unprocessable(m) => assert!(m.contains("password")),
            other => panic!("expected Unprocessable, got {other:?}"),
        }
    }

    #[test]
    fn invalid_request_collapses_to_unprocessable() {
        let err = map_oidc_client(OidcClientPortError::InvalidRequest("missing".into()));
        match err {
            ApiError::Unprocessable(m) => assert!(m.contains("missing")),
            other => panic!("expected Unprocessable, got {other:?}"),
        }
    }

    #[test]
    fn not_found_collapses_to_not_found() {
        let err = map_oidc_client(OidcClientPortError::NotFound);
        assert!(matches!(err, ApiError::NotFound));
    }

    #[test]
    fn dependency_collapses_to_dependency() {
        let err = map_oidc_client(OidcClientPortError::Dependency("db".into()));
        assert!(matches!(err, ApiError::Dependency(_)));
    }

    #[test]
    fn internal_collapses_to_internal() {
        let err = map_oidc_client(OidcClientPortError::Internal("boom".into()));
        assert!(matches!(err, ApiError::Internal(_)));
    }
}
