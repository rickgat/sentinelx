//! `WebAuthn` / FIDO2 MFA controller (P1-002).
//!
//! Backs four endpoints:
//!
//! - `POST /v1/auth/mfa/webauthn/register/start`  (authenticated)
//! - `POST /v1/auth/mfa/webauthn/register/finish` (authenticated)
//! - `POST /v1/auth/mfa/webauthn/login/start`     (public)
//! - `POST /v1/auth/mfa/webauthn/login/finish`    (public)
//!
//! The two register endpoints are authenticated — the caller is enrolling
//! a passkey on their already-logged-in session. The two login endpoints
//! are public because they are precisely the path that *establishes* the
//! authenticated session via FIDO2.
//!
//! ## Tracing
//!
//! - Raw challenge bytes, raw assertion bytes, and the full credential
//!   blob are NEVER logged. Handlers emit only the user id (when
//!   authenticated), email hash (when public), state id, and resulting
//!   cred_id (which is the W3C-public credential identifier).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_iam;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::webauthn_view::{
    LoginFinishRequest, LoginStartRequest, PutAaguidPolicyRequest, RegisterFinishRequest,
    RegisterStartRequest,
};

/// `POST /v1/auth/mfa/webauthn/register/start` — issue a registration
/// challenge for the authenticated user.
pub async fn register_start(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<RegisterStartRequest>,
) -> Result<impl IntoResponse, ApiError> {
    tracing::info!(
        target: "controller.webauthn.register_start",
        user_id = %user.claims.sub,
        tenant_id = %user.claims.tenant_id,
        label_present = req.label.is_some(),
        "webauthn register/start requested",
    );
    // `user_name` is best-effort taken from the `sub` claim — in
    // production the adapter will look up the user's email via the
    // shared user repository, but the controller already has a stable
    // string identifier and the user-visible label is mostly cosmetic.
    let resp = state
        .webauthn
        .register_start(&user.claims.tenant_id, &user.claims.sub, &user.claims.sub)
        .await
        .map_err(map_iam)?;
    // `label` is forwarded by stashing it alongside the state in the
    // adapter via a follow-up `register_finish` call; we DO NOT echo it
    // back here.
    let _ = req.label;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

/// `POST /v1/auth/mfa/webauthn/register/finish` — verify the
/// authenticator's attestation and persist the credential.
pub async fn register_finish(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<RegisterFinishRequest>,
) -> Result<impl IntoResponse, ApiError> {
    tracing::info!(
        target: "controller.webauthn.register_finish",
        user_id = %user.claims.sub,
        tenant_id = %user.claims.tenant_id,
        state_id = %req.state_id,
        "webauthn register/finish requested",
    );
    let resp = state
        .webauthn
        .register_finish(&user.claims.tenant_id, &user.claims.sub, req, None)
        .await
        .map_err(map_iam)?;
    Ok((StatusCode::CREATED, Json(ApiResponse::ok(resp))))
}

/// `POST /v1/auth/mfa/webauthn/login/start` — issue an authentication
/// challenge for the user identified by `email`. Public endpoint.
pub async fn login_start(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<LoginStartRequest>,
) -> Result<impl IntoResponse, ApiError> {
    tracing::info!(
        target: "controller.webauthn.login_start",
        email_len = req.email.len(),
        "webauthn login/start requested",
    );
    let resp = state
        .webauthn
        .login_start(&req.email)
        .await
        .map_err(map_iam)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

/// `POST /v1/auth/mfa/webauthn/login/finish` — verify the assertion and
/// mint a credential-bound access token. Public endpoint.
pub async fn login_finish(
    State(state): State<AppState>,
    Json(req): Json<LoginFinishRequest>,
) -> Result<impl IntoResponse, ApiError> {
    tracing::info!(
        target: "controller.webauthn.login_finish",
        state_id = %req.state_id,
        "webauthn login/finish requested",
    );
    let resp = state.webauthn.login_finish(req).await.map_err(map_iam)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

// ---------------------------------------------------------------------------
// HIGH-002 — AAGUID policy + MDS3 management endpoints
// ---------------------------------------------------------------------------

/// `GET /v1/iam/webauthn/aaguid-policy` — list the tenant's AAGUID
/// policy rows. Requires `webauthn:read`.
pub async fn list_aaguid_policy(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "webauthn:read")?;
    tracing::info!(
        target: "controller.webauthn.aaguid_policy.list",
        tenant_id = %user.claims.tenant_id,
        "aaguid policy list requested",
    );
    let resp = state
        .webauthn
        .list_aaguid_policy(&user.claims.tenant_id)
        .await
        .map_err(map_iam)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

/// `PUT /v1/iam/webauthn/aaguid-policy/{aaguid}` — upsert a policy row.
/// Requires `webauthn:write`. Every mutation is audit-logged at the
/// adapter (port impl) layer.
pub async fn put_aaguid_policy(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(aaguid): Path<String>,
    ValidatedJson(req): ValidatedJson<PutAaguidPolicyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "webauthn:write")?;
    tracing::info!(
        target: "controller.webauthn.aaguid_policy.put",
        tenant_id = %user.claims.tenant_id,
        user_id = %user.claims.sub,
        aaguid = %aaguid,
        action = %req.action,
        "aaguid policy upsert requested",
    );
    let resp = state
        .webauthn
        .put_aaguid_policy(&user.claims.tenant_id, &user.claims.sub, &aaguid, req)
        .await
        .map_err(map_iam)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

/// `DELETE /v1/iam/webauthn/aaguid-policy/{aaguid}` — clear the row.
/// Requires `webauthn:write`.
pub async fn delete_aaguid_policy(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(aaguid): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "webauthn:write")?;
    tracing::info!(
        target: "controller.webauthn.aaguid_policy.delete",
        tenant_id = %user.claims.tenant_id,
        user_id = %user.claims.sub,
        aaguid = %aaguid,
        "aaguid policy delete requested",
    );
    state
        .webauthn
        .delete_aaguid_policy(&user.claims.tenant_id, &aaguid)
        .await
        .map_err(map_iam)?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/iam/webauthn/mds-status` — local MDS cache health.
/// Requires `webauthn:read`.
pub async fn mds_status(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "webauthn:read")?;
    let resp = state.webauthn.mds_status().await.map_err(map_iam)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

/// `POST /v1/iam/webauthn/mds-refresh` — force-refresh the MDS cache.
///
/// Requires `webauthn:admin` (a strictly-tighter grant than
/// `webauthn:write` — the dashboard surfaces the button only to
/// platform admins).
pub async fn mds_refresh(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "webauthn:admin")?;
    tracing::info!(
        target: "controller.webauthn.mds_refresh",
        tenant_id = %user.claims.tenant_id,
        user_id = %user.claims.sub,
        "mds refresh requested",
    );
    let resp = state.webauthn.mds_refresh().await.map_err(map_iam)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

/// `GET /v1/iam/webauthn/credentials` — list active credentials for the
/// authenticated user enriched with MDS metadata. Requires
/// `webauthn:read`.
pub async fn list_user_credentials(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "webauthn:read")?;
    let resp = state
        .webauthn
        .list_user_credentials(&user.claims.tenant_id, &user.claims.sub)
        .await
        .map_err(map_iam)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

/// Enforce a single `resource:action` permission with wildcard support.
///
/// Mirrors the helper in `controller::admin` — local copy avoids a
/// pub-cross-module dependency. Any future refactor moving this to a
/// shared util would consolidate both.
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use sx_iam::model::claims::{AccessClaims, TokenType};

    fn mk_user(perms: Vec<&str>) -> AuthenticatedUser {
        AuthenticatedUser {
            claims: AccessClaims {
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
                permissions: perms
                    .into_iter()
                    .map(|p| Permission::parse(p).unwrap())
                    .collect(),
                cred_id: None,
            },
        }
    }

    #[test]
    fn require_permission_allows_exact_match() {
        let u = mk_user(vec!["webauthn:read"]);
        assert!(require_permission(&u, "webauthn:read").is_ok());
    }

    #[test]
    fn require_permission_allows_wildcards() {
        let u = mk_user(vec!["webauthn:*"]);
        assert!(require_permission(&u, "webauthn:read").is_ok());
        assert!(require_permission(&u, "webauthn:write").is_ok());
        let u_star = mk_user(vec!["*:*"]);
        assert!(require_permission(&u_star, "webauthn:admin").is_ok());
    }

    #[test]
    fn require_permission_denies_when_missing() {
        let u = mk_user(vec!["other:read"]);
        let err = require_permission(&u, "webauthn:read").unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }
}
