//! Device-trust controllers — `/v1/device-trust/*`.
//!
//! Three endpoints back the dashboard policy editor + session table:
//!
//! | Method | Path                          | RBAC          |
//! | ------ | ----------------------------- | ------------- |
//! | GET    | `/v1/device-trust/policy`     | (authn)       |
//! | PUT    | `/v1/device-trust/policy`     | `admin:users` |
//! | GET    | `/v1/device-trust/sessions`   | (authn)       |
//!
//! Every handler is intentionally thin: it derives the tenant scope
//! from the bearer claims, gates writes on `admin:users`, forwards to
//! the [`crate::port::DeviceTrustPort`] trait object, and projects the
//! result into a view.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use sx_device_trust::service::DeviceTrustError;
use sx_iam::domain::Permission;

use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::extractor::tenant::TenantScope;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::device_trust_view::{
    ListSessionsResponseView, PosturePolicyView, PostureSessionView,
};
use crate::view::envelope::ApiResponse;

/// Default page size for `GET /v1/device-trust/sessions` when the
/// `limit` query parameter is absent.
const DEFAULT_SESSIONS_LIMIT: usize = 50;

/// Hard upper bound for `limit` — protects the JSON body size + the
/// adapter's cloning cost.
const MAX_SESSIONS_LIMIT: usize = 500;

/// Translate a [`DeviceTrustError`] into the appropriate [`ApiError`].
pub fn map_device_trust(err: DeviceTrustError) -> ApiError {
    match err {
        DeviceTrustError::NotFound => ApiError::NotFound,
        DeviceTrustError::Forbidden => ApiError::Forbidden,
        DeviceTrustError::Invalid(m) => ApiError::Unprocessable(m),
        DeviceTrustError::Dependency(m) => ApiError::Dependency(m),
        DeviceTrustError::Internal(m) => ApiError::Internal(m),
    }
}

/// `GET /v1/device-trust/policy` — fetch the active policy for the
/// caller's tenant. Returns the permissive default when no policy has
/// been stored.
pub async fn get_policy(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    scope: TenantScope,
) -> Result<Json<ApiResponse<PosturePolicyView>>, ApiError> {
    // Intentional-open read (SEC-AUTHZ-001): the controller doc-table
    // marks GET as `(authn)` and the OpenAPI label `device-trust:read`
    // is not a grantable permission — `device-trust` contains a hyphen,
    // which `Permission::parse` rejects, so there is no valid perm to
    // enforce. The mutating `put_policy` is gated (`admin:users`).
    let policy = state
        .device_trust
        .get_policy(&scope.tenant_id)
        .await
        .map_err(map_device_trust)?;
    Ok(Json(ApiResponse::ok(policy.into())))
}

/// `PUT /v1/device-trust/policy` — replace the policy bound to the
/// caller's tenant. Requires the `admin:users` permission.
pub async fn put_policy(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    ValidatedJson(req): ValidatedJson<PosturePolicyView>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "admin:users")?;
    let saved = state
        .device_trust
        .put_policy(&scope.tenant_id, req.into())
        .await
        .map_err(map_device_trust)?;
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok(PosturePolicyView::from(saved))),
    ))
}

/// `GET /v1/device-trust/sessions?limit=…` — list recent posture
/// snapshots, newest-first.
pub async fn list_sessions(
    State(state): State<AppState>,
    _user: AuthenticatedUser,
    scope: TenantScope,
    Query(q): Query<ListSessionsQuery>,
) -> Result<Json<ApiResponse<ListSessionsResponseView>>, ApiError> {
    // Intentional-open read (SEC-AUTHZ-001): see `get_policy` — the
    // documented `device-trust:read` label is not a grantable
    // permission (hyphen), and the controller marks reads `(authn)`.
    let limit = q
        .limit
        .map_or(DEFAULT_SESSIONS_LIMIT, |l| l.clamp(1, MAX_SESSIONS_LIMIT));
    let snaps = state
        .device_trust
        .list_snapshots(&scope.tenant_id, limit)
        .await
        .map_err(map_device_trust)?;
    let items: Vec<PostureSessionView> = snaps.into_iter().map(Into::into).collect();
    Ok(Json(ApiResponse::ok(ListSessionsResponseView { items })))
}

/// Query parameters for [`list_sessions`].
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ListSessionsQuery {
    /// Page size cap. Defaults to [`DEFAULT_SESSIONS_LIMIT`] and is
    /// clamped at [`MAX_SESSIONS_LIMIT`].
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Enforce a single `resource:action` permission with wildcard support.
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use sx_iam::model::claims::{AccessClaims, TokenType};

    fn user(perms: Vec<&str>) -> AuthenticatedUser {
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
    fn put_policy_requires_admin_users() {
        let u = user(vec!["findings:read"]);
        assert!(matches!(
            require_permission(&u, "admin:users"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn put_policy_allowed_with_admin_users() {
        let u = user(vec!["admin:users"]);
        assert!(require_permission(&u, "admin:users").is_ok());
    }

    #[test]
    fn put_policy_allowed_with_wildcard() {
        let u = user(vec!["admin:*"]);
        assert!(require_permission(&u, "admin:users").is_ok());
    }

    #[test]
    fn device_trust_errors_map_predictably() {
        assert!(matches!(
            map_device_trust(DeviceTrustError::NotFound),
            ApiError::NotFound
        ));
        assert!(matches!(
            map_device_trust(DeviceTrustError::Forbidden),
            ApiError::Forbidden
        ));
        assert!(matches!(
            map_device_trust(DeviceTrustError::Invalid("x".into())),
            ApiError::Unprocessable(_)
        ));
        assert!(matches!(
            map_device_trust(DeviceTrustError::Dependency("x".into())),
            ApiError::Dependency(_)
        ));
        assert!(matches!(
            map_device_trust(DeviceTrustError::Internal("x".into())),
            ApiError::Internal(_)
        ));
    }
}
