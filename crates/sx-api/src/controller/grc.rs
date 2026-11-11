//! GRC controllers — `/v1/grc/*` (P2-009).
//!
//! Four endpoints back the dashboard GRC tab and the manual sync
//! button:
//!
//! | Method | Path                                  | RBAC          |
//! | ------ | ------------------------------------- | ------------- |
//! | POST   | `/v1/grc/configs`                     | `admin:users` |
//! | GET    | `/v1/grc/configs`                     | (authn)       |
//! | POST   | `/v1/grc/configs/:kind/test`          | `admin:users` |
//! | POST   | `/v1/grc/push`                        | (authn)       |
//!
//! `:kind` is the connector wire string (`vanta` / `drata` /
//! `servicenow`). The HTTP layer is intentionally thin — the adapter
//! owns the encrypted-token resolution, the dispatcher fan-out, and
//! the audit emission.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::extractor::tenant::TenantScope;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::GrcPortError;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::grc_view::{
    GrcConfigUpsertRequest, GrcConfigView, GrcConnectionTestView, GrcPushOutcomeView,
    GrcPushRequest,
};

/// Translate the port-level error into the HTTP envelope.
///
/// Rate limits collapse onto 503 because by the time the dispatcher
/// gives up the retry budget is already exhausted — the client never
/// sees the raw `429` from the vendor.
pub fn map_grc(err: GrcPortError) -> ApiError {
    match err {
        GrcPortError::NotFound => ApiError::NotFound,
        GrcPortError::Invalid(m) => ApiError::Unprocessable(m),
        GrcPortError::Unauthorized => ApiError::Unauthorized,
        GrcPortError::RateLimited | GrcPortError::Dependency(_) => {
            ApiError::Dependency("grc upstream unavailable".to_owned())
        }
        GrcPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// `POST /v1/grc/configs` — upsert the per-tenant GRC connection.
///
/// Requires `admin:users`. The secret travels inline on the request
/// body and is rewritten to the configured secrets backend by the
/// adapter — only the *path* survives on the persisted row.
pub async fn upsert_config(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    ValidatedJson(req): ValidatedJson<GrcConfigUpsertRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "admin:users")?;
    let view = state
        .grc
        .upsert_config(&scope.tenant_id, req)
        .await
        .map_err(map_grc)?;
    Ok((StatusCode::CREATED, Json(ApiResponse::ok(view))))
}

/// `GET /v1/grc/configs` — list every configured connection for the
/// caller's tenant.
pub async fn list_configs(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
) -> Result<Json<ApiResponse<Vec<GrcConfigView>>>, ApiError> {
    // OpenAPI documents this endpoint as requiring `grc:read`.
    require_permission(&user, "grc:read")?;
    let items = state
        .grc
        .list_configs(&scope.tenant_id)
        .await
        .map_err(map_grc)?;
    Ok(Json(ApiResponse::ok(items)))
}

/// `POST /v1/grc/configs/{kind}/test` — probe the configured
/// connection with a synthetic evidence push.
pub async fn test_connection(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    Path(kind): Path<String>,
) -> Result<Json<ApiResponse<GrcConnectionTestView>>, ApiError> {
    require_permission(&user, "admin:users")?;
    let view = state
        .grc
        .test_connection(&scope.tenant_id, &kind)
        .await
        .map_err(map_grc)?;
    Ok(Json(ApiResponse::ok(view)))
}

/// `POST /v1/grc/push` — dispatch a single evidence or finding push.
pub async fn push(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    ValidatedJson(req): ValidatedJson<GrcPushRequest>,
) -> Result<Json<ApiResponse<GrcPushOutcomeView>>, ApiError> {
    // OpenAPI documents this endpoint as requiring `grc:write`.
    require_permission(&user, "grc:write")?;
    let view = state
        .grc
        .push(&scope.tenant_id, req)
        .await
        .map_err(map_grc)?;
    Ok(Json(ApiResponse::ok(view)))
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
                    .filter_map(|p| Permission::parse(p).ok())
                    .collect(),
                cred_id: None,
            },
        }
    }

    #[test]
    fn map_grc_translates_known_variants() {
        assert!(matches!(
            map_grc(GrcPortError::NotFound),
            ApiError::NotFound
        ));
        assert!(matches!(
            map_grc(GrcPortError::Invalid("x".into())),
            ApiError::Unprocessable(_)
        ));
        assert!(matches!(
            map_grc(GrcPortError::Unauthorized),
            ApiError::Unauthorized
        ));
        assert!(matches!(
            map_grc(GrcPortError::RateLimited),
            ApiError::Dependency(_)
        ));
        assert!(matches!(
            map_grc(GrcPortError::Dependency("d".into())),
            ApiError::Dependency(_)
        ));
        assert!(matches!(
            map_grc(GrcPortError::Internal("i".into())),
            ApiError::Internal(_)
        ));
    }

    #[test]
    fn require_admin_users_rejects_without_permission() {
        let u = user(vec!["findings:read"]);
        assert!(matches!(
            require_permission(&u, "admin:users"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn require_admin_users_accepts_with_explicit_permission() {
        let u = user(vec!["admin:users"]);
        assert!(require_permission(&u, "admin:users").is_ok());
    }

    #[test]
    fn require_admin_users_accepts_wildcard() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "admin:users").is_ok());
    }
}
