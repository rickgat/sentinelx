//! Threat-hunt controller (P3-006).
//!
//! Single endpoint: `POST /v1/hunt/query` — analyst submits a KQL/SPL-like
//! query as JSON, the port parses + compiles + executes against ClickHouse,
//! and returns the row set plus the compiled SQL.
//!
//! Tenant scoping is non-bypassable: the controller pulls `tenant_id`
//! from the caller's [`AuthenticatedUser`] claims and forwards it to the
//! port, where the compiler unconditionally `AND`-injects
//! `tenant_id = {tenant:String}` into the WHERE clause regardless of
//! what the analyst typed.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_hunt;
use crate::error::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::hunt_view::{HuntQueryRequest, HuntQueryResponse};

/// Wildcard-aware permission gate (local copy — each controller owns its
/// own so the authorization decision stays beside the handler it guards).
/// A grant of `*` on either the resource or the action segment matches.
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

/// `POST /v1/hunt/query` — run one hunt query.
///
/// The request body carries the analyst's raw query text. The port
/// returns the row set plus the compiled SQL (for UI display + audit).
pub async fn query(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<HuntQueryRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `hunt:read`; enforce it.
    require_permission(&user, "hunt:read")?;
    let resp: HuntQueryResponse = state
        .hunt
        .query(&user.claims.tenant_id, &user.claims.sub, &req.query)
        .await
        .map_err(map_hunt)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn request_view_shape_is_stable() {
        let r = HuntQueryRequest {
            query: "events_raw".to_string(),
        };
        // Just ensure the field name does not regress.
        let raw = serde_json::to_string(&r).unwrap();
        assert!(raw.contains("\"query\""));
    }

    fn user(perms: Vec<&str>) -> AuthenticatedUser {
        use sx_iam::model::claims::{AccessClaims, TokenType};
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
    fn exact_permission_is_allowed() {
        assert!(require_permission(&user(vec!["hunt:read"]), "hunt:read").is_ok());
    }

    #[test]
    fn wildcard_permission_is_allowed() {
        assert!(require_permission(&user(vec!["hunt:*"]), "hunt:read").is_ok());
        assert!(require_permission(&user(vec!["*:*"]), "hunt:read").is_ok());
    }

    #[test]
    fn missing_permission_is_denied() {
        let err = require_permission(&user(vec!["findings:read"]), "hunt:read").unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }
}
