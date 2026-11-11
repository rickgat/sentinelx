//! Admin controller — `POST /v1/admin/users`.
//!
//! Operators with the `admin:users` permission can provision additional
//! users beyond the single bootstrap admin. The controller is intentionally
//! thin: it gates on the RBAC permission, delegates to the
//! [`crate::port::CreateUserPort`], and serialises the projection.
//!
//! Every business rule (email normalisation, password hashing, conflict on
//! duplicate email) is enforced by the underlying use case via the
//! adapter — the controller never inspects the request body beyond what
//! `ValidatedJson` already checked.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use sx_iam::domain::Permission;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::extractor::tenant::TenantScope;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::admin_view::{AdminUserSummaryView, CreateUserRequestView};
use crate::view::envelope::ApiResponse;

/// Query parameters for `GET /v1/admin/users`. Both optional; defaults
/// are `limit=50` (cap 500) and `offset=0`.
#[derive(Debug, Deserialize, Default)]
pub struct ListUsersQuery {
    /// Page size, clamped to `1..=500`. Defaults to `50`.
    pub limit: Option<u32>,
    /// Zero-based offset. Defaults to `0`.
    pub offset: Option<u64>,
}

/// Default page size for [`list_users`].
const DEFAULT_LIST_LIMIT: u32 = 50;
/// Hard cap on the page size for [`list_users`].
const MAX_LIST_LIMIT: u32 = 500;

/// `GET /v1/admin/users` — list users for the caller's tenant.
///
/// Gates on the `admin:users` permission. Tenant scoping is enforced by
/// the bearer claims; an attacker cannot enumerate another tenant's users
/// by manipulating the URL.
pub async fn list_users(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    Query(q): Query<ListUsersQuery>,
) -> Result<Json<ApiResponse<Vec<AdminUserSummaryView>>>, ApiError> {
    require_permission(&user, "admin:users")?;
    let limit = q
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);
    let offset = q.offset.unwrap_or(0);
    let rows = state
        .admin_user_list
        .list_users(&scope.tenant_id, limit, offset)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(rows)))
}

/// `POST /v1/admin/users` — provision a new user.
///
/// Returns `201 Created` with the new user's projection on success.
pub async fn create_user(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<CreateUserRequestView>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "admin:users")?;
    let resp = state.create_user.create(req).await.map_err(map_phase3)?;
    Ok((StatusCode::CREATED, Json(ApiResponse::ok(resp))))
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
    fn create_user_requires_admin_users_permission() {
        let u = user(vec!["findings:read"]);
        assert!(matches!(
            require_permission(&u, "admin:users"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_admin_users_permission_allowed() {
        let u = user(vec!["admin:users"]);
        assert!(require_permission(&u, "admin:users").is_ok());
    }

    #[test]
    fn wildcard_users_grant_allowed() {
        let u = user(vec!["admin:*"]);
        assert!(require_permission(&u, "admin:users").is_ok());
    }

    #[test]
    fn full_wildcard_grant_allowed() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "admin:users").is_ok());
    }

    // --- GET /v1/admin/users tests ------------------------------------

    use crate::port::{AdminUserListPort, Phase3PortError};
    use async_trait::async_trait;
    use std::sync::Arc;

    /// Stub admin-user list port returning a configurable row set.
    struct StubAdminUserList {
        rows: Vec<AdminUserSummaryView>,
    }

    #[async_trait]
    impl AdminUserListPort for StubAdminUserList {
        async fn list_users(
            &self,
            tenant_id: &str,
            limit: u32,
            offset: u64,
        ) -> Result<Vec<AdminUserSummaryView>, Phase3PortError> {
            Ok(self
                .rows
                .iter()
                .filter(|r| r.tenant_id == tenant_id)
                .skip(usize::try_from(offset).unwrap_or(usize::MAX))
                .take(usize::try_from(limit).unwrap_or(usize::MAX))
                .cloned()
                .collect())
        }
    }

    fn user_row(id: &str, tenant: &str, email: &str) -> AdminUserSummaryView {
        AdminUserSummaryView {
            id: id.to_owned(),
            tenant_id: tenant.to_owned(),
            email: email.to_owned(),
            is_active: true,
            role_count: 1,
            created_at: "2026-06-13T00:00:00Z".to_owned(),
        }
    }

    #[tokio::test]
    async fn list_users_returns_rows_for_tenant() {
        let port: Arc<dyn AdminUserListPort> = Arc::new(StubAdminUserList {
            rows: vec![
                user_row("u1", "t-a", "alice@example.com"),
                user_row("u2", "t-a", "bob@example.com"),
                user_row("u3", "t-other", "carol@example.com"),
            ],
        });
        let rows = port.list_users("t-a", 50, 0).await.unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[tokio::test]
    async fn list_users_empty_for_unknown_tenant() {
        let port: Arc<dyn AdminUserListPort> = Arc::new(StubAdminUserList { rows: vec![] });
        let rows = port.list_users("t-missing", 50, 0).await.unwrap();
        assert!(rows.is_empty());
    }
}
