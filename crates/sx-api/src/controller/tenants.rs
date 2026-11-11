//! Tenant administration controllers — three operator-only endpoints
//! under `/v1/admin/tenants`.
//!
//! The single-tenant read endpoint (`GET /v1/tenants/me`) lives in
//! [`crate::controller::tenant`] and is untouched by this module. The
//! handlers here only cover the write surface:
//!
//! - `POST   /v1/admin/tenants`         — create a new tenant.
//! - `PATCH  /v1/admin/tenants/{id}`    — partial update.
//! - `DELETE /v1/admin/tenants/{id}`    — delete by id.
//!
//! Every handler gates on the `admin:tenants` RBAC permission via the
//! local [`require_permission`] helper (wildcards `admin:*` and `*:*`
//! are honoured), then forwards to the [`crate::port::TenantWritePort`]
//! trait object held on [`AppState`].
//!
//! ## Conflict handling
//!
//! The in-memory adapter signals a slug-uniqueness collision by
//! returning [`Phase3PortError::Invalid`] carrying the sentinel
//! [`DUPLICATE_TENANT_MARKER`]. [`map_tenants_error`] translates that
//! into HTTP `409 Conflict`; every other `Invalid` lands on `422
//! Unprocessable`.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use sx_iam::domain::Permission;

use crate::controller::{map_engagement, map_phase3};
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::{Phase3PortError, TenantSummaryView};
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::tenant_view::{CreateTenantRequest, UpdateTenantRequest};

/// Query parameters for `GET /v1/admin/tenants`. Both fields are
/// optional; defaults are `limit=50` (cap 500) and `offset=0`.
#[derive(Debug, Deserialize, Default)]
pub struct ListTenantsQuery {
    /// Page size, clamped to `1..=500`. Defaults to `50`.
    pub limit: Option<u32>,
    /// Zero-based offset. Defaults to `0`.
    pub offset: Option<u64>,
}

/// Default page size for [`list`].
const DEFAULT_LIST_LIMIT: u32 = 50;
/// Hard cap on the page size for [`list`].
const MAX_LIST_LIMIT: u32 = 500;

/// `GET /v1/admin/tenants` — list tenants, paged via `?limit=&offset=`.
///
/// Gates on the `admin:tenants` permission. The data plane is intentionally
/// global (operator surface); a non-admin caller is rejected at the
/// permission gate before any data is touched.
pub async fn list(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<ListTenantsQuery>,
) -> Result<Json<ApiResponse<Vec<TenantSummaryView>>>, ApiError> {
    require_permission(&user, "admin:tenants")?;
    let limit = q
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);
    let offset = q.offset.unwrap_or(0);
    let rows = state
        .tenants
        .list_tenants(limit, offset)
        .await
        .map_err(map_engagement)?;
    Ok(Json(ApiResponse::ok(rows)))
}

/// Sentinel string the adapter returns inside
/// [`Phase3PortError::Invalid`] to signal a duplicate slug. Mapped into
/// HTTP `409 Conflict` by [`map_tenants_error`].
pub(crate) const DUPLICATE_TENANT_MARKER: &str = "tenant exists";

/// `POST /v1/admin/tenants` — provision a new tenant.
///
/// Returns `201 Created` carrying the persisted [`TenantSummaryView`] on
/// success; `409 Conflict` when the slug is already taken.
pub async fn create(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<CreateTenantRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "admin:tenants")?;
    let view = state
        .tenant_write
        .create(req)
        .await
        .map_err(map_tenants_error)?;
    Ok((StatusCode::CREATED, Json(ApiResponse::ok(view))))
}

/// `PATCH /v1/admin/tenants/{id}` — apply a partial update.
///
/// Returns `200 OK` carrying the persisted [`TenantSummaryView`] on
/// success; `404 Not Found` when the id is unknown.
pub async fn update(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
    ValidatedJson(req): ValidatedJson<UpdateTenantRequest>,
) -> Result<Json<ApiResponse<TenantSummaryView>>, ApiError> {
    require_permission(&user, "admin:tenants")?;
    let view = state
        .tenant_write
        .update(&id, req)
        .await
        .map_err(map_tenants_error)?;
    Ok(Json(ApiResponse::ok(view)))
}

/// `DELETE /v1/admin/tenants/{id}` — remove a tenant.
///
/// Returns `204 No Content` on success; `404 Not Found` when the id is
/// unknown.
pub async fn delete(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    require_permission(&user, "admin:tenants")?;
    state
        .tenant_write
        .delete(&id)
        .await
        .map_err(map_tenants_error)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Map a [`Phase3PortError`] into the appropriate [`ApiError`], treating
/// the adapter's slug-uniqueness sentinel as `409 Conflict` instead of
/// `422`.
fn map_tenants_error(err: Phase3PortError) -> ApiError {
    match err {
        Phase3PortError::Invalid(ref msg) if msg == DUPLICATE_TENANT_MARKER => {
            ApiError::Conflict(DUPLICATE_TENANT_MARKER.to_owned())
        }
        other => map_phase3(other),
    }
}

/// Enforce a single `resource:action` permission with wildcard support.
///
/// Mirrors the helper used by [`crate::controller::roles`] /
/// [`crate::controller::assets`] / [`crate::controller::admin`]. The
/// helper is local rather than shared because the wildcard semantics are
/// stable per-controller and inlining keeps the dependency graph small.
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

    /// Build a synthetic [`AuthenticatedUser`] carrying the supplied
    /// permission tokens.
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
    fn create_requires_admin_tenants_permission() {
        let u = user(vec!["findings:read"]);
        assert!(matches!(
            require_permission(&u, "admin:tenants"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn update_requires_admin_tenants_permission() {
        let u = user(vec!["admin:users"]);
        assert!(matches!(
            require_permission(&u, "admin:tenants"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn delete_requires_admin_tenants_permission() {
        let u = user(vec!["admin:roles"]);
        assert!(matches!(
            require_permission(&u, "admin:tenants"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_admin_tenants_permission_allowed() {
        let u = user(vec!["admin:tenants"]);
        assert!(require_permission(&u, "admin:tenants").is_ok());
    }

    #[test]
    fn admin_wildcard_grants_tenants_permission() {
        let u = user(vec!["admin:*"]);
        assert!(require_permission(&u, "admin:tenants").is_ok());
    }

    #[test]
    fn full_wildcard_grants_tenants_permission() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "admin:tenants").is_ok());
    }

    #[test]
    fn empty_permissions_denied() {
        let u = user(vec![]);
        assert!(matches!(
            require_permission(&u, "admin:tenants"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn duplicate_marker_maps_to_conflict() {
        let err = map_tenants_error(Phase3PortError::Invalid(DUPLICATE_TENANT_MARKER.into()));
        assert!(
            matches!(err, ApiError::Conflict(ref m) if m == DUPLICATE_TENANT_MARKER),
            "expected Conflict, got {err:?}"
        );
    }

    #[test]
    fn other_invalid_maps_to_unprocessable() {
        let err = map_tenants_error(Phase3PortError::Invalid("bad slug shape".into()));
        assert!(
            matches!(err, ApiError::Unprocessable(_)),
            "expected Unprocessable, got {err:?}"
        );
    }

    #[test]
    fn not_found_maps_to_not_found() {
        let err = map_tenants_error(Phase3PortError::NotFound);
        assert!(
            matches!(err, ApiError::NotFound),
            "expected NotFound, got {err:?}"
        );
    }

    #[test]
    fn forbidden_maps_to_forbidden() {
        let err = map_tenants_error(Phase3PortError::Forbidden("nope".into()));
        assert!(
            matches!(err, ApiError::Forbidden),
            "expected Forbidden, got {err:?}"
        );
    }

    #[test]
    fn dependency_maps_to_dependency() {
        let err = map_tenants_error(Phase3PortError::Dependency("upstream".into()));
        assert!(
            matches!(err, ApiError::Dependency(_)),
            "expected Dependency, got {err:?}"
        );
    }

    // --- GET /v1/admin/tenants tests ----------------------------------

    use crate::port::{EngagementPortError, TenantRepositoryPort};
    use async_trait::async_trait;
    use std::sync::Arc;

    /// Stub repository returning a configurable list of rows.
    struct StubTenantsList {
        rows: Vec<TenantSummaryView>,
    }

    #[async_trait]
    impl TenantRepositoryPort for StubTenantsList {
        async fn get(&self, _id: &str) -> Result<TenantSummaryView, EngagementPortError> {
            Err(EngagementPortError::NotFound)
        }
        async fn list_tenants(
            &self,
            limit: u32,
            offset: u64,
        ) -> Result<Vec<TenantSummaryView>, EngagementPortError> {
            Ok(self
                .rows
                .iter()
                .skip(usize::try_from(offset).unwrap_or(usize::MAX))
                .take(usize::try_from(limit).unwrap_or(usize::MAX))
                .cloned()
                .collect())
        }
    }

    fn tenant_row(id: &str, slug: &str) -> TenantSummaryView {
        TenantSummaryView {
            id: id.to_owned(),
            name: slug.to_owned(),
            slug: slug.to_owned(),
            is_active: true,
        }
    }

    #[tokio::test]
    async fn list_returns_rows_from_port() {
        let repo: Arc<dyn TenantRepositoryPort> = Arc::new(StubTenantsList {
            rows: vec![tenant_row("t1", "alpha"), tenant_row("t2", "beta")],
        });
        let rows = repo.list_tenants(50, 0).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].slug, "alpha");
    }

    #[tokio::test]
    async fn list_empty_when_no_rows() {
        let repo: Arc<dyn TenantRepositoryPort> = Arc::new(StubTenantsList { rows: vec![] });
        let rows = repo.list_tenants(50, 0).await.unwrap();
        assert!(rows.is_empty());
    }

    #[test]
    fn list_requires_admin_tenants_permission() {
        let u = user(vec!["findings:read"]);
        assert!(matches!(
            require_permission(&u, "admin:tenants"),
            Err(ApiError::Forbidden)
        ));
    }
}
