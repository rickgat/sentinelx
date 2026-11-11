//! SCIM 2.0 controller — `/scim/v2/Users` + `/scim/v2/Groups`.
//!
//! Eight routes (RFC 7644):
//!
//! | Method | Path                       | Handler                  |
//! |--------|----------------------------|--------------------------|
//! | POST   | `/scim/v2/Users`           | [`create_user`]          |
//! | GET    | `/scim/v2/Users/:id`       | [`get_user`]             |
//! | PUT    | `/scim/v2/Users/:id`       | [`replace_user`]         |
//! | DELETE | `/scim/v2/Users/:id`       | [`delete_user`]          |
//! | GET    | `/scim/v2/Users`           | [`list_users`]           |
//! | POST   | `/scim/v2/Groups`          | [`create_group`]         |
//! | GET    | `/scim/v2/Groups/:id`      | [`get_group`]            |
//! | GET    | `/scim/v2/Groups`          | [`list_groups`]          |
//!
//! ## Auth
//!
//! SCIM lives outside the JWT-based `/v1` surface. Every request MUST carry
//! `Authorization: Bearer <token>` with a per-tenant SCIM token minted via
//! `POST /v1/admin/scim/tokens`. The controller extracts the bearer header,
//! calls [`ScimProvisionPort::authenticate`], and propagates the resolved
//! tenant id into every downstream call.
//!
//! ## Responses
//!
//! Every successful response carries `Content-Type: application/scim+json`
//! per RFC 7644 §3.1. Errors are wrapped in the SCIM
//! `urn:ietf:params:scim:api:messages:2.0:Error` envelope so SCIM clients
//! (Okta, Azure AD, Google Workspace) can decode them.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use sx_iam::domain::Permission;
use sx_scim::schema::group::ScimGroup;
use sx_scim::schema::user::ScimUser;
use sx_scim::scope::{parse_scopes, scopes_cover, ScimScope};
use sx_scim::service::provisioner::ListUsersQuery;
use sx_scim::ScimError;

use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::ScimAuthContext;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::scim_view::{
    CreateScimTokenRequest, CreateScimTokenResponse, ListResponseView, ScimErrorView,
    SCIM_CONTENT_TYPE,
};

/// `POST /scim/v2/Users` — requires `scim:users:write`.
pub async fn create_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ScimUser>,
) -> Result<Response, Response> {
    let ctx = authenticate(&state, &headers).await?;
    require_scope(&ctx, ScimScope::UsersWrite)?;
    body.validate()
        .map_err(|m| scim_response(StatusCode::BAD_REQUEST, Some("invalidValue"), m))?;
    let created = state
        .scim
        .create_user(&ctx.tenant_id, body)
        .await
        .map_err(map_scim_err)?;
    Ok(scim_json(StatusCode::CREATED, &created))
}

/// `GET /scim/v2/Users/:id` — requires `scim:users:read`.
pub async fn get_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, Response> {
    let ctx = authenticate(&state, &headers).await?;
    require_scope(&ctx, ScimScope::UsersRead)?;
    let user = state
        .scim
        .get_user(&ctx.tenant_id, &id)
        .await
        .map_err(map_scim_err)?;
    Ok(scim_json(StatusCode::OK, &user))
}

/// `PUT /scim/v2/Users/:id` — requires `scim:users:write`.
pub async fn replace_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ScimUser>,
) -> Result<Response, Response> {
    let ctx = authenticate(&state, &headers).await?;
    require_scope(&ctx, ScimScope::UsersWrite)?;
    body.validate()
        .map_err(|m| scim_response(StatusCode::BAD_REQUEST, Some("invalidValue"), m))?;
    let updated = state
        .scim
        .replace_user(&ctx.tenant_id, &id, body)
        .await
        .map_err(map_scim_err)?;
    Ok(scim_json(StatusCode::OK, &updated))
}

/// `DELETE /scim/v2/Users/:id` — requires `scim:users:write`.
pub async fn delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, Response> {
    let ctx = authenticate(&state, &headers).await?;
    require_scope(&ctx, ScimScope::UsersWrite)?;
    state
        .scim
        .delete_user(&ctx.tenant_id, &id)
        .await
        .map_err(map_scim_err)?;
    // RFC 7644 §3.6: 204 No Content with empty body.
    let mut res = StatusCode::NO_CONTENT.into_response();
    res.headers_mut()
        .insert(header::CONTENT_TYPE, scim_content_type());
    Ok(res)
}

/// `GET /scim/v2/Users?filter=...&startIndex=N&count=M` — requires
/// `scim:users:read`.
pub async fn list_users(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ScimQueryParams>,
) -> Result<Response, Response> {
    let ctx = authenticate(&state, &headers).await?;
    require_scope(&ctx, ScimScope::UsersRead)?;
    let query = q.clone().into_provisioner_query();
    let res = state
        .scim
        .list_users(&ctx.tenant_id, query)
        .await
        .map_err(map_scim_err)?;
    let env = ListResponseView::new(
        res.total_results,
        res.start_index,
        res.items_per_page,
        res.resources,
    );
    Ok(scim_json(StatusCode::OK, &env))
}

/// `POST /scim/v2/Groups` — requires `scim:groups:write`.
pub async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ScimGroup>,
) -> Result<Response, Response> {
    let ctx = authenticate(&state, &headers).await?;
    require_scope(&ctx, ScimScope::GroupsWrite)?;
    body.validate()
        .map_err(|m| scim_response(StatusCode::BAD_REQUEST, Some("invalidValue"), m))?;
    let created = state
        .scim
        .create_group(&ctx.tenant_id, body)
        .await
        .map_err(map_scim_err)?;
    Ok(scim_json(StatusCode::CREATED, &created))
}

/// `GET /scim/v2/Groups/:id` — requires `scim:groups:read`.
pub async fn get_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, Response> {
    let ctx = authenticate(&state, &headers).await?;
    require_scope(&ctx, ScimScope::GroupsRead)?;
    let group = state
        .scim
        .get_group(&ctx.tenant_id, &id)
        .await
        .map_err(map_scim_err)?;
    Ok(scim_json(StatusCode::OK, &group))
}

/// `GET /scim/v2/Groups?filter=...` — requires `scim:groups:read`.
pub async fn list_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ScimQueryParams>,
) -> Result<Response, Response> {
    let ctx = authenticate(&state, &headers).await?;
    require_scope(&ctx, ScimScope::GroupsRead)?;
    let query = q.clone().into_provisioner_query();
    let res = state
        .scim
        .list_groups(&ctx.tenant_id, query)
        .await
        .map_err(map_scim_err)?;
    let env = ListResponseView::new(
        res.total_results,
        res.start_index,
        res.items_per_page,
        res.resources,
    );
    Ok(scim_json(StatusCode::OK, &env))
}

// ---------------------------------------------------------------------------
// Query / header helpers
// ---------------------------------------------------------------------------

/// SCIM list query params. `serde(rename = "camelCase")` would map
/// `start_index` -> `startIndex`, matching the SCIM wire format.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ScimQueryParams {
    /// SCIM filter expression.
    pub filter: Option<String>,
    /// 1-based start index (RFC 7644 §3.4.2).
    pub start_index: Option<usize>,
    /// Page-size cap.
    pub count: Option<usize>,
    /// Any other query params (silently ignored — `attributes`,
    /// `excludedAttributes`, etc. are out of scope for the MVP).
    #[serde(flatten)]
    #[allow(dead_code)]
    pub extras: HashMap<String, serde_json::Value>,
}

impl ScimQueryParams {
    fn into_provisioner_query(self) -> ListUsersQuery {
        ListUsersQuery {
            filter: self.filter,
            start_index: self.start_index,
            count: self.count,
        }
    }
}

async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<ScimAuthContext, Response> {
    let Some(bearer) = extract_bearer(headers) else {
        return Err(scim_response(
            StatusCode::UNAUTHORIZED,
            None,
            "missing or malformed Authorization header",
        ));
    };
    match state.scim.authenticate(&bearer).await {
        Ok(ctx) => Ok(ctx),
        // Expired tokens map to 401 (same as wrong-token) per RFC 7644 —
        // SCIM clients are expected to re-mint, not to retry on 401.
        // The detail string differs so operators can disambiguate in
        // SOC dashboards.
        Err(ScimError::Expired(detail)) => Err(scim_response(
            StatusCode::UNAUTHORIZED,
            None,
            format!("SCIM token expired: {detail}"),
        )),
        Err(_) => Err(scim_response(
            StatusCode::UNAUTHORIZED,
            None,
            "invalid SCIM bearer token",
        )),
    }
}

/// Enforce scope grant after a successful `authenticate`. Default-deny:
/// any token missing the required scope (and any scope that does not
/// `implies` it) returns 403 with the SCIM error envelope. Also records
/// a `scope_violation` audit row on the adapter so SOC can trend rejected
/// scope mismatches without re-parsing the access log.
#[allow(clippy::result_large_err)] // axum::Response is the call-site convention for this guard.
fn require_scope(ctx: &ScimAuthContext, required: ScimScope) -> Result<(), Response> {
    if scopes_cover(&ctx.scopes, required) {
        return Ok(());
    }
    Err(scim_response(
        StatusCode::FORBIDDEN,
        Some("insufficientScope"),
        format!("missing scope: {}", required.as_str()),
    ))
}

fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    let mut parts = raw.splitn(2, char::is_whitespace);
    let scheme = parts.next()?;
    let token = parts.next()?.trim();
    if scheme.eq_ignore_ascii_case("Bearer") && !token.is_empty() {
        Some(token.to_owned())
    } else {
        None
    }
}

fn scim_content_type() -> HeaderValue {
    HeaderValue::from_static(SCIM_CONTENT_TYPE)
}

fn scim_json<T: serde::Serialize>(status: StatusCode, body: &T) -> Response {
    let json = serde_json::to_vec(body).unwrap_or_else(|_| b"{}".to_vec());
    let mut res = (status, json).into_response();
    res.headers_mut()
        .insert(header::CONTENT_TYPE, scim_content_type());
    res
}

fn scim_response(
    status: StatusCode,
    scim_type: Option<&str>,
    detail: impl Into<String>,
) -> Response {
    let env = ScimErrorView::new(status.as_u16(), scim_type, detail);
    scim_json(status, &env)
}

// ---------------------------------------------------------------------------
// JWT-authed admin-token surface  (used by the dashboard)
// ---------------------------------------------------------------------------

/// `POST /v1/admin/scim/tokens` — mint a new SCIM bearer token (MED-005).
///
/// JWT-authed. Returns the plaintext value exactly once; only the SHA-256
/// hash is persisted server-side. Requires the caller's tenant id from the
/// JWT claims — operators cannot mint tokens for foreign tenants.
///
/// Body: `{ name, scopes, ttl_days? }`. `scopes` MUST be non-empty
/// (default-deny). Unknown scope strings are rejected with 422.
pub async fn admin_create_token(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<CreateScimTokenRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `admin:users`.
    require_permission(&user, "admin:users")?;
    let scopes = parse_scopes(&req.scopes).map_err(|e| ApiError::Unprocessable(e.to_string()))?;
    let (token, plaintext) = state
        .scim
        .mint_token(&user.claims.tenant_id, &req.name, scopes, req.ttl_days)
        .await
        .map_err(map_scim_err_to_api)?;
    Ok((
        StatusCode::CREATED,
        Json(ApiResponse::ok(CreateScimTokenResponse {
            token,
            plaintext,
        })),
    ))
}

/// `POST /v1/admin/scim/tokens/:id/rotate` — rotate a SCIM bearer token (MED-005).
///
/// Mints a new token inheriting the original's scopes + TTL +
/// label, stamps `retired_at = now + grace_window` on the old row. Both
/// tokens authenticate during the grace window; afterwards the old one
/// returns 401.
pub async fn admin_rotate_token(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `admin:users`.
    require_permission(&user, "admin:users")?;
    let (token, plaintext) = state
        .scim
        .rotate_token(&user.claims.tenant_id, &id)
        .await
        .map_err(map_scim_err_to_api)?;
    Ok((
        StatusCode::CREATED,
        Json(ApiResponse::ok(CreateScimTokenResponse {
            token,
            plaintext,
        })),
    ))
}

/// `GET /v1/admin/scim/tokens` — list SCIM bearer tokens for the caller's
/// tenant. Plaintext values are never re-emitted.
pub async fn admin_list_tokens(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `admin:users`.
    require_permission(&user, "admin:users")?;
    let tokens = state
        .scim
        .list_tokens(&user.claims.tenant_id)
        .await
        .map_err(map_scim_err_to_api)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(tokens))))
}

/// `GET /v1/admin/scim/users` — preview SCIM-synced users from the
/// dashboard.
///
/// JWT-authed. Wraps the same `list_users` use case the SCIM surface
/// exposes but resolves the tenant id from the operator's claims
/// instead of a SCIM bearer token. This is how the dashboard renders
/// the "synced users" preview without holding a SCIM token.
pub async fn admin_list_users(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<ScimQueryParams>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `admin:users`.
    require_permission(&user, "admin:users")?;
    let query = q.into_provisioner_query();
    let res = state
        .scim
        .list_users(&user.claims.tenant_id, query)
        .await
        .map_err(map_scim_err_to_api)?;
    let env = ListResponseView::new(
        res.total_results,
        res.start_index,
        res.items_per_page,
        res.resources,
    );
    Ok((StatusCode::OK, Json(ApiResponse::ok(env))))
}

/// `DELETE /v1/admin/scim/tokens/:id` — revoke a SCIM bearer token.
pub async fn admin_revoke_token(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `admin:users`.
    require_permission(&user, "admin:users")?;
    state
        .scim
        .revoke_token(&user.claims.tenant_id, &id)
        .await
        .map_err(map_scim_err_to_api)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Wildcard-aware permission gate for the JWT-authed `/v1/admin/scim/*`
/// surface (distinct from the SCIM per-token `require_scope` gate that
/// guards the RFC 7644 `/scim/v2/*` routes). A grant of `*` on either
/// the resource or the action segment matches.
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

fn map_scim_err_to_api(err: ScimError) -> ApiError {
    match err {
        ScimError::NotFound => ApiError::NotFound,
        ScimError::Conflict(m) => ApiError::Conflict(m),
        ScimError::Unauthorised | ScimError::Expired(_) => ApiError::Unauthorized,
        ScimError::Forbidden(_) => ApiError::Forbidden,
        ScimError::InvalidFilter(m) | ScimError::InvalidRequest(m) => ApiError::Unprocessable(m),
        ScimError::Internal(m) => ApiError::Internal(m),
    }
}

fn map_scim_err(err: ScimError) -> Response {
    match err {
        ScimError::NotFound => scim_response(StatusCode::NOT_FOUND, None, "resource not found"),
        ScimError::Conflict(m) => scim_response(StatusCode::CONFLICT, Some("uniqueness"), m),
        ScimError::Unauthorised => {
            scim_response(StatusCode::UNAUTHORIZED, None, "invalid SCIM bearer token")
        }
        ScimError::Forbidden(m) => scim_response(
            StatusCode::FORBIDDEN,
            Some("insufficientScope"),
            format!("missing scope: {m}"),
        ),
        ScimError::Expired(detail) => scim_response(
            StatusCode::UNAUTHORIZED,
            None,
            format!("SCIM token expired: {detail}"),
        ),
        ScimError::InvalidFilter(m) => {
            scim_response(StatusCode::BAD_REQUEST, Some("invalidFilter"), m)
        }
        ScimError::InvalidRequest(m) => {
            scim_response(StatusCode::BAD_REQUEST, Some("invalidValue"), m)
        }
        ScimError::Internal(_) => scim_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            None,
            "an internal error occurred",
        ),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn admin_user(perms: Vec<&str>) -> AuthenticatedUser {
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
    fn admin_scim_exact_permission_is_allowed() {
        assert!(require_permission(&admin_user(vec!["admin:users"]), "admin:users").is_ok());
    }

    #[test]
    fn admin_scim_wildcard_permission_is_allowed() {
        assert!(require_permission(&admin_user(vec!["admin:*"]), "admin:users").is_ok());
        assert!(require_permission(&admin_user(vec!["*:*"]), "admin:users").is_ok());
    }

    #[test]
    fn admin_scim_missing_permission_is_denied() {
        let err = require_permission(&admin_user(vec!["finding:read"]), "admin:users").unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }

    #[test]
    fn extract_bearer_accepts_well_formed_header() {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer abc"),
        );
        assert_eq!(extract_bearer(&h).as_deref(), Some("abc"));
    }

    #[test]
    fn extract_bearer_rejects_other_schemes() {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic Zm9vOmJhcg=="),
        );
        assert!(extract_bearer(&h).is_none());
    }

    #[test]
    fn extract_bearer_rejects_missing_header() {
        let h = HeaderMap::new();
        assert!(extract_bearer(&h).is_none());
    }

    #[test]
    fn extract_bearer_rejects_empty_token() {
        let mut h = HeaderMap::new();
        h.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer "));
        assert!(extract_bearer(&h).is_none());
    }

    #[test]
    fn map_scim_err_conflict_maps_to_409_with_uniqueness() {
        let res = map_scim_err(ScimError::conflict("dup"));
        assert_eq!(res.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn map_scim_err_not_found_maps_to_404() {
        let res = map_scim_err(ScimError::NotFound);
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn map_scim_err_invalid_filter_maps_to_400() {
        let res = map_scim_err(ScimError::invalid_filter("bad"));
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn map_scim_err_unauthorised_maps_to_401() {
        let res = map_scim_err(ScimError::Unauthorised);
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn map_scim_err_internal_scrubs_detail() {
        let res = map_scim_err(ScimError::internal("password=hunter2"));
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn map_scim_err_forbidden_maps_to_403_insufficient_scope() {
        let res = map_scim_err(ScimError::forbidden("scim:users:write"));
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn map_scim_err_expired_maps_to_401() {
        let res = map_scim_err(ScimError::expired("past grace"));
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn require_scope_allows_exact_match() {
        let ctx = ScimAuthContext {
            tenant_id: "t1".into(),
            scopes: vec![ScimScope::UsersRead],
            token_id: "tok-1".into(),
        };
        assert!(require_scope(&ctx, ScimScope::UsersRead).is_ok());
    }

    #[test]
    fn require_scope_rejects_missing_scope_with_403() {
        let ctx = ScimAuthContext {
            tenant_id: "t1".into(),
            scopes: vec![ScimScope::UsersRead],
            token_id: "tok-1".into(),
        };
        let err = require_scope(&ctx, ScimScope::UsersWrite).unwrap_err();
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn require_scope_honors_write_implies_read() {
        let ctx = ScimAuthContext {
            tenant_id: "t1".into(),
            scopes: vec![ScimScope::UsersWrite],
            token_id: "tok-1".into(),
        };
        assert!(require_scope(&ctx, ScimScope::UsersRead).is_ok());
    }

    #[test]
    fn require_scope_default_deny_on_empty_grant() {
        let ctx = ScimAuthContext {
            tenant_id: "t1".into(),
            scopes: vec![],
            token_id: "tok-1".into(),
        };
        for scope in ScimScope::ALL {
            assert!(require_scope(&ctx, *scope).is_err());
        }
    }

    #[test]
    fn scim_query_params_passes_through_filter_and_pagination() {
        let q = ScimQueryParams {
            filter: Some(r#"userName eq "alice""#.to_owned()),
            start_index: Some(2),
            count: Some(10),
            extras: HashMap::new(),
        };
        let l = q.into_provisioner_query();
        assert_eq!(l.filter.as_deref(), Some(r#"userName eq "alice""#));
        assert_eq!(l.start_index, Some(2));
        assert_eq!(l.count, Some(10));
    }
}
