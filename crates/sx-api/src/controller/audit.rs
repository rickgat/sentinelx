//! Audit controller — log search + NDJSON export.
//!
//! Two routes (both RBAC `audit:read`):
//!
//! - `GET /v1/audit/search?since=&action=&actor=&limit=` — paginated
//!   search. Returns the standard [`ApiResponse`] envelope wrapping an
//!   [`AuditSearchResponse`].
//! - `GET /v1/audit/export?format=ndjson&since=` — streams an NDJSON body
//!   directly (one JSON object per line). The response is NOT wrapped in
//!   the standard envelope — NDJSON is line-oriented and any wrapper
//!   would break parsers that consume it.
//!
//! Both handlers delegate to [`crate::port::AuditQueryPort`]. The concrete
//! buffer-backed adapter lives in
//! `services/sx-monolith/src/adapters/audit_query.rs`.

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::audit_view::{
    AuditDiffQuery, AuditExportQuery, AuditReplayQuery, AuditSearchQuery,
};
use crate::view::envelope::ApiResponse;

/// `GET /v1/audit` — thin alias forwarding to [`search`].
///
/// The dashboard navigation links to `/v1/audit` directly; rather than
/// duplicating the search logic this alias forwards the same query
/// parameters (`limit`/`offset`/`since`/`action`/`actor`/…) to the same
/// underlying handler. RBAC is identical (`audit:read`).
pub async fn list_alias(
    state: State<AppState>,
    user: AuthenticatedUser,
    query: Query<AuditSearchQuery>,
) -> Result<impl IntoResponse, ApiError> {
    search(state, user, query).await
}

/// `GET /v1/audit/search` — paginated audit-log search.
///
/// Filters are AND-combined. `limit` defaults to 50, capped at 1000 by the
/// view validator; the controller falls back to
/// [`AuditSearchQuery::effective_limit`] for callers that bypass the
/// validator (e.g. typed-client tests).
pub async fn search(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<AuditSearchQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "audit:read")?;
    // Defence-in-depth: re-run the validator manually because `axum`'s
    // `Query<T>` extractor does not invoke `validator::Validate`.
    if let Some(limit) = q.limit {
        if !(1..=1_000).contains(&limit) {
            return Err(ApiError::Unprocessable(format!(
                "limit out of range: {limit}"
            )));
        }
    }
    let resp = state.audit_query.search(q).await.map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(resp)))
}

/// `GET /v1/audit/export?format=ndjson` — stream the audit buffer as NDJSON.
///
/// The response body is `application/x-ndjson` with one JSON object per
/// line. The adapter caps the response at
/// [`crate::view::audit_view::MAX_EXPORT_ENTRIES`] entries; callers needing
/// a full snapshot must page by advancing `since`.
pub async fn export_ndjson(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<AuditExportQuery>,
) -> Result<Response, ApiError> {
    require_permission(&user, "audit:read")?;
    let format = q.format.as_deref().unwrap_or("ndjson");
    if !format.eq_ignore_ascii_case("ndjson") {
        return Err(ApiError::Unprocessable(format!(
            "unsupported export format: {format}"
        )));
    }
    let body = state
        .audit_query
        .export_ndjson(q.since)
        .await
        .map_err(map_phase3)?;
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/x-ndjson")],
        body,
    )
        .into_response())
}

/// `GET /v1/audit/replay` — time-travel timeline for a single entity (P3-009).
///
/// Reconstructs the ordered mutation sequence for `(entity_type, entity_id)`
/// from the audit chain, scoped to the authenticated user's tenant. The
/// underlying hash chain is verified end-to-end before serving and any
/// integrity failure is surfaced explicitly via
/// `chain_verified=false` + `chain_error`.
///
/// RBAC: `audit:read`. Cross-tenant lookups are rejected — the `tenant_id`
/// sourced from the bearer token is the single source of truth.
pub async fn replay(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<AuditReplayQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "audit:read")?;
    let resp = state
        .audit_replay
        .replay(&user.claims.tenant_id, q)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(resp)))
}

/// `GET /v1/audit/diff` — before/after snapshot pair for a single entity (P3-009).
///
/// Returns the latest `after` snapshot at-or-before each endpoint, plus a
/// chain-verification flag. Both `from` and `to` are required and `from`
/// must be `<= to`.
///
/// RBAC: `audit:read`. Cross-tenant lookups are rejected.
pub async fn diff(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<AuditDiffQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "audit:read")?;
    let resp = state
        .audit_replay
        .diff(&user.claims.tenant_id, q)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(resp)))
}

/// Enforce a single `resource:action` permission with wildcard support.
///
/// Mirrors the helper in [`crate::controller::soc`] — kept private here so
/// the controller stays self-contained and there is no cross-module RBAC
/// coupling.
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
    fn search_requires_audit_read_permission() {
        let u = user(vec!["findings:read"]);
        assert!(matches!(
            require_permission(&u, "audit:read"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_audit_read_permission_allowed() {
        let u = user(vec!["audit:read"]);
        assert!(require_permission(&u, "audit:read").is_ok());
    }

    #[test]
    fn wildcard_audit_action_allowed() {
        let u = user(vec!["audit:*"]);
        assert!(require_permission(&u, "audit:read").is_ok());
    }

    #[test]
    fn full_wildcard_grant_allowed_for_audit() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "audit:read").is_ok());
    }

    #[test]
    fn wildcard_resource_allowed_for_read() {
        let u = user(vec!["*:read"]);
        assert!(require_permission(&u, "audit:read").is_ok());
    }

    #[test]
    fn missing_permission_denied() {
        let u = user(vec![]);
        assert!(matches!(
            require_permission(&u, "audit:read"),
            Err(ApiError::Forbidden)
        ));
    }
}
