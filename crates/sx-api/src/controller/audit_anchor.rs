//! External audit-chain anchoring controller (P1-015).
//!
//! Two routes (both RBAC `audit:read`):
//!
//! - `GET /v1/audit/anchors` — paginated list of the caller-tenant's
//!   anchor runs, newest first.
//! - `POST /v1/audit/anchors/verify/{run_id}` — re-verify a persisted
//!   anchor run against the operator-pinned per-tenant CA cert.
//!
//! Both handlers delegate to [`crate::port::AuditAnchorPort`]. The
//! concrete adapter lives in `services/sx-monolith/src/adapters/`.
//!
//! ## Security notes
//!
//! - The caller's `tenant_id` (from the bearer token) is the single
//!   source of truth. The port refuses cross-tenant lookups with a 403.
//! - Raw TSA reply bytes are NEVER projected onto the wire. The list
//!   view exposes only `payload_size_bytes`; the verify endpoint loads
//!   the bytes server-side and returns only the parsed serial /
//!   genTime / Merkle root.
//! - Verification failure auto-emits an `sx-audit` CRITICAL event via
//!   the port adapter — the controller surfaces only the 4xx response.

use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::audit_anchor_view::AuditAnchorListQuery;
use crate::view::envelope::ApiResponse;

/// `GET /v1/audit/anchors` — list the caller-tenant's anchor runs.
///
/// `limit` is validated against [`crate::view::audit_anchor_view::MAX_ANCHOR_LIMIT`]
/// at the controller layer because `axum`'s `Query<T>` extractor does
/// not invoke `validator::Validate`.
pub async fn list(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<AuditAnchorListQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "audit:read")?;
    if let Some(limit) = q.limit {
        if !(1..=500).contains(&limit) {
            return Err(ApiError::Unprocessable(format!(
                "limit out of range: {limit}"
            )));
        }
    }
    let resp = state
        .audit_anchor
        .list(&user.claims.tenant_id, q)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(resp)))
}

/// `POST /v1/audit/anchors/verify/{run_id}` — re-verify a persisted run.
///
/// On verification failure the port emits a CRITICAL `sx-audit` event
/// and surfaces a [`Phase3PortError::Invalid`] which maps to 422 here.
/// A cross-tenant lookup surfaces as 403.
pub async fn verify(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(run_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "audit:read")?;
    let resp = state
        .audit_anchor
        .verify(&user.claims.tenant_id, &run_id)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(resp)))
}

/// Enforce a single `resource:action` permission with wildcard support.
///
/// Mirrors [`crate::controller::audit::require_permission`] — kept
/// private so the controller stays self-contained.
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
    fn anchor_list_requires_audit_read() {
        let u = user(vec!["findings:read"]);
        assert!(matches!(
            require_permission(&u, "audit:read"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_audit_read_allowed() {
        let u = user(vec!["audit:read"]);
        assert!(require_permission(&u, "audit:read").is_ok());
    }

    #[test]
    fn audit_wildcard_action_allowed() {
        let u = user(vec!["audit:*"]);
        assert!(require_permission(&u, "audit:read").is_ok());
    }

    #[test]
    fn full_wildcard_allowed_for_audit() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "audit:read").is_ok());
    }

    #[test]
    fn no_permissions_denied() {
        let u = user(vec![]);
        assert!(matches!(
            require_permission(&u, "audit:read"),
            Err(ApiError::Forbidden)
        ));
    }
}
