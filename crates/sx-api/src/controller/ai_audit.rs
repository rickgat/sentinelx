//! AI security audit controllers (AI-SEC-001).
//!
//! Read + run surface for the AI-audit subsystem. Every endpoint derives the
//! active tenant from the caller's [`AuthenticatedUser`] claims so an
//! attacker cannot ask for another tenant's data via URL manipulation.
//!
//! Routes:
//!
//! * `GET  /v1/ai-audit/assets`   — AI asset inventory (`ai_audit:read`).
//! * `GET  /v1/ai-audit/aibom`    — CycloneDX-ML-style AI-BOM (`ai_audit:read`).
//! * `GET  /v1/ai-audit/controls` — AI governance controls (`ai_audit:read`).
//! * `POST /v1/ai-audit/run`      — run a full audit (`ai_audit:run`).

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_ai_audit;
use crate::error::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::ai_audit_view::RunExternalAuditRequest;
use crate::view::envelope::ApiResponse;

/// `GET /v1/ai-audit/assets` — list the caller-tenant AI asset inventory.
pub async fn list_assets(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "ai_audit:read")?;
    let resp = state
        .ai_audit
        .list_assets(&user.claims.tenant_id)
        .await
        .map_err(map_ai_audit)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

/// `GET /v1/ai-audit/aibom` — build the caller-tenant AI-BOM.
pub async fn get_aibom(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "ai_audit:read")?;
    let resp = state
        .ai_audit
        .aibom(&user.claims.tenant_id)
        .await
        .map_err(map_ai_audit)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

/// `GET /v1/ai-audit/controls` — list the built-in AI governance controls.
pub async fn list_controls(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "ai_audit:read")?;
    let resp = state
        .ai_audit
        .list_controls(&user.claims.tenant_id)
        .await
        .map_err(map_ai_audit)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

/// `POST /v1/ai-audit/run` — run a full AI audit for the caller's tenant.
///
/// Requires `ai_audit:run`. The adapter records the run to the
/// copilot-decision audit sink (ADR-0004 §7).
pub async fn run_audit(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "ai_audit:run")?;
    tracing::info!(
        target: "controller.ai_audit.run",
        tenant_id = %user.claims.tenant_id,
        user_id = %user.claims.sub,
        "ai-audit run requested",
    );
    let resp = state
        .ai_audit
        .run_audit(&user.claims.tenant_id, &user.claims.sub)
        .await
        .map_err(map_ai_audit)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

/// `POST /v1/ai-audit/run-external` — red-team a config-registered external
/// LLM target (AI-SEC-002).
///
/// Requires `ai_audit:run`. The target's host must be in scope of the named
/// Active, in-window, approved engagement, or the adapter returns 403.
pub async fn run_external_audit(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<RunExternalAuditRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "ai_audit:run")?;
    tracing::info!(
        target: "controller.ai_audit.run_external",
        tenant_id = %user.claims.tenant_id,
        user_id = %user.claims.sub,
        engagement_id = %req.engagement_id,
        target_id = %req.target_id,
        "external ai-audit run requested",
    );
    let resp = state
        .ai_audit
        .run_external_audit(
            &user.claims.tenant_id,
            &user.claims.sub,
            &req.engagement_id,
            &req.target_id,
        )
        .await
        .map_err(map_ai_audit)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

/// Enforce a single `resource:action` permission with wildcard support.
///
/// Copied verbatim from `controller::runtime` — the wildcard-aware form
/// (`*` resource / `*` action) is required so an `admin`'s `*:*` grant
/// satisfies `ai_audit:read` / `ai_audit:run`. A future refactor moving
/// this to a shared util would consolidate the copies.
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
    fn require_permission_allows_exact() {
        let u = user(vec!["ai_audit:read"]);
        assert!(require_permission(&u, "ai_audit:read").is_ok());
    }

    #[test]
    fn require_permission_wildcard_allows() {
        let u = user(vec!["ai_audit:*"]);
        assert!(require_permission(&u, "ai_audit:run").is_ok());
    }

    #[test]
    fn require_permission_denies_when_missing() {
        let u = user(vec!["ueba:read"]);
        assert!(matches!(
            require_permission(&u, "ai_audit:read"),
            Err(ApiError::Forbidden)
        ));
    }
}
