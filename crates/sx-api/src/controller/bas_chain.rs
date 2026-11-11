//! Lateral-movement chain replay controller (P2-015).
//!
//! Exposes three routes that mirror the single-technique BAS surface:
//!
//! - `GET    /v1/bas/chains`                — list pre-canned catalogue.
//! - `POST   /v1/bas/chains/{id}/run`       — start a run for a chain.
//! - `GET    /v1/bas/chains/runs/{id}`      — fetch a run's status + steps.
//!
//! Permissions:
//!
//! - `bas:run_list` is required to browse the catalogue.
//! - `bas:run` is required to start a run. Mid-tier modes (anything above
//!   `theoretical`) re-use the existing
//!   [`crate::port::ApprovalPort::count_distinct_approvers`] two-person
//!   rule against the chain id.
//! - `bas:run_list` is required to read a recorded run.
//!
//! Every transition (start, complete, denied) emits a structured `tracing`
//! event tagged `target = "audit"` so the tap-sink picks it up as an
//! `AuditEvent`.

use axum::extract::{Path, State};
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::bas_view::{ListChainsResponse, StartChainRunRequest};
use crate::view::envelope::ApiResponse;

/// Minimum distinct approvers required before any non-`theoretical` chain
/// is allowed to start. Re-uses the per-technique two-person rule keyed
/// by the chain id.
const TWO_PERSON_RULE_MIN: u32 = 2;

/// `GET /v1/bas/chains`
pub async fn list_chains(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "bas:run_list")?;
    let items = state.bas_chain.list_catalogue().await.map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(ListChainsResponse { items })))
}

/// `POST /v1/bas/chains/{id}/run`
pub async fn start_run(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(chain_id): Path<String>,
    ValidatedJson(req): ValidatedJson<StartChainRunRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "bas:run")?;
    if chain_id.is_empty() {
        return Err(ApiError::BadRequest("chain id required".into()));
    }
    if uuid::Uuid::parse_str(&req.engagement_id).is_err() {
        return Err(ApiError::BadRequest(
            "engagement_id must be a uuid".to_owned(),
        ));
    }

    // Re-use the BAS two-person rule. Mid-tier modes require ≥2 distinct
    // approvers recorded against the (engagement, chain) pair before the
    // adapter executes a single step.
    if requires_two_person_rule(&req.mode) {
        let present = state
            .approvals
            .count_distinct_approvers(&req.engagement_id, &chain_id)
            .await
            .map_err(map_phase3)?;
        if present < TWO_PERSON_RULE_MIN {
            tracing::warn!(
                target = "audit",
                action = "bas.chain.denied",
                chain_id = %chain_id,
                engagement_id = %req.engagement_id,
                mode = %req.mode,
                actor = %user.claims.sub,
                tenant_id = %user.claims.tenant_id,
                reason = "two_person_rule",
                "bas.chain.denied"
            );
            return Err(ApiError::Forbidden);
        }
    }

    tracing::info!(
        target = "audit",
        action = "bas.chain.started",
        chain_id = %chain_id,
        engagement_id = %req.engagement_id,
        mode = %req.mode,
        actor = %user.claims.sub,
        tenant_id = %user.claims.tenant_id,
        "bas.chain.started"
    );

    let tenant_id = user.claims.tenant_id.clone();
    let run = state
        .bas_chain
        .start_run(tenant_id.clone(), chain_id.clone(), req)
        .await
        .map_err(map_phase3)?;

    tracing::info!(
        target = "audit",
        action = "bas.chain.completed",
        run_id = %run.run_id,
        chain_id = %chain_id,
        status = %run.status,
        actor = %user.claims.sub,
        tenant_id = %tenant_id,
        "bas.chain.completed"
    );

    Ok(Json(ApiResponse::ok(run)))
}

/// `GET /v1/bas/chains/runs/{id}`
pub async fn get_run(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Path(run_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "bas:run_list")?;
    if uuid::Uuid::parse_str(&run_id).is_err() {
        return Err(ApiError::BadRequest("run_id must be a uuid".into()));
    }
    let tenant_id = user.claims.tenant_id.clone();
    let run = state
        .bas_chain
        .get_run(&tenant_id, &run_id)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(run)))
}

/// Whether the requested mode requires the two-person rule.
const fn requires_two_person_rule(mode: &str) -> bool {
    matches!(mode.as_bytes(), b"safe_interactive" | b"active_exploit")
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
    use super::{require_permission, requires_two_person_rule};
    use crate::error::ApiError;
    use crate::middleware::auth::AuthenticatedUser;
    use sx_iam::domain::Permission;
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
    fn list_chains_requires_run_list_permission() {
        let u = user(vec!["finding:read"]);
        assert!(matches!(
            require_permission(&u, "bas:run_list"),
            Err(ApiError::Forbidden)
        ));
        let u_ok = user(vec!["bas:run_list"]);
        assert!(require_permission(&u_ok, "bas:run_list").is_ok());
        let u_wild = user(vec!["bas:*"]);
        assert!(require_permission(&u_wild, "bas:run_list").is_ok());
    }

    #[test]
    fn start_run_requires_run_permission() {
        let u = user(vec!["bas:run_list"]);
        assert!(matches!(
            require_permission(&u, "bas:run"),
            Err(ApiError::Forbidden)
        ));
        let u_ok = user(vec!["bas:run"]);
        assert!(require_permission(&u_ok, "bas:run").is_ok());
    }

    #[test]
    fn two_person_rule_matrix() {
        assert!(!requires_two_person_rule("theoretical"));
        assert!(requires_two_person_rule("safe_interactive"));
        assert!(requires_two_person_rule("active_exploit"));
        assert!(!requires_two_person_rule("garbage"));
    }
}
