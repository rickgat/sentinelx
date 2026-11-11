//! SOC controller — autonomous-correlator alert listing + event submission.
//!
//! Two routes:
//!
//! - `GET  /v1/soc/alerts` — buffered alert snapshot (RBAC: `soc:read`).
//! - `POST /v1/soc/events` — operator event submission (RBAC: `soc:write`).
//!
//! Both handlers delegate to [`crate::port::SocPort`]. The concrete
//! correlator + sink live in `services/sx-monolith/src/adapters/soc.rs`.

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::extractor::tenant::TenantScope;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::soc_view::{ListSocAlertsResponse, SubmitSocEventRequest};

/// `GET /v1/soc/alerts` — list recent buffered SOC alerts.
///
/// Filters to the caller's tenant. Global alerts (tenant_id = None on the
/// alert side) are returned to every caller; tenant-scoped alerts are
/// returned only when their tenant matches the caller's `tenant_id` claim.
pub async fn list_alerts(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "soc:read")?;
    let items = state
        .soc
        .list_alerts(Some(scope.tenant_id.as_str()))
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(ListSocAlertsResponse { items })))
}

/// `POST /v1/soc/events` — push an event into the correlator for rule testing.
///
/// Returns the number of events accepted by the mpsc sender (always `1`).
pub async fn submit_event(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<SubmitSocEventRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "soc:write")?;
    let accepted = state
        .soc
        .submit_event(req.event)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(serde_json::json!({
        "accepted": accepted,
    }))))
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
    fn list_alerts_requires_soc_read_permission() {
        let u = user(vec!["findings:read"]);
        assert!(matches!(
            require_permission(&u, "soc:read"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_soc_read_permission_allowed() {
        let u = user(vec!["soc:read"]);
        assert!(require_permission(&u, "soc:read").is_ok());
    }

    #[test]
    fn submit_event_requires_soc_write_permission() {
        // `soc:read` is NOT enough — must hold `soc:write` to push events.
        let u = user(vec!["soc:read"]);
        assert!(matches!(
            require_permission(&u, "soc:write"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_soc_write_permission_allowed() {
        let u = user(vec!["soc:write"]);
        assert!(require_permission(&u, "soc:write").is_ok());
    }

    #[test]
    fn wildcard_soc_action_allowed() {
        let u = user(vec!["soc:*"]);
        assert!(require_permission(&u, "soc:read").is_ok());
        assert!(require_permission(&u, "soc:write").is_ok());
    }

    #[test]
    fn full_wildcard_grant_allowed_for_soc() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "soc:read").is_ok());
        assert!(require_permission(&u, "soc:write").is_ok());
    }

    #[test]
    fn wildcard_resource_allowed_for_write() {
        let u = user(vec!["*:write"]);
        assert!(require_permission(&u, "soc:write").is_ok());
    }
}
