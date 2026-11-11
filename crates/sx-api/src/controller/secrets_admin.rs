//! Per-tenant DEK rotation admin controller (CRIT-003).
//!
//! Two routes, both gated by the `admin:secrets` permission:
//!
//! - `POST /v1/admin/secrets/rotate-dek`
//!   * Body: [`crate::view::secrets_admin_view::RotateDekRequest`].
//!   * Triggers (or resumes) a per-tenant DEK rotation. Delegates to
//!     [`crate::port::DekRotationAdminPort::rotate_dek`].
//! - `GET  /v1/admin/secrets/rotation-progress?tenant_id=…`
//!   * Reports the latest checkpoint for `tenant_id`. Delegates to
//!     [`crate::port::DekRotationAdminPort::rotation_progress`].
//!
//! ## Security notes
//!
//! - The caller's permissions are validated at the controller layer. The
//!   `admin:secrets` permission is required for both routes.
//! - The target `tenant_id` comes from the request body / query string,
//!   NOT the bearer claims, because platform-wide admins may rotate
//!   tenant DEKs on behalf of customers. The adapter performs the
//!   cross-tenant authorisation (see
//!   [`crate::port::DekRotationAdminPort`] docstring).
//! - Neither plaintext nor ciphertext bytes ever appear in the wire
//!   response — only `(tenant_id, target_dek_version, status, counters,
//!   timestamps, redacted_error)`.

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::secrets_admin_view::{RotateDekRequest, RotateDekResponse, RotationProgressQuery};

/// `POST /v1/admin/secrets/rotate-dek` — start (or resume) a rotation.
pub async fn rotate_dek(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(body): Json<RotateDekRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "admin:secrets")?;
    if body.tenant_id.trim().is_empty() {
        return Err(ApiError::Unprocessable("tenant_id is required".into()));
    }
    if let Some(v) = body.target_version {
        if v == 0 {
            return Err(ApiError::Unprocessable("target_version must be > 0".into()));
        }
    }
    let view: RotateDekResponse = state
        .dek_rotation_admin
        .rotate_dek(&body.tenant_id, body.target_version)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(view)))
}

/// `GET /v1/admin/secrets/rotation-progress` — latest checkpoint.
pub async fn rotation_progress(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<RotationProgressQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "admin:secrets")?;
    if q.tenant_id.trim().is_empty() {
        return Err(ApiError::Unprocessable("tenant_id is required".into()));
    }
    let view = state
        .dek_rotation_admin
        .rotation_progress(&q.tenant_id)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(view)))
}

/// Permission gate — identical to the audit_anchor controller's helper,
/// kept private so each controller stays self-contained.
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
    fn rotate_dek_requires_admin_secrets() {
        let u = user(vec!["audit:read"]);
        assert!(matches!(
            require_permission(&u, "admin:secrets"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_admin_secrets_allowed() {
        let u = user(vec!["admin:secrets"]);
        assert!(require_permission(&u, "admin:secrets").is_ok());
    }

    #[test]
    fn admin_wildcard_action_allowed() {
        let u = user(vec!["admin:*"]);
        assert!(require_permission(&u, "admin:secrets").is_ok());
    }

    #[test]
    fn full_wildcard_allowed() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "admin:secrets").is_ok());
    }

    #[test]
    fn no_permissions_denied() {
        let u = user(vec![]);
        assert!(matches!(
            require_permission(&u, "admin:secrets"),
            Err(ApiError::Forbidden)
        ));
    }
}
