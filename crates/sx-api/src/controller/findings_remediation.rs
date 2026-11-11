//! Findings remediation-link controllers — `PATCH` + `DELETE` on
//! `/v1/findings/{id}/remediation`.
//!
//! Two routes, both gated on the `findings:write` permission with the same
//! wildcard-aware helper used by [`crate::controller::assets`] /
//! [`crate::controller::findings_bulk`]:
//!
//! - `PATCH  /v1/findings/{id}/remediation` — upsert a remediation link
//!   for the finding identified by `{id}`. Returns the persisted
//!   [`RemediationLinkView`] on success.
//! - `DELETE /v1/findings/{id}/remediation` — drop the link. Returns
//!   `204 No Content` on success and `404 Not Found` when no link is
//!   currently recorded.
//!
//! ## Wire contract
//!
//! The PATCH body is validated by `ValidatedJson` against the field-level
//! shape constraints declared in [`RemediationLinkRequest`] — scheme =
//! https, host ∈ `{github.com, gitlab.com}` for `pr_url`, marker presence
//! (`/browse/` or `/issues/`) for `ticket_url`, comment ≤ 2 000 chars.
//!
//! The cross-field guard — at least one of `pr_url` / `ticket_url` must be
//! present — is enforced inside the handler via
//! [`RemediationLinkRequest::require_at_least_one_url`] so the rejection
//! reason carries a stable `missing_url` code in the response envelope.
//!
//! Adapters never see anything outside the validated shape; the
//! [`crate::port::RemediationTrackingPort`] trait object handed to the
//! handler is the only thing this module knows about persistence.

use axum::extract::{Path, State};
use axum::http::StatusCode;
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
use crate::view::finding_view::{RemediationLinkRequest, RemediationLinkView};

/// `PATCH /v1/findings/{id}/remediation` — upsert the remediation link.
///
/// Validation order:
///
/// 1. [`ValidatedJson`] checks every field's shape (scheme, host, marker,
///    length).
/// 2. The handler enforces the cross-field rule (at least one URL).
/// 3. The handler gates on the `findings:write` permission.
/// 4. The handler delegates to
///    [`crate::port::RemediationTrackingPort::link`].
///
/// The adapter's [`RemediationLinkView`] response is returned verbatim
/// under the standard envelope.
pub async fn link(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    Path(id): Path<String>,
    ValidatedJson(req): ValidatedJson<RemediationLinkRequest>,
) -> Result<Json<ApiResponse<RemediationLinkView>>, ApiError> {
    require_permission(&user, "findings:write")?;
    if let Err(e) = req.require_at_least_one_url() {
        let msg = e
            .message
            .as_ref()
            .map_or_else(|| e.code.as_ref().to_owned(), |m| m.as_ref().to_owned());
        return Err(ApiError::Unprocessable(msg));
    }
    let actor_id = user.claims.sub.clone();
    let view = state
        .remediation_tracking
        .link(&scope.tenant_id, &id, &actor_id, req)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(view)))
}

/// `DELETE /v1/findings/{id}/remediation` — drop the remediation link.
///
/// Returns `204 No Content` on success and translates a missing link via
/// [`crate::controller::map_phase3`] into `404 Not Found`.
pub async fn unlink(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "findings:write")?;
    state
        .remediation_tracking
        .unlink(&scope.tenant_id, &id)
        .await
        .map_err(map_phase3)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Enforce a single `resource:action` permission with wildcard support.
///
/// Mirrors the helper in [`crate::controller::assets`] /
/// [`crate::controller::findings_bulk`] — kept private so this controller
/// stays self-contained with no cross-module RBAC coupling.
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
#[allow(clippy::unwrap_used, clippy::expect_used)]
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
    fn link_requires_findings_write_permission() {
        let u = user(vec!["findings:read"]);
        assert!(matches!(
            require_permission(&u, "findings:write"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_findings_write_permission_allowed() {
        let u = user(vec!["findings:write"]);
        assert!(require_permission(&u, "findings:write").is_ok());
    }

    #[test]
    fn wildcard_findings_action_allowed() {
        let u = user(vec!["findings:*"]);
        assert!(require_permission(&u, "findings:write").is_ok());
    }

    #[test]
    fn wildcard_resource_for_write_allowed() {
        let u = user(vec!["*:write"]);
        assert!(require_permission(&u, "findings:write").is_ok());
    }

    #[test]
    fn full_wildcard_grant_allowed() {
        let u = user(vec!["*:*"]);
        assert!(require_permission(&u, "findings:write").is_ok());
    }

    #[test]
    fn no_permissions_denied() {
        let u = user(vec![]);
        assert!(matches!(
            require_permission(&u, "findings:write"),
            Err(ApiError::Forbidden)
        ));
    }
}
