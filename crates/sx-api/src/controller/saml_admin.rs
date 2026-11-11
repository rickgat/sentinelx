//! P0-004 — SAML IdP configuration admin controller.
//!
//! Two endpoints under normal auth + RBAC (`admin:tenants`):
//!
//! - `GET /v1/admin/saml/idp` — the calling tenant's IdP config (or 404).
//! - `PUT /v1/admin/saml/idp` — upsert it.
//!
//! These work regardless of the SAML SP enabled flag so an operator can
//! author the IdP record (persisted durably) before flipping
//! `saml.enabled = true`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::SamlIdpAdminPortError;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::saml_view::SamlIdpConfigView;

/// `GET /v1/admin/saml/idp` — return the calling tenant's IdP config.
/// Requires `admin:tenants`. 404 when none is set.
pub async fn get_idp(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "admin:tenants")?;
    let found = state
        .saml_idp_admin
        .get_idp(&user.claims.tenant_id)
        .await
        .map_err(map_err)?;
    match found {
        Some(cfg) => Ok((StatusCode::OK, Json(ApiResponse::ok(cfg)))),
        None => Err(ApiError::NotFound),
    }
}

/// `PUT /v1/admin/saml/idp` — upsert the calling tenant's IdP config.
/// Requires `admin:tenants`. Persisted durably when a database is wired.
pub async fn put_idp(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<SamlIdpConfigView>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "admin:tenants")?;
    tracing::info!(
        target: "controller.saml_admin.set_idp",
        tenant_id = %user.claims.tenant_id,
        user_id = %user.claims.sub,
        entity_id = %req.entity_id,
        "saml idp config upsert requested",
    );
    let stored = state
        .saml_idp_admin
        .set_idp(&user.claims.tenant_id, req)
        .await
        .map_err(map_err)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(stored))))
}

/// Require that `user` carries `perm` (resource/action, wildcard-aware).
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

/// Translate a [`SamlIdpAdminPortError`] into the nearest [`ApiError`].
pub fn map_err(err: SamlIdpAdminPortError) -> ApiError {
    match err {
        SamlIdpAdminPortError::Invalid(m) => ApiError::Unprocessable(m),
        SamlIdpAdminPortError::Internal(m) => ApiError::Internal(m),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_maps_to_unprocessable() {
        assert!(matches!(
            map_err(SamlIdpAdminPortError::Invalid("bad".into())),
            ApiError::Unprocessable(_)
        ));
    }

    #[test]
    fn internal_maps_to_internal() {
        assert!(matches!(
            map_err(SamlIdpAdminPortError::Internal("boom".into())),
            ApiError::Internal(_)
        ));
    }
}
