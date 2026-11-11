//! Prowler v4 native-JSON CSPM import controller (P1-009).
//!
//! Backs `POST /v1/discovery/prowler/import` — a `multipart/form-data`
//! upload of an externally-produced Prowler v4 native-JSON report for
//! GCP or Azure. AWS rows in the same payload are silently dropped at
//! the parser layer to avoid double-ingestion (AWS is covered by the
//! OCSF scanner path).
//!
//! ## Wire shape
//!
//! Accepted multipart fields:
//!
//! - `file` (or `payload`): the raw JSON body. Hard cap 100 MiB.
//! - `actor` (optional): free-form identifier recorded in the audit log
//!   alongside the authenticated subject (`user:<sub>`).
//!
//! ## Authorisation
//!
//! Requires the `cspm:import` permission. Cross-tenant rejection happens
//! inside the port — a tenant that uploads a report referencing a cloud
//! account owned by **another** tenant receives `403 Forbidden`.
//!
//! ## Status codes
//!
//! - `200 OK` on success with the per-import metrics envelope.
//! - `400 Bad Request` for missing `file` field, empty body, multipart
//!   parse failure, or payload exceeding the 100 MiB cap (mirrors the
//!   `POST /v1/vuln/import` convention).
//! - `403 Forbidden` for missing permission **or** cross-tenant rejection.
//! - `422 Unprocessable Entity` when the payload is not valid Prowler v4
//!   JSON.

use axum::extract::{Multipart, State};
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::error::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::ProwlerImportPortError;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;

/// Hard cap on the accepted payload size (must match the spec — 100 MiB).
const MAX_PAYLOAD_BYTES: usize = 100 * 1024 * 1024;

/// `POST /v1/discovery/prowler/import` — multipart upload of a Prowler v4
/// native-JSON CSPM report.
pub async fn import(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "cspm:import")?;

    let mut payload: Option<Vec<u8>> = None;
    let mut actor_override: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::BadRequest(format!("multipart read failed: {e}")))?
    {
        let name = field.name().unwrap_or("").to_owned();
        let bytes = field
            .bytes()
            .await
            .map_err(|e| ApiError::BadRequest(format!("multipart field read failed: {e}")))?;
        match name.as_str() {
            "file" | "payload" => {
                if bytes.len() > MAX_PAYLOAD_BYTES {
                    return Err(ApiError::BadRequest(format!(
                        "payload too large: {} bytes (max {MAX_PAYLOAD_BYTES})",
                        bytes.len()
                    )));
                }
                payload = Some(bytes.to_vec());
            }
            "actor" => {
                if let Ok(s) = std::str::from_utf8(&bytes) {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        actor_override = Some(trimmed.to_owned());
                    }
                }
            }
            _ => {
                // Forward-compatible: ignore unknown fields.
            }
        }
    }

    let payload = payload.ok_or_else(|| ApiError::BadRequest("file field is required".into()))?;
    if payload.is_empty() {
        return Err(ApiError::BadRequest("file field is empty".into()));
    }

    // Audit actor: prefer explicit override, fall back to subject claim.
    let actor = actor_override.unwrap_or_else(|| format!("user:{}", user.claims.sub));

    let resp = state
        .prowler_import
        .import(&user.claims.tenant_id, &actor, &payload)
        .await
        .map_err(map_err)?;

    tracing::info!(
        target = "audit",
        action = "cspm.prowler.import",
        tenant_id = %user.claims.tenant_id,
        actor = %actor,
        upload_digest = %resp.upload_digest,
        upload_bytes = resp.upload_bytes,
        parsed = resp.parsed,
        written = resp.written,
        rejected_cross_tenant = resp.rejected_cross_tenant,
        deduplicated = resp.deduplicated,
        kev_uplifts_applied = resp.kev_uplifts_applied,
        unmapped_check_ids = resp.unmapped_check_ids,
        "cspm.prowler.import",
    );

    Ok(Json(ApiResponse::ok(resp)))
}

/// Map [`ProwlerImportPortError`] onto [`ApiError`].
pub fn map_err(err: ProwlerImportPortError) -> ApiError {
    match err {
        ProwlerImportPortError::TooLarge { actual, limit } => {
            ApiError::BadRequest(format!("payload too large: {actual} bytes > {limit}"))
        }
        ProwlerImportPortError::Malformed(m) => ApiError::Unprocessable(m),
        ProwlerImportPortError::CrossTenant(_) => ApiError::Forbidden,
        ProwlerImportPortError::Internal(m) => ApiError::Internal(m),
    }
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
    fn import_requires_cspm_import_permission() {
        let u = user(vec!["cspm:read"]);
        assert!(matches!(
            require_permission(&u, "cspm:import"),
            Err(ApiError::Forbidden),
        ));
    }

    #[test]
    fn exact_cspm_import_permission_allowed() {
        let u = user(vec!["cspm:import"]);
        assert!(require_permission(&u, "cspm:import").is_ok());
    }

    #[test]
    fn wildcard_cspm_action_allowed() {
        let u = user(vec!["cspm:*"]);
        assert!(require_permission(&u, "cspm:import").is_ok());
    }

    #[test]
    fn wildcard_resource_for_import_allowed() {
        let u = user(vec!["*:import"]);
        assert!(require_permission(&u, "cspm:import").is_ok());
    }

    #[test]
    fn no_permissions_denied() {
        let u = user(vec![]);
        assert!(matches!(
            require_permission(&u, "cspm:import"),
            Err(ApiError::Forbidden),
        ));
    }

    #[test]
    fn map_err_too_large_to_400() {
        let err = map_err(ProwlerImportPortError::TooLarge {
            actual: 200_000_000,
            limit: 100_000_000,
        });
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn map_err_malformed_to_422() {
        let err = map_err(ProwlerImportPortError::Malformed("bad".into()));
        assert!(matches!(err, ApiError::Unprocessable(_)));
    }

    #[test]
    fn map_err_cross_tenant_to_403() {
        let err = map_err(ProwlerImportPortError::CrossTenant("x".into()));
        assert!(matches!(err, ApiError::Forbidden));
    }

    #[test]
    fn map_err_internal_to_500() {
        let err = map_err(ProwlerImportPortError::Internal("boom".into()));
        assert!(matches!(err, ApiError::Internal(_)));
    }
}
