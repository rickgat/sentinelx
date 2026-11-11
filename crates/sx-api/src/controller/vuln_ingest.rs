//! Credentialed vulnerability-scanner ingest controller — `POST /v1/vuln/import`
//! and `GET /v1/vuln/imports`.
//!
//! Accepts a `multipart/form-data` upload (max 100 MiB) carrying the raw
//! scanner XML (Nessus `.nessus` or OpenVAS GMP) plus a `source` field
//! identifying the family. The handler:
//!
//! 1. Enforces `vuln:import` RBAC.
//! 2. Streams the multipart body to memory and asserts the 100 MiB cap.
//! 3. Delegates to [`crate::port::VulnIngestPort::import`] which owns the
//!    parse + dedup + persist pipeline.
//! 4. Projects the result into [`VulnImportResponse`].
//!
//! `GET /v1/vuln/imports` requires `vuln:read` and surfaces the persistent
//! import-history newest-first.

use axum::extract::{Multipart, Query, State};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use sx_iam::domain::Permission;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::vuln_ingest_view::ListVulnImportsResponse;

/// Hard cap on the accepted payload size (mirrors `sx-vuln-ingest`).
const MAX_PAYLOAD_BYTES: usize = 100 * 1024 * 1024;

/// `POST /v1/vuln/import` — multipart upload of a scanner export.
///
/// Required parts:
/// - `source`: text part — one of `nessus`, `openvas`.
/// - `file`:   binary/text part — the raw XML body.
///
/// Returns `200 OK` carrying the freshly persisted import receipt plus the
/// dedup / parse-error counts on success.
pub async fn import(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "vuln:import")?;

    let mut source: Option<String> = None;
    let mut payload: Option<Vec<u8>> = None;

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
            "source" => {
                let s = std::str::from_utf8(&bytes)
                    .map_err(|_| ApiError::BadRequest("source must be utf-8".into()))?
                    .trim()
                    .to_ascii_lowercase();
                source = Some(s);
            }
            "file" | "payload" => {
                if bytes.len() > MAX_PAYLOAD_BYTES {
                    return Err(ApiError::BadRequest(format!(
                        "payload too large: {} bytes (max {MAX_PAYLOAD_BYTES})",
                        bytes.len()
                    )));
                }
                payload = Some(bytes.to_vec());
            }
            _ => {
                // Ignore unknown fields — keeps the wire forward-compatible
                // with optional metadata fields the client may add later.
            }
        }
    }

    let source = source.ok_or_else(|| ApiError::BadRequest("source field is required".into()))?;
    if source != "nessus" && source != "openvas" {
        return Err(ApiError::BadRequest(
            "source must be 'nessus' or 'openvas'".into(),
        ));
    }
    let payload = payload.ok_or_else(|| ApiError::BadRequest("file field is required".into()))?;
    if payload.is_empty() {
        return Err(ApiError::BadRequest("file field is empty".into()));
    }

    let resp = state
        .vuln_ingest
        .import(&user.claims.tenant_id, &source, &payload)
        .await
        .map_err(map_phase3)?;

    tracing::info!(
        target = "audit",
        action = "vuln.import.recorded",
        tenant_id = %user.claims.tenant_id,
        actor = %user.claims.sub,
        source = %source,
        asset_count = resp.import.asset_count,
        finding_count = resp.import.finding_count,
        status = %resp.import.status,
        "vuln.import.recorded"
    );

    Ok(Json(ApiResponse::ok(resp)))
}

/// Query string for `GET /v1/vuln/imports`.
#[derive(Debug, Clone, Deserialize)]
pub struct ListImportsQuery {
    /// Maximum number of entries to return. Defaults to 50, capped at 200.
    pub limit: Option<u32>,
}

/// `GET /v1/vuln/imports?limit=...` — persistent import-history.
pub async fn list_imports(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<ListImportsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "vuln:read")?;
    let limit = q.limit.unwrap_or(50).clamp(1, 200) as usize;
    let items = state
        .vuln_ingest
        .list(&user.claims.tenant_id, limit)
        .await
        .map_err(map_phase3)?;
    Ok(Json(ApiResponse::ok(ListVulnImportsResponse { items })))
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
    fn import_requires_vuln_import_permission() {
        let u = user(vec!["vuln:read"]);
        assert!(matches!(
            require_permission(&u, "vuln:import"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn exact_vuln_import_permission_allowed() {
        let u = user(vec!["vuln:import"]);
        assert!(require_permission(&u, "vuln:import").is_ok());
    }

    #[test]
    fn wildcard_vuln_action_allowed() {
        let u = user(vec!["vuln:*"]);
        assert!(require_permission(&u, "vuln:import").is_ok());
    }

    #[test]
    fn list_requires_vuln_read_permission() {
        let u = user(vec!["vuln:import"]);
        assert!(matches!(
            require_permission(&u, "vuln:read"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn wildcard_resource_for_read_allowed() {
        let u = user(vec!["*:read"]);
        assert!(require_permission(&u, "vuln:read").is_ok());
    }

    #[test]
    fn no_permissions_denied() {
        let u = user(vec![]);
        assert!(matches!(
            require_permission(&u, "vuln:import"),
            Err(ApiError::Forbidden)
        ));
    }
}
