//! API DAST (P2-013) HTTP controller — `/v1/discovery/dast/*`.
//!
//! Two endpoints are wired:
//!
//! * `POST /v1/discovery/dast/scan` — multipart upload carrying:
//!   - `postman` (alias `collection`): Postman v2.1 JSON bytes.
//!   - `base_url` (alias `target` / `base-url`): target API base URL.
//!   - `bearer` (alias `token` / `authorization`): optional bearer
//!     credential. **Never logged.**
//!   - `idor_probe_ids` (alias `probe_ids`): optional comma-separated
//!     list of known other-tenant ids permitted in IDOR probes.
//!
//!   Replays the collection against the live target and returns the
//!   projected scan result.
//!
//! * `GET /v1/discovery/dast/scans` — newest-first list of previously
//!   persisted scans for the caller's tenant. The `limit` query
//!   parameter is clamped to `[1, 200]` (default 50).
//!
//! Every successful scan emits a structured audit-log line under the
//! `audit` target carrying the tenant id, actor, collection name,
//! request count, and finding count. The raw bearer token is **never**
//! logged or persisted by this controller — the multipart parser
//! consumes the credential into a [`secrecy::SecretString`] before any
//! tracing event is written.

use axum::extract::{Multipart, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use secrecy::SecretString;
use serde::Deserialize;
use sx_core::reference::url_guard::validate_scan_target;
use sx_iam::domain::Permission;

use crate::controller::scan::map_scan_target_error;
use crate::error::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::ApiDastPortError;
use crate::state::AppState;
use crate::view::api_dast_view::{ApiDastListResponse, ApiDastScanResponse};
use crate::view::envelope::ApiResponse;

/// Hard cap on the accepted Postman collection bytes.
const MAX_COLLECTION_BYTES: usize = 16 * 1024 * 1024;

/// Hard cap on individual non-`postman` multipart string fields
/// (base URL, bearer token, IDOR ids). Mirrors the kind of values an
/// operator would paste — none of them legitimately exceed a couple of
/// KiB.
const MAX_TEXT_FIELD_BYTES: usize = 16 * 1024;

/// `POST /v1/discovery/dast/scan` — replay an uploaded Postman v2.1
/// collection against a live target API and return the projected scan
/// result.
pub async fn scan(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `scan:write`.
    require_permission(&user, "scan:write")?;
    let mut collection: Option<Vec<u8>> = None;
    let mut base_url: Option<String> = None;
    let mut bearer: Option<SecretString> = None;
    let mut probe_ids: Vec<String> = Vec::new();

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
            "postman" | "collection" => {
                if bytes.len() > MAX_COLLECTION_BYTES {
                    return Err(ApiError::BadRequest(format!(
                        "postman collection too large: {} bytes (max {MAX_COLLECTION_BYTES})",
                        bytes.len()
                    )));
                }
                collection = Some(bytes.to_vec());
            }
            "base_url" | "base-url" | "target" => {
                if bytes.len() > MAX_TEXT_FIELD_BYTES {
                    return Err(ApiError::BadRequest("base_url field too large".into()));
                }
                let s = std::str::from_utf8(&bytes)
                    .map_err(|_| ApiError::BadRequest("base_url must be utf-8".into()))?
                    .trim()
                    .to_owned();
                base_url = Some(s);
            }
            "bearer" | "token" | "authorization" => {
                if bytes.len() > MAX_TEXT_FIELD_BYTES {
                    return Err(ApiError::BadRequest("bearer field too large".into()));
                }
                let s = std::str::from_utf8(&bytes)
                    .map_err(|_| ApiError::BadRequest("bearer must be utf-8".into()))?
                    .trim()
                    .to_owned();
                if !s.is_empty() {
                    bearer = Some(SecretString::from(s));
                }
            }
            "idor_probe_ids" | "probe_ids" => {
                if bytes.len() > MAX_TEXT_FIELD_BYTES {
                    return Err(ApiError::BadRequest(
                        "idor_probe_ids field too large".into(),
                    ));
                }
                let s = std::str::from_utf8(&bytes)
                    .map_err(|_| ApiError::BadRequest("idor_probe_ids must be utf-8".into()))?;
                probe_ids = s
                    .split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(ToOwned::to_owned)
                    .collect();
            }
            _ => {
                // Ignore unknown fields — keeps the wire forward-compatible.
            }
        }
    }

    let collection =
        collection.ok_or_else(|| ApiError::BadRequest("postman field is required".into()))?;
    if collection.is_empty() {
        return Err(ApiError::BadRequest("postman field is empty".into()));
    }
    let base_url =
        base_url.ok_or_else(|| ApiError::BadRequest("base_url field is required".into()))?;
    if base_url.is_empty() {
        return Err(ApiError::BadRequest("base_url field is empty".into()));
    }

    // SSRF guard (QC-SCAN-2026-06-25 fixes a + b): reject non-http(s)
    // schemes, loopback, link-local, and cloud-metadata IPs BEFORE
    // dispatching the Postman replay. We rebind `base_url` to the
    // post-guard canonical URL so the persisted scan record reflects
    // the normalised target.
    let validated = validate_scan_target(&base_url)
        .await
        .map_err(map_scan_target_error)?;
    let base_url = validated.to_string();

    let bearer_present = bearer.is_some();
    let result = state
        .api_dast
        .scan(
            &user.claims.tenant_id,
            &collection,
            &base_url,
            bearer,
            probe_ids.clone(),
        )
        .await
        .map_err(map_api_dast)?;

    // Audit. Note: `bearer` itself is never logged — we surface only
    // a redacted boolean indicating its presence.
    tracing::info!(
        target: "audit",
        action = "discovery.dast.scan.completed",
        tenant_id = %user.claims.tenant_id,
        actor = %user.claims.sub,
        scan_id = %result.scan_id,
        collection = %result.collection_name,
        base_url = %result.base_url,
        bearer_present = bearer_present,
        idor_probe_count = probe_ids.len(),
        requests_sent = result.requests_sent,
        finding_count = result.findings.len(),
        "discovery.dast.scan.completed",
    );

    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok(ApiDastScanResponse { result })),
    ))
}

/// Query string for `GET /v1/discovery/dast/scans`.
#[derive(Debug, Clone, Deserialize)]
pub struct ListScansQuery {
    /// Maximum number of entries returned. Defaults to 50, capped at 200.
    pub limit: Option<u32>,
}

/// `GET /v1/discovery/dast/scans?limit=…` — newest-first list of
/// previously persisted scans for the caller's tenant.
pub async fn list(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Query(q): Query<ListScansQuery>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `scan:read`.
    require_permission(&user, "scan:read")?;
    let limit = q.limit.unwrap_or(50).clamp(1, 200) as usize;
    let items = state
        .api_dast
        .list(&user.claims.tenant_id, limit)
        .await
        .map_err(map_api_dast)?;
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok(ApiDastListResponse { items })),
    ))
}

/// Wildcard-aware permission gate (local copy — each controller owns its
/// own so the authorization decision stays beside the handler it guards).
/// A grant of `*` on either the resource or the action segment matches.
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

/// Translate [`ApiDastPortError`] onto the API error envelope.
pub fn map_api_dast(err: ApiDastPortError) -> ApiError {
    match err {
        ApiDastPortError::Invalid(m) => ApiError::Unprocessable(m),
        ApiDastPortError::Dependency(m) => ApiError::Dependency(m),
        ApiDastPortError::Internal(m) => ApiError::Internal(m),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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
    fn exact_permission_is_allowed() {
        assert!(require_permission(&user(vec!["scan:write"]), "scan:write").is_ok());
        assert!(require_permission(&user(vec!["scan:read"]), "scan:read").is_ok());
    }

    #[test]
    fn wildcard_permission_is_allowed() {
        assert!(require_permission(&user(vec!["scan:*"]), "scan:write").is_ok());
        assert!(require_permission(&user(vec!["*:*"]), "scan:read").is_ok());
    }

    #[test]
    fn missing_permission_is_denied() {
        let err = require_permission(&user(vec!["finding:read"]), "scan:write").unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }

    #[test]
    fn map_invalid_is_unprocessable() {
        let err = map_api_dast(ApiDastPortError::Invalid("bad".into()));
        assert!(matches!(err, ApiError::Unprocessable(_)));
    }

    #[test]
    fn map_dependency_is_dependency() {
        let err = map_api_dast(ApiDastPortError::Dependency("dns".into()));
        assert!(matches!(err, ApiError::Dependency(_)));
    }

    #[test]
    fn map_internal_is_internal() {
        let err = map_api_dast(ApiDastPortError::Internal("oops".into()));
        assert!(matches!(err, ApiError::Internal(_)));
    }

    #[test]
    fn max_collection_bytes_sane() {
        assert_eq!(MAX_COLLECTION_BYTES, 16 * 1024 * 1024);
    }
}
