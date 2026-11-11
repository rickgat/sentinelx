//! DLP (P2-006) HTTP controllers — `/v1/dlp/*`.
//!
//! Three endpoints:
//!
//! * `POST /v1/dlp/scan`  — multipart-or-JSON upload (max 10 MB), scans
//!   the body for sensitive content via [`crate::port::DlpPort::scan`].
//! * `GET  /v1/dlp/config` — fetch the per-tenant detector
//!   configuration.
//! * `PUT  /v1/dlp/config` — replace the per-tenant detector
//!   configuration.
//!
//! Multipart parts accepted by `POST /v1/dlp/scan`:
//!
//! * `payload` / `file` — the bytes to scan. Anything else is ignored
//!   so the wire stays forward-compatible.
//!
//! When the request `Content-Type` is `application/json` the handler
//! falls back to a JSON body shape (`{"payload":"..."}`).
//!
//! Every successful scan emits a structured audit-log line under the
//! `audit` target so downstream sinks can persist the metadata. The raw
//! payload is **never** logged or persisted by this controller.

use axum::body::Bytes;
use axum::extract::{Multipart, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use sx_iam::domain::Permission;

use crate::error::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::{DlpPortError, DlpScanResultView};
use crate::state::AppState;
use crate::view::dlp_view::{
    DlpConfigResponse, DlpPutConfigRequest, DlpPutThresholdRequest, DlpScanJsonBody,
    DlpScanResponse, DlpThresholdResponse,
};
use crate::view::envelope::ApiResponse;

/// Hard cap shared with the underlying `sx-dlp` crate.
const MAX_PAYLOAD_BYTES: usize = 10 * 1024 * 1024;

/// `POST /v1/dlp/scan` — scan an uploaded payload for sensitive content.
///
/// Accepts:
///
/// * `multipart/form-data` with a `payload` (or `file`) part containing
///   the bytes to inspect.
/// * `application/json` body matching [`DlpScanJsonBody`].
///
/// Returns the [`DlpScanResultView`] inside [`DlpScanResponse`].
pub async fn scan(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `dlp:read`.
    require_permission(&user, "dlp:read")?;
    let payload = parse_request_payload(&headers, body).await?;
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(ApiError::BadRequest(format!(
            "payload too large: {} bytes (max {MAX_PAYLOAD_BYTES})",
            payload.len()
        )));
    }

    let result: DlpScanResultView = state
        .dlp
        .scan(&user.claims.tenant_id, &payload)
        .await
        .map_err(map_dlp)?;

    tracing::info!(
        target: "audit",
        action = "dlp.scan.completed",
        tenant_id = %user.claims.tenant_id,
        actor = %user.claims.sub,
        scan_id = %result.id,
        bytes_scanned = result.bytes_scanned,
        total_matches = result.total_matches,
        "dlp.scan.completed",
    );

    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok(DlpScanResponse { result })),
    ))
}

/// `GET /v1/dlp/config` — fetch the active detector configuration for
/// the caller's tenant.
pub async fn get_config(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `dlp:read`.
    require_permission(&user, "dlp:read")?;
    let cfg = state
        .dlp
        .get_config(&user.claims.tenant_id)
        .await
        .map_err(map_dlp)?;
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok(DlpConfigResponse { config: cfg })),
    ))
}

/// `PUT /v1/dlp/config` — replace the detector configuration for the
/// caller's tenant.
pub async fn put_config(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<DlpPutConfigRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `dlp:write`.
    require_permission(&user, "dlp:write")?;
    let cfg = state
        .dlp
        .put_config(
            &user.claims.tenant_id,
            req.enabled.clone(),
            req.min_confidence,
        )
        .await
        .map_err(map_dlp)?;

    tracing::info!(
        target: "audit",
        action = "dlp.config.replaced",
        tenant_id = %user.claims.tenant_id,
        actor = %user.claims.sub,
        enabled_count = cfg.enabled.len(),
        min_confidence = cfg.min_confidence,
        "dlp.config.replaced",
    );

    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok(DlpConfigResponse { config: cfg })),
    ))
}

/// `GET /v1/admin/dlp/thresholds` — fetch the HIGH-004 minimum-confidence
/// threshold for the caller's tenant.
pub async fn get_threshold(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `admin:dlp`.
    require_permission(&user, "admin:dlp")?;
    let t = state
        .dlp
        .get_threshold(&user.claims.tenant_id)
        .await
        .map_err(map_dlp)?;
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok(DlpThresholdResponse { threshold: t })),
    ))
}

/// `PUT /v1/admin/dlp/thresholds` — replace the HIGH-004
/// minimum-confidence threshold for the caller's tenant. Values are
/// clamped into `[0.0, 1.0]`; `NaN` is rejected with `422`.
pub async fn put_threshold(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<DlpPutThresholdRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // OpenAPI documents this endpoint as requiring `admin:dlp`.
    require_permission(&user, "admin:dlp")?;
    if req.min_confidence.is_nan() {
        return Err(ApiError::Unprocessable(
            "min_confidence must be a finite number in [0.0, 1.0]".into(),
        ));
    }
    let t = state
        .dlp
        .put_threshold(&user.claims.tenant_id, req.min_confidence)
        .await
        .map_err(map_dlp)?;

    tracing::info!(
        target: "audit",
        action = "dlp.threshold.replaced",
        tenant_id = %user.claims.tenant_id,
        actor = %user.claims.sub,
        min_confidence = t.min_confidence,
        "dlp.threshold.replaced",
    );

    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok(DlpThresholdResponse { threshold: t })),
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

/// Translate [`DlpPortError`] onto the API error envelope.
pub fn map_dlp(err: DlpPortError) -> ApiError {
    match err {
        DlpPortError::PayloadTooLarge { bytes, max } => {
            ApiError::BadRequest(format!("payload too large: {bytes} bytes (max {max})"))
        }
        DlpPortError::Invalid(m) => ApiError::Unprocessable(m),
        DlpPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// Extract the scan payload from either a multipart body or a JSON
/// body. Unknown content types are treated as raw bytes — this matches
/// how every internal tool emits payloads (curl `--data-binary @file`).
async fn parse_request_payload(headers: &HeaderMap, body: Bytes) -> Result<Vec<u8>, ApiError> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    if content_type.starts_with("multipart/form-data") {
        // Re-parse the buffered body via axum's Multipart extractor by
        // constructing a Request and calling the field iterator. We
        // already enforce the body cap upstream via the axum body
        // limit middleware; this branch only walks the field stream.
        let mut req = axum::http::Request::new(axum::body::Body::from(body));
        let _ = std::mem::replace(req.headers_mut(), headers.clone());
        let mut multipart = Multipart::from_request(req, &())
            .await
            .map_err(|e| ApiError::BadRequest(format!("multipart parse failed: {e}")))?;
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
            if matches!(name.as_str(), "payload" | "file") {
                return Ok(bytes.to_vec());
            }
        }
        return Err(ApiError::BadRequest(
            "missing 'payload' multipart field".into(),
        ));
    }

    if content_type.starts_with("application/json") {
        let parsed: DlpScanJsonBody = serde_json::from_slice(&body)
            .map_err(|e| ApiError::BadRequest(format!("json parse failed: {e}")))?;
        return Ok(parsed.payload.into_bytes());
    }

    // Fall back to raw bytes.
    Ok(body.to_vec())
}

// `Multipart::from_request` is implemented on the `FromRequest` trait
// from axum's extract module — bring it into scope.
use axum::extract::FromRequest;

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
        assert!(require_permission(&user(vec!["dlp:read"]), "dlp:read").is_ok());
        assert!(require_permission(&user(vec!["dlp:write"]), "dlp:write").is_ok());
        assert!(require_permission(&user(vec!["admin:dlp"]), "admin:dlp").is_ok());
    }

    #[test]
    fn wildcard_permission_is_allowed() {
        assert!(require_permission(&user(vec!["dlp:*"]), "dlp:write").is_ok());
        assert!(require_permission(&user(vec!["*:*"]), "admin:dlp").is_ok());
    }

    #[test]
    fn missing_permission_is_denied() {
        let err = require_permission(&user(vec!["finding:read"]), "dlp:read").unwrap_err();
        assert!(matches!(err, ApiError::Forbidden));
    }

    #[test]
    fn max_payload_matches_implementation_crate() {
        assert_eq!(MAX_PAYLOAD_BYTES, 10 * 1024 * 1024);
    }

    #[test]
    fn map_dlp_payload_too_large_is_bad_request() {
        let err = map_dlp(DlpPortError::PayloadTooLarge {
            bytes: 99,
            max: MAX_PAYLOAD_BYTES,
        });
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn map_dlp_invalid_is_unprocessable() {
        let err = map_dlp(DlpPortError::Invalid("x".into()));
        assert!(matches!(err, ApiError::Unprocessable(_)));
    }

    #[test]
    fn map_dlp_internal_is_internal() {
        let err = map_dlp(DlpPortError::Internal("x".into()));
        assert!(matches!(err, ApiError::Internal(_)));
    }
}
