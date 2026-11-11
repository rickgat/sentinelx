//! Runtime-security controller — Falco webhook ingestion.
//!
//! Single route:
//!
//! - `POST /v1/runtime/falco/alerts` — accept one Falco alert (or an
//!   array of alerts in a batch) signed by a per-tenant HMAC key.
//!
//! Authentication is **not** the bearer-token middleware; the request is
//! self-authenticating via HMAC-SHA256 over `v1:{timestamp}:{body}`.
//! The route is therefore listed in the auth middleware's bypass set and
//! the per-tenant key is resolved through [`sx_runtime`].
//!
//! The handler delegates the heavy lifting (HMAC verify, OCSF normalise,
//! finding emission, audit) to [`sx_runtime::FalcoIngestService`]; it is
//! intentionally a thin shim that translates HTTP into the service call
//! and the service's `RuntimeError` into [`ApiError`].

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use serde::Serialize;
use sx_iam::domain::Permission;
use sx_runtime::auth::{SIGNATURE_HEADER, TENANT_HEADER, TIMESTAMP_HEADER};
use sx_runtime::{IngestionReport, RuntimeError, RuntimeFinding};
use time::OffsetDateTime;

use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::RuntimeOverridesPortError;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::runtime_view::{DeleteFalcoOverrideRequest, PutFalcoOverrideRequest};

/// Response body returned on `200 OK` from the runtime webhook.
#[derive(Debug, Serialize)]
pub struct RuntimeIngestResponse {
    /// Total number of alerts the batch carried.
    pub alert_count: usize,
    /// Number of alerts that produced a finding.
    pub accepted: usize,
    /// Findings emitted — mirrored back to the caller so a sidecar can
    /// surface them without re-querying the SOC pipeline.
    pub findings: Vec<RuntimeFinding>,
}

impl From<IngestionReport> for RuntimeIngestResponse {
    fn from(report: IngestionReport) -> Self {
        Self {
            alert_count: report.alert_count,
            accepted: report.accepted,
            findings: report.findings,
        }
    }
}

/// `POST /v1/runtime/falco/alerts` — accept one Falco alert (single
/// object) or an array of alerts (falcosidekick batched delivery).
///
/// The tenant id, timestamp, and signature travel in non-sensitive
/// headers (`X-Sentinelx-Tenant`, `X-Sentinelx-Runtime-Timestamp`,
/// `X-Sentinelx-Runtime-Signature`); the body is forwarded verbatim to
/// the HMAC verifier — the caller must not mutate it.
pub async fn ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    let tenant_id = headers
        .get(TENANT_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .ok_or(ApiError::Unauthorized)?
        .to_owned();
    let timestamp = headers
        .get(TIMESTAMP_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or(ApiError::Unauthorized)?;
    let signature = headers
        .get(SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let now = OffsetDateTime::now_utc().unix_timestamp();

    let report = state
        .runtime_falco
        .ingest(&tenant_id, timestamp, signature.as_deref(), &body, now)
        .await
        .map_err(map_runtime_error)?;

    Ok(Json(ApiResponse::ok(RuntimeIngestResponse::from(report))))
}

/// Translate a [`RuntimeError`] from the ingestion service into the
/// nearest [`ApiError`]. The mapping deliberately collapses all auth
/// failures to `401 Unauthorized` so the response never discriminates
/// between *unknown tenant* and *bad signature* — that would otherwise
/// give an attacker an oracle for tenant enumeration.
fn map_runtime_error(err: RuntimeError) -> ApiError {
    match err {
        RuntimeError::BadPayload => ApiError::BadRequest("malformed payload".to_owned()),
        RuntimeError::InvalidSignature
        | RuntimeError::ReplayWindowExceeded
        | RuntimeError::UnknownTenant => ApiError::Unauthorized,
        RuntimeError::Audit(m) => ApiError::Internal(format!("runtime audit: {m}")),
        RuntimeError::Internal(m) => ApiError::Internal(m),
    }
}

// ---------------------------------------------------------------------------
// HIGH-006 — Falco rule override admin endpoints
// ---------------------------------------------------------------------------

/// `GET /v1/admin/runtime/falco/overrides` — list every override row
/// for the caller's tenant. Requires `runtime:read`.
pub async fn list_falco_overrides(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "runtime:read")?;
    tracing::info!(
        target: "controller.runtime.falco_overrides.list",
        tenant_id = %user.claims.tenant_id,
        "falco override list requested",
    );
    let resp = state
        .runtime_falco_overrides
        .list(&user.claims.tenant_id)
        .await
        .map_err(map_runtime_overrides_error)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

/// `PUT /v1/admin/runtime/falco/overrides` — upsert one row keyed by
/// `(rule_name, subkey)`. Requires `runtime:write`. The adapter
/// records an audit row for every mutation.
pub async fn put_falco_override(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<PutFalcoOverrideRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "runtime:write")?;
    tracing::info!(
        target: "controller.runtime.falco_overrides.put",
        tenant_id = %user.claims.tenant_id,
        user_id = %user.claims.sub,
        rule_name = %req.rule_name,
        subkey = %req.subkey,
        action = %req.action,
        "falco override upsert requested",
    );
    let resp = state
        .runtime_falco_overrides
        .upsert(&user.claims.tenant_id, &user.claims.sub, req)
        .await
        .map_err(map_runtime_overrides_error)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

/// `DELETE /v1/admin/runtime/falco/overrides` — delete one row.
///
/// The key travels in the JSON body because the wildcard subkey `"*"`
/// does not round-trip cleanly through a URL path component in every
/// proxy. Requires `runtime:write`. Idempotent: returns `removed:
/// false` when the row was absent.
pub async fn delete_falco_override(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<DeleteFalcoOverrideRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "runtime:write")?;
    tracing::info!(
        target: "controller.runtime.falco_overrides.delete",
        tenant_id = %user.claims.tenant_id,
        user_id = %user.claims.sub,
        rule_name = %req.rule_name,
        subkey = %req.subkey,
        "falco override delete requested",
    );
    let resp = state
        .runtime_falco_overrides
        .delete(&user.claims.tenant_id, &user.claims.sub, req)
        .await
        .map_err(map_runtime_overrides_error)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

/// Translate a [`RuntimeOverridesPortError`] into the matching
/// [`ApiError`]. `Invalid` is `422` (validator passed but semantics
/// rejected), `Dependency` is `503`, and `Internal` is `500`.
pub fn map_runtime_overrides_error(err: RuntimeOverridesPortError) -> ApiError {
    match err {
        RuntimeOverridesPortError::Invalid(m) => ApiError::Unprocessable(m),
        RuntimeOverridesPortError::Dependency(m) => ApiError::Dependency(m),
        RuntimeOverridesPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// Enforce a single `resource:action` permission with wildcard support.
///
/// Mirrors the helper in `controller::webauthn` — local copy avoids a
/// pub-cross-module dependency. Any future refactor moving this to a
/// shared util would consolidate both.
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

    #[test]
    fn unknown_tenant_collapses_to_unauthorized() {
        let mapped = map_runtime_error(RuntimeError::UnknownTenant);
        assert!(matches!(mapped, ApiError::Unauthorized));
    }

    #[test]
    fn bad_signature_collapses_to_unauthorized() {
        let mapped = map_runtime_error(RuntimeError::InvalidSignature);
        assert!(matches!(mapped, ApiError::Unauthorized));
    }

    #[test]
    fn replay_window_collapses_to_unauthorized() {
        let mapped = map_runtime_error(RuntimeError::ReplayWindowExceeded);
        assert!(matches!(mapped, ApiError::Unauthorized));
    }

    #[test]
    fn bad_payload_maps_to_bad_request() {
        let mapped = map_runtime_error(RuntimeError::BadPayload);
        assert!(matches!(mapped, ApiError::BadRequest(_)));
    }

    #[test]
    fn audit_failure_maps_to_internal() {
        let mapped = map_runtime_error(RuntimeError::Audit("boom".into()));
        assert!(matches!(mapped, ApiError::Internal(_)));
    }

    #[test]
    fn internal_passes_through_as_internal() {
        let mapped = map_runtime_error(RuntimeError::Internal("boom".into()));
        assert!(matches!(mapped, ApiError::Internal(_)));
    }

    // HIGH-006 — admin endpoint mapping + permission tests.

    #[test]
    fn overrides_invalid_maps_to_unprocessable() {
        let mapped = map_runtime_overrides_error(RuntimeOverridesPortError::Invalid(
            "unknown action".into(),
        ));
        assert!(matches!(mapped, ApiError::Unprocessable(_)));
    }

    #[test]
    fn overrides_dependency_maps_to_dependency() {
        let mapped =
            map_runtime_overrides_error(RuntimeOverridesPortError::Dependency("pg down".into()));
        assert!(matches!(mapped, ApiError::Dependency(_)));
    }

    #[test]
    fn overrides_internal_maps_to_internal() {
        let mapped =
            map_runtime_overrides_error(RuntimeOverridesPortError::Internal("boom".into()));
        assert!(matches!(mapped, ApiError::Internal(_)));
    }

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
    fn require_permission_runtime_read_allows_exact() {
        let u = user(vec!["runtime:read"]);
        assert!(require_permission(&u, "runtime:read").is_ok());
    }

    #[test]
    fn require_permission_runtime_admin_wildcard_allows() {
        let u = user(vec!["runtime:*"]);
        assert!(require_permission(&u, "runtime:write").is_ok());
    }

    #[test]
    fn require_permission_denies_when_missing() {
        let u = user(vec!["webauthn:read"]);
        assert!(matches!(
            require_permission(&u, "runtime:read"),
            Err(ApiError::Forbidden)
        ));
    }
}
