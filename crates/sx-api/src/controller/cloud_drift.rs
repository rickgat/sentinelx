//! Cloud-drift controllers (P2-004).
//!
//! Four endpoints back the dashboard's "what changed since IaC?" view:
//!
//! | Method | Path                              | RBAC              |
//! | ------ | --------------------------------- | ----------------- |
//! | POST   | `/v1/cloud/drift/baselines`       | `cloud:inventory` |
//! | GET    | `/v1/cloud/drift/baselines`       | `cloud:inventory` |
//! | POST   | `/v1/cloud/drift/scan`            | `cloud:inventory` |
//! | GET    | `/v1/cloud/drift/findings`        | `cloud:inventory` |
//!
//! Every handler is intentionally thin. It:
//!
//! 1. Validates the body via `validator` (when applicable).
//! 2. Enforces the `cloud:inventory` permission (wildcards honoured).
//! 3. Derives the tenant from the bearer claims via [`TenantScope`] —
//!    the body never carries a tenant id, so a client cannot ask for
//!    another tenant's baselines or drift findings.
//! 4. For uploads: decodes the base64 payload and enforces
//!    [`BASELINE_MAX_DECODED_BYTES`].
//! 5. Forwards to the [`CloudDriftPort`] trait object.
//! 6. Emits a `tracing::info!` audit line so the structured log shipper
//!    picks the event up.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::Deserialize;
use sx_iam::domain::Permission;
use tracing::info;

use crate::controller::map_cloud_drift;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::extractor::tenant::TenantScope;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::cloud_drift_view::{
    DriftListResponse, DriftScanRequest, DriftScanResponse, ListBaselinesResponse,
    UploadBaselineRequest, UploadBaselineResponse, BASELINE_MAX_DECODED_BYTES,
};
use crate::view::envelope::ApiResponse;

/// Hard upper bound the controller enforces on the `?asset=` filter
/// substring so a misbehaving client can't blow up the query.
const MAX_ASSET_FILTER_LEN: usize = 512;

/// `POST /v1/cloud/drift/baselines` — store an IaC baseline document
/// (Terraform JSON or CloudFormation YAML).
pub async fn upload_baseline(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    ValidatedJson(req): ValidatedJson<UploadBaselineRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "cloud:inventory")?;

    // Decode the base64 payload at the controller boundary so the adapter
    // only sees raw bytes — and so we can enforce the decoded-length cap
    // (`validator` only sees the encoded string length).
    let decoded = BASE64
        .decode(req.payload.as_bytes())
        .map_err(|e| ApiError::Unprocessable(format!("payload is not valid base64: {e}")))?;
    if decoded.len() > BASELINE_MAX_DECODED_BYTES {
        return Err(ApiError::Unprocessable(format!(
            "decoded payload exceeds {BASELINE_MAX_DECODED_BYTES} bytes"
        )));
    }

    let resp: UploadBaselineResponse = state
        .cloud_drift
        .upload_baseline(&scope.tenant_id, &req.name, &req.format, decoded)
        .await
        .map_err(map_cloud_drift)?;

    // Audit trail. Structured fields so downstream log shippers
    // (Loki / CloudWatch) can index by tenant and action without parsing
    // the message string.
    info!(
        target: "audit.cloud_drift",
        tenant_id = %scope.tenant_id,
        actor = %user.claims.sub,
        action = "cloud_drift.upload_baseline",
        baseline_id = %resp.id,
        baseline_name = %resp.name,
        format = %resp.format,
        resource_count = resp.resource_count,
        "uploaded cloud-drift baseline",
    );

    Ok((StatusCode::CREATED, Json(ApiResponse::ok(resp))))
}

/// `GET /v1/cloud/drift/baselines` — list baselines available to the
/// caller's tenant.
pub async fn list_baselines(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
) -> Result<Json<ApiResponse<ListBaselinesResponse>>, ApiError> {
    require_permission(&user, "cloud:inventory")?;
    let resp = state
        .cloud_drift
        .list_baselines(&scope.tenant_id)
        .await
        .map_err(map_cloud_drift)?;
    Ok(Json(ApiResponse::ok(resp)))
}

/// `POST /v1/cloud/drift/scan` — diff the live cloud inventory against
/// the supplied (or most recent) baseline. Persists the resulting
/// entries so they show up on `GET /v1/cloud/drift/findings`.
pub async fn scan(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    ValidatedJson(req): ValidatedJson<DriftScanRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "cloud:inventory")?;

    let resp: DriftScanResponse = state
        .cloud_drift
        .scan(
            &scope.tenant_id,
            &req.engagement_id,
            req.baseline_id.as_deref(),
        )
        .await
        .map_err(map_cloud_drift)?;

    info!(
        target: "audit.cloud_drift",
        tenant_id = %scope.tenant_id,
        actor = %user.claims.sub,
        action = "cloud_drift.scan",
        engagement_id = %req.engagement_id,
        baseline_id = %resp.baseline_id,
        entries = resp.entries.len(),
        "executed cloud-drift scan",
    );

    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

/// `GET /v1/cloud/drift/findings?asset=<substring>` — read drift entries
/// previously detected for the caller's tenant.
pub async fn list_findings(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    scope: TenantScope,
    Query(q): Query<DriftListQuery>,
) -> Result<Json<ApiResponse<DriftListResponse>>, ApiError> {
    require_permission(&user, "cloud:inventory")?;

    if let Some(ref needle) = q.asset {
        if needle.len() > MAX_ASSET_FILTER_LEN {
            return Err(ApiError::Unprocessable(format!(
                "asset filter exceeds {MAX_ASSET_FILTER_LEN} chars"
            )));
        }
    }

    let resp = state
        .cloud_drift
        .list_drift(&scope.tenant_id, q.asset.as_deref())
        .await
        .map_err(map_cloud_drift)?;
    Ok(Json(ApiResponse::ok(resp)))
}

/// Query parameters for [`list_findings`].
#[derive(Debug, Clone, Deserialize, Default)]
pub struct DriftListQuery {
    /// Optional substring matched against `resource_id`.
    #[serde(default)]
    pub asset: Option<String>,
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
    fn upload_requires_cloud_inventory_permission() {
        let u = user(vec!["findings:read"]);
        assert!(matches!(
            require_permission(&u, "cloud:inventory"),
            Err(ApiError::Forbidden)
        ));
    }

    #[test]
    fn upload_allowed_with_cloud_inventory_permission() {
        let u = user(vec!["cloud:inventory"]);
        assert!(require_permission(&u, "cloud:inventory").is_ok());
    }

    #[test]
    fn wildcard_action_permits_drift_endpoints() {
        let u = user(vec!["cloud:*"]);
        assert!(require_permission(&u, "cloud:inventory").is_ok());
    }
}
