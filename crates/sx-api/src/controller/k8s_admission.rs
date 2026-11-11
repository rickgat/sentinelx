//! HIGH-009 — Kubernetes admission webhook controller.
//!
//! Single endpoint: `POST /v1/runtime/k8s/admit` accepts an
//! `admission.k8s.io/v1` [`AdmissionReview`] envelope from the cluster
//! apiserver, dispatches to [`crate::port::K8sAdmissionPort::admit`],
//! and returns the response envelope verbatim. The route is bypassed
//! in [`crate::middleware::auth`] because the apiserver authenticates
//! itself via the mutual-TLS the cluster admin wires up at install
//! time (the `ValidatingWebhookConfiguration` references the cluster
//! CA bundle injected by cert-manager — see `deploy/helm/sx-admission`).
//!
//! Tenant resolution is via the `X-Sentinelx-Tenant` header. The
//! Helm-installed `MutatingWebhookConfiguration` is responsible for
//! adding that header from the cluster's labels; tests use a small
//! integration fixture that sets it directly.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use sx_discovery::k8s_admission::AdmissionReview;
use sx_iam::domain::Permission;

use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::K8sAdmissionPortError;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::k8s_admission_view::K8sAdmissionPolicyView;

/// Header carrying the resolved tenant id. Set by the in-cluster
/// `MutatingWebhookConfiguration` (or by the test fixture directly).
pub const TENANT_HEADER: &str = "X-Sentinelx-Tenant";

/// `POST /v1/runtime/k8s/admit` — apiserver-facing admission entry
/// point.
///
/// The handler is intentionally a thin shim:
///
/// 1. Read tenant id from `X-Sentinelx-Tenant`.
/// 2. Pass the parsed `AdmissionReview` body to the port.
/// 3. Return the response envelope as JSON.
///
/// Error handling: a `K8sAdmissionPortError::Invalid` surfaces as
/// 422; an `Internal` surfaces as 500 — the apiserver retries on 5xx
/// per its configured `failurePolicy`. Operators who want hard "fail
/// open" should set `failurePolicy: Ignore` in the Helm chart.
pub async fn admit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(review): Json<AdmissionReview>,
) -> Result<Json<AdmissionReview>, ApiError> {
    let tenant_id = headers
        .get(TENANT_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| ApiError::BadRequest(format!("missing required header {TENANT_HEADER}")))?
        .to_owned();

    let response = state
        .k8s_admission
        .admit(&tenant_id, review)
        .await
        .map_err(map_k8s_admission)?;
    Ok(Json(response))
}

/// `GET /v1/admin/runtime/k8s/policies` — return the calling tenant's
/// active admission policy. Requires `runtime:read`.
pub async fn get_policy(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "runtime:read")?;
    let policy = state
        .k8s_admission
        .get_policy(&user.claims.tenant_id)
        .await
        .map_err(map_k8s_admission)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(policy))))
}

/// `PUT /v1/admin/runtime/k8s/policies` — replace the policy.
///
/// Replaces the calling tenant's admission policy. Requires
/// `runtime:write`. Persisted durably when a database is wired, and
/// applied to the live admission engine at once.
pub async fn put_policy(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<K8sAdmissionPolicyView>,
) -> Result<impl IntoResponse, ApiError> {
    require_permission(&user, "runtime:write")?;
    tracing::info!(
        target: "controller.k8s_admission.set_policy",
        tenant_id = %user.claims.tenant_id,
        user_id = %user.claims.sub,
        pss_profile = ?req.pss_profile,
        dry_run = req.dry_run,
        "k8s admission policy upsert requested",
    );
    let policy = state
        .k8s_admission
        .set_policy(&user.claims.tenant_id, req)
        .await
        .map_err(map_k8s_admission)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(policy))))
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

/// Translate a [`K8sAdmissionPortError`] into the nearest [`ApiError`].
pub fn map_k8s_admission(err: K8sAdmissionPortError) -> ApiError {
    match err {
        K8sAdmissionPortError::Invalid(m) => ApiError::Unprocessable(m),
        K8sAdmissionPortError::Internal(m) => ApiError::Internal(m),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_maps_to_unprocessable() {
        let mapped = map_k8s_admission(K8sAdmissionPortError::Invalid("bad".into()));
        assert!(matches!(mapped, ApiError::Unprocessable(_)));
    }

    #[test]
    fn internal_maps_to_internal() {
        let mapped = map_k8s_admission(K8sAdmissionPortError::Internal("boom".into()));
        assert!(matches!(mapped, ApiError::Internal(_)));
    }
}
