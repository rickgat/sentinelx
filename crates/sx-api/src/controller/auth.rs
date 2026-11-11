//! Authentication controllers — login, refresh, logout.

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;

use crate::controller::{map_iam, map_phase3};
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::AuthenticateUserInput;
use crate::state::AppState;
use crate::view::auth_view::{LoginView, LogoutView, OidcExchangeRequest, RefreshView, TokenView};
use crate::view::envelope::ApiResponse;

/// `POST /v1/auth/login`
///
/// The login flow:
/// 1. Validates the body shape (handled by [`ValidatedJson`]).
/// 2. Calls [`AuthenticateUserPort::authenticate`], which:
///    * verifies the password,
///    * delegates to the RBA engine for a risk score / action,
///    * issues a JWT IFF the action is `Allow`.
/// 3. Step-up / block outcomes surface as `IamError::Forbidden` and
///    are translated to HTTP `403` with the wire reason
///    `rba_step_up_mfa_required` or `rba_block` so the dashboard can
///    branch to an MFA prompt or surface a hard block.
pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(req): ValidatedJson<LoginView>,
) -> Result<impl IntoResponse, ApiError> {
    let input = AuthenticateUserInput {
        tenant_id: req.tenant_id.clone(),
        email: req.email.clone(),
        password: req.password,
        ip: extract_client_ip(&headers),
        user_agent: extract_user_agent(&headers),
    };
    let token: TokenView = state.authn.authenticate(input).await.map_err(map_iam)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(token))))
}

/// Pull the first non-empty hop of `X-Forwarded-For`, falling back to
/// `X-Real-IP`. Returns `None` when neither header is set or both are
/// empty.
fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let first = v.split(',').next().unwrap_or("").trim();
        if !first.is_empty() {
            return Some(first.to_owned());
        }
    }
    if let Some(v) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        let v = v.trim();
        if !v.is_empty() {
            return Some(v.to_owned());
        }
    }
    None
}

/// Pull `User-Agent`. Returns `None` when absent or unparseable.
fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(std::borrow::ToOwned::to_owned)
}

/// `POST /v1/auth/refresh`
pub async fn refresh(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<RefreshView>,
) -> Result<impl IntoResponse, ApiError> {
    let token = state
        .refresh
        .refresh(&req.refresh_token)
        .await
        .map_err(map_iam)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(token))))
}

/// `POST /v1/auth/oidc/exchange`
///
/// Validate an OIDC `id_token` against the configured IdP and issue an
/// SX-internal access + refresh token pair for the underlying user.
///
/// Error mapping:
/// * Invalid body → `400 Bad Request`.
/// * `Phase3PortError::Invalid("OIDC disabled")` (when the deployment has
///   not enabled OIDC) → mapped via [`map_phase3`] to `422 Unprocessable`.
/// * `Phase3PortError::Forbidden(_)` (token rejected by the verifier) →
///   mapped via [`map_phase3`] to `403`.
pub async fn exchange_oidc(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<OidcExchangeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let token = state
        .oidc_exchange
        .exchange(req)
        .await
        .map_err(map_phase3)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(token))))
}

/// `POST /v1/auth/logout`
pub async fn logout(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(_req): ValidatedJson<LogoutView>,
) -> Result<impl IntoResponse, ApiError> {
    state
        .logout
        .revoke(&user.claims.jti)
        .await
        .map_err(map_iam)?;
    Ok(StatusCode::NO_CONTENT)
}
