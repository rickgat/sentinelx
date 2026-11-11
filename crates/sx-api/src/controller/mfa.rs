//! MFA controller — `POST /v1/mfa/enroll`, `POST /v1/mfa/verify`,
//! `POST /v1/mfa/disable`, `GET /v1/mfa/status`.
//!
//! Every endpoint is authenticated via the standard `AuthenticatedUser`
//! extractor; no additional RBAC permission is required because each
//! handler is scoped to **the caller's own** user id (`claims.sub`).
//!
//! ## Tracing
//!
//! - TOTP codes, recovery codes, and the shared secret are NEVER logged.
//!   Handlers emit only the user id + a one-word summary of the action.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

use crate::controller::map_iam;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::middleware::auth::AuthenticatedUser;
use crate::state::AppState;
use crate::view::envelope::ApiResponse;
use crate::view::mfa_view::{DisableRequest, VerifyRequest};

/// `POST /v1/mfa/enroll` — generate a TOTP secret + recovery codes.
///
/// The secret and recovery codes are returned **once**; afterwards the
/// server only retains the (hashed) recovery codes and the secret. The
/// account is not yet considered MFA-enrolled until the caller invokes
/// `verify` with a valid TOTP code (this confirms they have a working
/// authenticator app configured with the secret).
pub async fn enroll(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    tracing::info!(
        target: "controller.mfa.enroll",
        user_id = %user.claims.sub,
        "mfa enroll requested"
    );
    let resp = state.mfa.enroll(&user.claims.sub).await.map_err(map_iam)?;
    Ok((StatusCode::CREATED, Json(ApiResponse::ok(resp))))
}

/// `POST /v1/mfa/verify` — verify a TOTP or recovery code.
///
/// On the first successful verification the adapter promotes the user
/// to fully MFA-enrolled. Subsequent calls act as a step-up check the
/// rest of the platform can rely on.
pub async fn verify(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<VerifyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    tracing::debug!(
        target: "controller.mfa.verify",
        user_id = %user.claims.sub,
        "mfa verify requested"
    );
    state
        .mfa
        .verify(&user.claims.sub, &req.code)
        .await
        .map_err(map_iam)?;
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok(crate::view::mfa_view::MfaStatusView {
            enrolled: true,
            last_verified_at: None,
        })),
    ))
}

/// `POST /v1/mfa/disable` — remove MFA after proving possession.
///
/// Requires a currently-valid TOTP or recovery code; on success the
/// adapter wipes the secret + recovery codes for the caller.
pub async fn disable(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    ValidatedJson(req): ValidatedJson<DisableRequest>,
) -> Result<impl IntoResponse, ApiError> {
    tracing::info!(
        target: "controller.mfa.disable",
        user_id = %user.claims.sub,
        "mfa disable requested"
    );
    state
        .mfa
        .disable(&user.claims.sub, &req.code)
        .await
        .map_err(map_iam)?;
    Ok((
        StatusCode::OK,
        Json(ApiResponse::ok(crate::view::mfa_view::MfaStatusView {
            enrolled: false,
            last_verified_at: None,
        })),
    ))
}

/// `GET /v1/mfa/status` — report whether the caller has MFA enrolled.
pub async fn status(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<impl IntoResponse, ApiError> {
    let resp = state.mfa.status(&user.claims.sub).await.map_err(map_iam)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}
