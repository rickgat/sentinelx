//! Customer-facing authentication controllers — signup, email
//! verification, forgot-password, reset-password.
//!
//! Every handler in this module is **public** (no `AuthenticatedUser`
//! extractor). The public router applies the same `rate_limit_middleware`
//! used by `/v1/auth/login`, so abuse mitigation is shared with the rest
//! of the auth surface.
//!
//! ## Tracing
//!
//! Handlers log only the tenant id + (lower-cased) email. Plaintext
//! passwords are wrapped in `SecretString` from the moment they leave the
//! JSON parser, and reset / verification tokens are NEVER logged — the
//! controller propagates them to the port unchanged and emits a generic
//! redacted marker if it traces anything at all.
//!
//! ## Status codes
//!
//! - `signup`           → `201 Created` (a new user resource was minted).
//! - `verify_email`     → `200 OK`.
//! - `forgot_password`  → `200 OK` (always — even on unknown email).
//! - `reset_password`   → `200 OK`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;

use crate::controller::map_phase3;
use crate::error::ApiError;
use crate::extractor::json::ValidatedJson;
use crate::state::AppState;
use crate::view::customer_auth_view::{
    ForgotPasswordRequest, ResetPasswordRequest, SignupRequest, VerifyEmailRequest,
};
use crate::view::envelope::ApiResponse;

/// `POST /v1/auth/signup` — create a new inactive customer-facing user.
///
/// The adapter mints a verification token and (in production) emails it
/// to the user. In dev the token is logged at INFO with a `token_id`
/// marker — never the token value itself.
pub async fn signup(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<SignupRequest>,
) -> Result<impl IntoResponse, ApiError> {
    // The `serde(deserialize_with)` annotation on the password bypasses
    // the derive's `#[validate]`. Enforce the length policy explicitly so
    // the controller never hands a 0-length plaintext to the hasher.
    if req.validate_password().is_err() {
        return Err(ApiError::Unprocessable(
            "password must be 8..=200 characters".into(),
        ));
    }
    tracing::debug!(
        target: "controller.customer_auth.signup",
        tenant_id = %req.tenant_id,
        email = %req.email,
        "customer signup request"
    );
    let resp = state.customer_auth.signup(req).await.map_err(map_phase3)?;
    Ok((StatusCode::CREATED, Json(ApiResponse::ok(resp))))
}

/// `POST /v1/auth/verify-email` — exchange a verification token for
/// account activation.
///
/// The token value is intentionally never logged.
pub async fn verify_email(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<VerifyEmailRequest>,
) -> Result<impl IntoResponse, ApiError> {
    tracing::debug!(
        target: "controller.customer_auth.verify_email",
        "verify-email request received"
    );
    let resp = state
        .customer_auth
        .verify_email(req)
        .await
        .map_err(map_phase3)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

/// `POST /v1/auth/forgot-password` — mint a reset token (always `Ok`).
///
/// The response is identical regardless of whether the email exists, so
/// callers cannot probe account presence.
pub async fn forgot_password(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<ForgotPasswordRequest>,
) -> Result<impl IntoResponse, ApiError> {
    tracing::debug!(
        target: "controller.customer_auth.forgot_password",
        tenant_id = %req.tenant_id,
        email = %req.email,
        "forgot-password request"
    );
    let resp = state
        .customer_auth
        .forgot_password(req)
        .await
        .map_err(map_phase3)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}

/// `POST /v1/auth/reset-password` — rotate the password hash if the
/// supplied token is valid.
///
/// Neither the token nor the new password are logged.
pub async fn reset_password(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<ResetPasswordRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if req.validate_password().is_err() {
        return Err(ApiError::Unprocessable(
            "password must be 8..=200 characters".into(),
        ));
    }
    tracing::debug!(
        target: "controller.customer_auth.reset_password",
        "reset-password request received"
    );
    let resp = state
        .customer_auth
        .reset_password(req)
        .await
        .map_err(map_phase3)?;
    Ok((StatusCode::OK, Json(ApiResponse::ok(resp))))
}
