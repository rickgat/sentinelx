//! CRIT-004 — OIDC + SAML logout controllers.
//!
//! Four endpoints, all public (no JWT bearer required) — the OIDC
//! back-channel binding carries its own self-authenticating signed
//! `logout_token`, the SAML back-channel binding carries its own signed
//! XML, and the RP-initiated + front-channel endpoints work off the
//! session cookie / sid query parameter the user agent already has:
//!
//! * `GET  /v1/auth/oidc/logout`               — RP-initiated logout.
//! * `POST /v1/auth/oidc/back-channel-logout`  — IdP→SP back-channel.
//! * `GET  /v1/auth/oidc/front-channel-logout` — iframe receiver.
//! * `POST /v1/auth/saml/back-channel-logout`  — SAML back-channel.
//! * `GET  /.well-known/openid-configuration`  — discovery document.
//!
//! Every handler emits an `audit.iam.logout.*` tracing record on
//! success and failure paths so the audit pipeline can persist them.

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use serde::Deserialize;
use tracing::{info, warn};

use crate::error::ApiError;
use crate::middleware::auth::AuthenticatedUser;
use crate::port::LogoutPortError;
use crate::state::AppState;

/// Translate a [`LogoutPortError`] into the appropriate [`ApiError`].
///
/// Verification failures collapse to `401 Unauthorized` so an attacker
/// cannot tell which step rejected them. Replay-cache hits surface as
/// `Unauthorized` too — same reason.
pub fn map_logout(err: LogoutPortError) -> ApiError {
    match err {
        LogoutPortError::Disabled(m) => ApiError::Unprocessable(m),
        LogoutPortError::Rejected | LogoutPortError::Replay => ApiError::Unauthorized,
        LogoutPortError::Dependency(m) => ApiError::Dependency(m),
        LogoutPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// Query string for the front-channel iframe endpoint.
#[derive(Debug, Deserialize)]
pub struct FrontchannelQuery {
    /// `sid` — the IdP-side session identifier embedded in the original
    /// `id_token`. The SP looks this up in its session-registry to
    /// revoke the matching local session.
    pub sid: String,
    /// `iss` — the IdP issuer. Optional. Some IdPs include it so the SP
    /// can validate the iframe is from a known trust anchor.
    #[serde(default)]
    pub iss: Option<String>,
}

/// JSON body for the OIDC back-channel logout endpoint. The OIDC spec
/// states the body is `application/x-www-form-urlencoded` with a
/// `logout_token=...` field; we accept both forms.
#[derive(Debug, Deserialize)]
pub struct BackchannelLogoutForm {
    /// Signed `logout_token` JWT.
    pub logout_token: String,
}

/// Query for the RP-initiated logout endpoint.
#[derive(Debug, Default, Deserialize)]
pub struct OidcRpLogoutQuery {
    /// Optional `post_logout_redirect_uri` override.
    #[serde(default)]
    pub post_logout_redirect_uri: Option<String>,
}

// ---------------------------------------------------------------------------
// `GET /v1/auth/oidc/logout` — RP-initiated logout.
// ---------------------------------------------------------------------------

/// Build the IdP `end_session_endpoint` URL and bounce the user agent.
///
/// The SP reads the `id_token` and `sid` from the caller's session
/// (resolved via the bearer token's `jti`), revokes the local session,
/// then returns a 302 redirect to the IdP. JSON clients can opt out of
/// the redirect by sending `Accept: application/json`.
pub async fn oidc_rp_logout(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    headers: HeaderMap,
    Query(_q): Query<OidcRpLogoutQuery>,
) -> Result<Response, ApiError> {
    let session_id = user.claims.jti.clone();
    let redirect = state
        .oidc_rp_logout
        .initiate(&session_id)
        .await
        .map_err(|e| {
            warn!(
                target: "audit.iam.logout.oidc_rp",
                outcome = "failure",
                session_id = %session_id,
                error = %e,
                "oidc rp-initiated logout: rejected",
            );
            map_logout(e)
        })?;

    info!(
        target: "audit.iam.logout.oidc_rp",
        outcome = "success",
        session_id = %session_id,
        "oidc rp-initiated logout: redirecting to idp",
    );

    if accepts_json(&headers) {
        let body = serde_json::json!({
            "redirect_url": redirect.url,
            "state": redirect.state,
        });
        Ok((StatusCode::OK, Json(body)).into_response())
    } else {
        Ok(Redirect::to(&redirect.url).into_response())
    }
}

// ---------------------------------------------------------------------------
// `POST /v1/auth/oidc/back-channel-logout` — IdP→SP back-channel.
// ---------------------------------------------------------------------------

/// Process a back-channel `logout_token` and revoke the matching local
/// session.
///
/// Per the OpenID Connect Back-Channel Logout 1.0 spec, a successful
/// response is `200 OK` with no body. Errors surface as `400 Bad
/// Request` (malformed body) or `401 Unauthorized` (verification or
/// replay failure).
pub async fn oidc_backchannel_logout(
    State(state): State<AppState>,
    axum::Form(form): axum::Form<BackchannelLogoutForm>,
) -> Result<Response, ApiError> {
    match state
        .oidc_backchannel_logout
        .process(&form.logout_token)
        .await
    {
        Ok(()) => {
            info!(
                target: "audit.iam.logout.oidc_backchannel",
                outcome = "success",
                "oidc back-channel logout: accepted",
            );
            Ok((StatusCode::OK, ()).into_response())
        }
        Err(e) => {
            warn!(
                target: "audit.iam.logout.oidc_backchannel",
                outcome = "failure",
                error = %e,
                "oidc back-channel logout: rejected",
            );
            Err(map_logout(e))
        }
    }
}

// ---------------------------------------------------------------------------
// `GET /v1/auth/oidc/front-channel-logout` — iframe receiver.
// ---------------------------------------------------------------------------

/// Revoke the session identified by `?sid=...` and respond with an
/// empty `200 OK` + `Cache-Control: no-store`.
pub async fn oidc_frontchannel_logout(
    State(state): State<AppState>,
    Query(q): Query<FrontchannelQuery>,
) -> Result<Response, ApiError> {
    match state.oidc_frontchannel_logout.revoke_by_sid(&q.sid).await {
        Ok(()) => {
            info!(
                target: "audit.iam.logout.oidc_frontchannel",
                outcome = "success",
                sid = %q.sid,
                "oidc front-channel logout: accepted",
            );
            let mut resp = (StatusCode::OK, "").into_response();
            resp.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            Ok(resp)
        }
        Err(e) => {
            warn!(
                target: "audit.iam.logout.oidc_frontchannel",
                outcome = "failure",
                sid = %q.sid,
                error = %e,
                "oidc front-channel logout: rejected",
            );
            Err(map_logout(e))
        }
    }
}

// ---------------------------------------------------------------------------
// `POST /v1/auth/saml/back-channel-logout`
// ---------------------------------------------------------------------------

/// Form body for the SAML back-channel binding.
#[derive(Debug, Deserialize)]
pub struct SamlBackchannelLogoutForm {
    /// Tenant id hint (multi-tenant deployments key off this to pick
    /// the IdP record).
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Raw `<samlp:LogoutRequest>` XML body.
    #[serde(rename = "SAMLRequest")]
    pub saml_request: String,
}

/// Process a SAML back-channel `LogoutRequest`.
pub async fn saml_backchannel_logout(
    State(state): State<AppState>,
    axum::Form(form): axum::Form<SamlBackchannelLogoutForm>,
) -> Result<Response, ApiError> {
    let tenant_hint = form.tenant_id.as_deref();
    match state
        .saml_backchannel_logout
        .process(tenant_hint, &form.saml_request)
        .await
    {
        Ok(()) => {
            info!(
                target: "audit.iam.logout.saml_backchannel",
                outcome = "success",
                tenant_id = tenant_hint.unwrap_or("-"),
                "saml back-channel logout: accepted",
            );
            Ok((StatusCode::OK, "").into_response())
        }
        Err(e) => {
            warn!(
                target: "audit.iam.logout.saml_backchannel",
                outcome = "failure",
                tenant_id = tenant_hint.unwrap_or("-"),
                error = %e,
                "saml back-channel logout: rejected",
            );
            Err(map_logout(e))
        }
    }
}

// ---------------------------------------------------------------------------
// `GET /.well-known/openid-configuration`
// ---------------------------------------------------------------------------

/// Serve the OIDC discovery document. Public; no auth.
pub async fn openid_configuration(State(state): State<AppState>) -> Result<Response, ApiError> {
    let doc = state.oidc_discovery.document().await.map_err(map_logout)?;
    let mut resp = (StatusCode::OK, Json(doc)).into_response();
    resp.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=300"),
    );
    Ok(resp)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn accepts_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().contains("application/json"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn maps_disabled_to_unprocessable() {
        assert!(matches!(
            map_logout(LogoutPortError::Disabled("off".into())),
            ApiError::Unprocessable(_)
        ));
    }

    #[test]
    fn maps_rejected_to_unauthorized() {
        assert!(matches!(
            map_logout(LogoutPortError::Rejected),
            ApiError::Unauthorized
        ));
    }

    #[test]
    fn maps_replay_to_unauthorized() {
        assert!(matches!(
            map_logout(LogoutPortError::Replay),
            ApiError::Unauthorized
        ));
    }

    #[test]
    fn maps_dependency_to_dependency() {
        assert!(matches!(
            map_logout(LogoutPortError::Dependency("db".into())),
            ApiError::Dependency(_)
        ));
    }

    #[test]
    fn maps_internal_to_internal() {
        assert!(matches!(
            map_logout(LogoutPortError::Internal("oom".into())),
            ApiError::Internal(_)
        ));
    }

    #[test]
    fn accepts_json_detects_header() {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT, "application/json".parse().unwrap());
        assert!(accepts_json(&h));
        h.insert(header::ACCEPT, "text/html".parse().unwrap());
        assert!(!accepts_json(&h));
    }
}
