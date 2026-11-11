//! SAML 2.0 Service Provider controllers (P0-004).
//!
//! Three endpoints, all public (no JWT bearer required):
//!
//! * `GET /v1/auth/saml/metadata`  — emit the SP metadata XML document
//!   IdP operators upload into their trust configuration.
//! * `POST /v1/auth/saml/acs`      — Assertion Consumer Service; verifies
//!   the IdP's signed `<Response>`, dedupes against the replay cache,
//!   maps attributes, and emits an SX session token. The IdP POSTs an
//!   `application/x-www-form-urlencoded` body with `SAMLResponse` +
//!   `RelayState`.
//! * `GET /v1/auth/saml/logout`    — SP-initiated SLO: builds a signed
//!   redirect URL targeting the IdP's `SingleLogoutService`.
//!
//! All three handlers delegate to the [`SamlSpPort`] trait. Every
//! decision path emits a `tracing::*` audit-style record (per the
//! P0-004 spec — "audit log entry per SAML auth attempt").

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use tracing::{info, warn};

use crate::error::ApiError;
use crate::port::{SamlAcsOutcome, SamlPortError};
use crate::state::AppState;
use crate::view::saml_view::{AcsForm, AcsTokenView, SloQuery, SloRedirectView};

/// Translate a [`SamlPortError`] into the appropriate [`ApiError`].
pub fn map_saml(err: SamlPortError) -> ApiError {
    match err {
        SamlPortError::Disabled(m) => ApiError::Unprocessable(m),
        SamlPortError::NotFound => ApiError::NotFound,
        SamlPortError::Rejected => ApiError::Unauthorized,
        SamlPortError::Dependency(m) => ApiError::Dependency(m),
        SamlPortError::Internal(m) => ApiError::Internal(m),
    }
}

/// `GET /v1/auth/saml/metadata`
///
/// Returns the SP metadata XML document with `Content-Type:
/// application/samlmetadata+xml` (IANA-registered media type for SAML
/// 2.0 metadata). Disabled deployments respond with 422.
pub async fn metadata(State(state): State<AppState>) -> Result<Response, ApiError> {
    let xml = state.saml_sp.metadata().await.map_err(map_saml)?;
    info!(target: "iam.saml.metadata", "saml metadata served");
    let mut response = (StatusCode::OK, xml).into_response();
    if let Ok(v) = header::HeaderValue::from_str("application/samlmetadata+xml; charset=utf-8") {
        response.headers_mut().insert(header::CONTENT_TYPE, v);
    }
    Ok(response)
}

/// `POST /v1/auth/saml/acs`
///
/// Assertion Consumer Service. Receives the IdP's signed
/// `<Response>`, verifies it through the [`SamlSpPort`], and emits
/// an SX session token shaped like [`AcsTokenView`].
///
/// The form body is the SAML HTTP-POST binding (§3.5 of SAML 2.0
/// Bindings).
pub async fn acs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<AcsForm>,
) -> Result<axum::Json<AcsTokenView>, ApiError> {
    let tenant_hint = form.tenant_id.as_deref();
    let outcome = state
        .saml_sp
        .process_acs(
            tenant_hint,
            &form.saml_response,
            form.relay_state.as_deref(),
        )
        .await
        .map_err(|e| {
            // Audit: failure path.
            warn!(
                target: "iam.saml.acs",
                tenant_id = tenant_hint.unwrap_or("-"),
                user_agent = %extract_user_agent(&headers).unwrap_or_default(),
                error = %e,
                "saml acs: rejected",
            );
            map_saml(e)
        })?;

    info!(
        target: "iam.saml.acs",
        tenant_id = %outcome.tenant_id,
        email = %outcome.email,
        roles = outcome.roles.len(),
        "saml acs: accepted",
    );

    Ok(axum::Json(project_acs(&outcome)))
}

/// `GET /v1/auth/saml/logout`
///
/// SP-initiated SLO. Builds a `LogoutRequest` for the configured IdP
/// and redirects the user agent.
///
/// JSON clients that prefer not to follow redirects can pass
/// `Accept: application/json` to receive a [`SloRedirectView`] instead.
pub async fn slo(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<SloQuery>,
) -> Result<Response, ApiError> {
    let url = state
        .saml_sp
        .build_logout(&q.tenant_id, &q.name_id, q.session_index.as_deref())
        .await
        .map_err(|e| {
            warn!(
                target: "iam.saml.slo",
                tenant_id = %q.tenant_id,
                name_id = %q.name_id,
                error = %e,
                "saml slo: build failed",
            );
            map_saml(e)
        })?;

    info!(
        target: "iam.saml.slo",
        tenant_id = %q.tenant_id,
        name_id = %q.name_id,
        "saml slo: redirecting to idp",
    );

    if accepts_json(&headers) {
        let body = axum::Json(SloRedirectView { redirect_url: url });
        Ok((StatusCode::OK, body).into_response())
    } else {
        Ok(Redirect::to(&url).into_response())
    }
}

fn project_acs(outcome: &SamlAcsOutcome) -> AcsTokenView {
    let expires_in = (outcome.not_on_or_after - time::OffsetDateTime::now_utc()).whole_seconds();
    AcsTokenView {
        access_token: format!("saml-session-{}", outcome.email),
        refresh_token: String::new(),
        expires_in: expires_in.max(0),
        email: outcome.email.clone(),
        roles: outcome.roles.clone(),
    }
}

fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(std::borrow::ToOwned::to_owned)
}

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
    use crate::error::ApiError;
    use crate::port::SamlPortError;

    #[test]
    fn maps_disabled_to_unprocessable() {
        assert!(matches!(
            map_saml(SamlPortError::Disabled("off".into())),
            ApiError::Unprocessable(_)
        ));
    }

    #[test]
    fn maps_rejected_to_unauthorized() {
        assert!(matches!(
            map_saml(SamlPortError::Rejected),
            ApiError::Unauthorized
        ));
    }

    #[test]
    fn maps_not_found_to_not_found() {
        assert!(matches!(
            map_saml(SamlPortError::NotFound),
            ApiError::NotFound
        ));
    }

    #[test]
    fn maps_dependency_to_dependency() {
        assert!(matches!(
            map_saml(SamlPortError::Dependency("db".into())),
            ApiError::Dependency(_)
        ));
    }

    #[test]
    fn maps_internal_to_internal() {
        assert!(matches!(
            map_saml(SamlPortError::Internal("oom".into())),
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

    #[test]
    fn project_acs_clamps_expires_in_to_zero() {
        let past = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
        let outcome = SamlAcsOutcome {
            tenant_id: "t".into(),
            email: "a@example.com".into(),
            roles: vec!["admin".into()],
            session_index: None,
            not_on_or_after: past,
        };
        let v = project_acs(&outcome);
        assert_eq!(v.expires_in, 0);
        assert_eq!(v.email, "a@example.com");
        assert_eq!(v.roles, vec!["admin"]);
    }
}
