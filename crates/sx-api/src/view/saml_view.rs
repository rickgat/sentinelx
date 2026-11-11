//! SAML 2.0 SP request / response DTOs (P0-004).
//!
//! The ACS endpoint receives a classic SAML `application/x-www-form-urlencoded`
//! body with two fields: `SAMLResponse` (base64-encoded XML) and
//! `RelayState` (opaque echo from the IdP). The SLO endpoint takes the
//! user's SX-session token (extracted from the bearer header by the
//! caller) plus an optional tenant override.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Per-tenant IdP configuration (P0-004 admin surface).
///
/// Mirrors the `saml_idp_config` row. Backs `GET` / `PUT
/// /v1/admin/saml/idp`. `signing_algo` is one of `sha1` / `sha256` /
/// `sha384` (the DB CHECK set); an unknown value is rejected by the
/// adapter. The `x509_cert_pem` is the IdP's signing certificate, not a
/// secret — it is a public key and safe to echo back.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, PartialEq, Eq)]
pub struct SamlIdpConfigView {
    /// IdP `EntityID` (its issuer). 1–1024 chars.
    #[validate(length(min = 1, max = 1024))]
    pub entity_id: String,
    /// IdP SSO (sign-in) endpoint — an absolute `http(s)://` URL.
    #[validate(length(min = 1, max = 2048))]
    pub sso_url: String,
    /// IdP SLO (single-logout) endpoint. Optional.
    #[serde(default)]
    pub slo_url: Option<String>,
    /// IdP signing certificate, PEM-encoded. 64–16384 chars.
    #[validate(length(min = 64, max = 16384))]
    pub x509_cert_pem: String,
    /// Signing algorithm: `sha1` | `sha256` | `sha384`.
    #[serde(default = "default_signing_algo")]
    pub signing_algo: String,
}

/// Serde default for [`SamlIdpConfigView::signing_algo`].
fn default_signing_algo() -> String {
    "sha256".to_owned()
}

/// `POST /v1/auth/saml/acs` form body.
///
/// `RelayState` is required to be either empty or a base64url token the
/// SP minted on the `/authn` leg; the controller never logs the value.
#[derive(Debug, Clone, Deserialize)]
pub struct AcsForm {
    /// Base64-encoded SAML `<Response>` XML.
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,
    /// Opaque relay state. SAML 2.0 Bindings §3.5.3: the SP MUST treat
    /// this as opaque on the response leg.
    #[serde(default, rename = "RelayState")]
    pub relay_state: Option<String>,
    /// Tenant id the IdP record should be loaded from. Single-tenant
    /// deployments leave this absent; multi-tenant deployments pin it
    /// via a per-IdP path prefix or the `RelayState`.
    #[serde(default)]
    pub tenant_id: Option<String>,
}

/// `GET /v1/auth/saml/logout?tenant_id=...&name_id=...` query parameters.
#[derive(Debug, Clone, Deserialize)]
pub struct SloQuery {
    /// Tenant id the IdP record belongs to.
    pub tenant_id: String,
    /// User the SLO request is for. Typically the email address that
    /// was the `NameID` on the original assertion.
    pub name_id: String,
    /// Optional SAML `SessionIndex` to scope the IdP-side logout.
    #[serde(default)]
    pub session_index: Option<String>,
}

/// `GET /v1/auth/saml/logout` 302 redirect response surfaced as JSON.
///
/// For JSON clients that prefer not to follow redirects (the
/// controller emits both shapes — JSON for `Accept: application/json`,
/// 302 otherwise).
#[derive(Debug, Clone, Serialize)]
pub struct SloRedirectView {
    /// Target URL the client should redirect to to initiate SLO.
    pub redirect_url: String,
}

/// Successful ACS outcome surfaced as JSON.
///
/// Used when the IdP / SP have agreed to the JSON binding extension.
/// The token shape mirrors [`crate::view::auth_view::TokenView`] so
/// the dashboard can reuse the same session machinery for SAML and
/// password logins.
#[derive(Debug, Clone, Serialize)]
pub struct AcsTokenView {
    /// SX-internal bearer token (JWT) the dashboard stores.
    pub access_token: String,
    /// Refresh token paired with `access_token`.
    pub refresh_token: String,
    /// Lifetime of `access_token` in seconds.
    pub expires_in: i64,
    /// The user's email, derived from the SAML `NameID`.
    pub email: String,
    /// Group memberships derived from the SAML `Group` attribute.
    pub roles: Vec<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn acs_form_deserialises_minimum_fields() {
        let json = serde_json::json!({
            "SAMLResponse": "ZHVtbXk=",
        });
        let v: AcsForm = serde_json::from_value(json).unwrap();
        assert_eq!(v.saml_response, "ZHVtbXk=");
        assert!(v.relay_state.is_none());
        assert!(v.tenant_id.is_none());
    }

    #[test]
    fn acs_form_deserialises_all_fields() {
        let json = serde_json::json!({
            "SAMLResponse": "ZHVtbXk=",
            "RelayState": "opaque",
            "tenant_id": "t1",
        });
        let v: AcsForm = serde_json::from_value(json).unwrap();
        assert_eq!(v.relay_state.as_deref(), Some("opaque"));
        assert_eq!(v.tenant_id.as_deref(), Some("t1"));
    }

    #[test]
    fn slo_query_round_trips() {
        let json = serde_json::json!({
            "tenant_id": "t1",
            "name_id": "alice@example.com",
            "session_index": "sess-1"
        });
        let v: SloQuery = serde_json::from_value(json).unwrap();
        assert_eq!(v.session_index.as_deref(), Some("sess-1"));
    }

    #[test]
    fn acs_token_view_serialises() {
        let v = AcsTokenView {
            access_token: "a".into(),
            refresh_token: "r".into(),
            expires_in: 60,
            email: "alice@example.com".into(),
            roles: vec!["admin".into()],
        };
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("access_token"));
        assert!(s.contains("admin"));
    }
}
