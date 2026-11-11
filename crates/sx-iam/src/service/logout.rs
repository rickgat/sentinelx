//! CRIT-004 — OIDC + SAML logout primitives.
//!
//! This module provides three pure-logic primitives the API layer (and
//! the monolith composition root) compose into HTTP endpoints:
//!
//! * [`LogoutTokenClaims`] / [`verify_logout_token`] — verify an OIDC
//!   back-channel `logout_token` per OpenID Connect Back-Channel Logout
//!   1.0 §2.4. The verifier enforces:
//!     - JWS signature against a JWKS,
//!     - `iss`, `aud` claims,
//!     - `iat` recency window (per spec the token is short-lived),
//!     - `events` claim contains the required
//!       `http://schemas.openid.net/event/backchannel-logout` URI,
//!     - `nonce` claim is absent (spec MUST NOT have it),
//!     - at least one of `sub` / `sid` is present.
//! * [`parse_saml_logout_request`] / [`SamlLogoutRequest`] — parse the
//!   inflated XML of a SAML 2.0 `<samlp:LogoutRequest>` arriving on the
//!   back-channel binding. Surfaces `NameID` + `SessionIndex` for the
//!   downstream revoker. Signature verification is delegated to the
//!   existing SAML core (`verify_assertion` / `verify_xmldsig`).
//! * [`RpLogoutRedirect`] / [`build_rp_logout_redirect`] — assemble the
//!   IdP-side `end_session_endpoint` URL the SP redirects the user agent
//!   to during RP-initiated logout (OpenID Connect RP-Initiated Logout
//!   1.0 §2).
//!
//! ## Replay protection
//!
//! The back-channel `logout_token` MUST NOT be accepted twice — Section
//! 2.6 of the spec. This module exposes a stateless verifier; the
//! caller is expected to hand the verified `jti` (or, when `jti` is
//! absent, the entire raw token's SHA-256 fingerprint) to a replay
//! cache. The monolith composition root uses
//! [`crate::service::saml::InMemoryReplayCache`] for this so we share
//! the existing implementation.
//!
//! All entry points return [`crate::IamError`]; failures collapse to
//! `IamError::InvalidCredentials` on the wire so an attacker cannot
//! distinguish "bad signature" from "wrong issuer" via timing or
//! response shape.

#![allow(
    // The OIDC / SAML logout space is loaded with acronyms (IdP, SP,
    // OIDC, RP, SLO, SAML, JWKS, ...). Backticking each one in narrative
    // comments would hurt readability for no security gain — same call
    // the SAML core module already made.
    clippy::doc_markdown,
    // `verify_logout_token` is a 100-line pipeline; splitting it would
    // hide the spec walkthrough rather than help readability.
    clippy::too_many_lines,
    // The XML parser test fixtures slice into byte ranges that the
    // surrounding pipeline guarantees are valid. The matching
    // `extract_element_slice` helper in the SAML module accepts this
    // same lint allowance for the same reason.
    clippy::indexing_slicing,
)]

use std::collections::HashSet;
use std::time::Duration;

use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::IamError;

/// The OIDC back-channel logout event URI (Section 2.4 of the spec).
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// Verified claims extracted from a back-channel `logout_token`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutTokenClaims {
    /// `iss` — IdP issuer (already matched against the verifier config).
    pub issuer: String,
    /// `aud` — RP client id (already matched).
    pub audience: String,
    /// `sub` — subject identifier. Optional; at least one of `sub` / `sid`
    /// MUST be present (verifier enforces this).
    pub subject: Option<String>,
    /// `sid` — Session ID. Preferred over `sub` for revocation lookup.
    pub session_id: Option<String>,
    /// `jti` — unique token id, used for replay-cache keying.
    pub jti: Option<String>,
    /// `iat` — issuance time (epoch seconds).
    pub issued_at: i64,
}

/// Configuration the back-channel logout verifier consumes. Mirrors the
/// shape of [`crate::service::oidc_verifier::OidcVerifierConfig`] so the
/// caller can re-use a single OIDC settings struct.
#[derive(Debug, Clone)]
pub struct LogoutTokenVerifierConfig {
    /// Required `iss` claim — IdP issuer URL.
    pub issuer: String,
    /// Required `aud` claim — RP client id.
    pub audience: String,
    /// Clock-skew tolerance applied to `iat`. Five seconds matches the
    /// default of the `id_token` verifier.
    pub leeway: Duration,
}

/// Verify an OIDC back-channel `logout_token` against `jwks`.
///
/// Returns the verified [`LogoutTokenClaims`] on success; otherwise an
/// [`IamError::InvalidCredentials`]. The raw token is never logged.
///
/// The function does NOT perform replay protection — see the module
/// docs. Callers MUST hand the returned `jti` (or token fingerprint) to
/// a replay cache before acting on the claims.
#[allow(clippy::cognitive_complexity)] // linear pipeline; spec-walkthrough reads top-to-bottom
pub fn verify_logout_token(
    cfg: &LogoutTokenVerifierConfig,
    jwks: &JwkSet,
    logout_token: &str,
) -> Result<LogoutTokenClaims, IamError> {
    let header = decode_header(logout_token).map_err(|_| {
        tracing::warn!(
            target: "iam.oidc.backchannel",
            reason = "bad_header",
            "oidc.backchannel.verify.reject"
        );
        IamError::InvalidCredentials
    })?;

    // Per OIDC core: symmetric algorithms MUST NOT be accepted for
    // public verification flows. The IdP signs with its private key
    // material; only asymmetric algorithms are appropriate.
    if matches!(
        header.alg,
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
    ) {
        tracing::warn!(
            target: "iam.oidc.backchannel",
            reason = "symmetric_alg_rejected",
            "oidc.backchannel.verify.reject"
        );
        return Err(IamError::InvalidCredentials);
    }

    let kid = header.kid.ok_or_else(|| {
        tracing::warn!(
            target: "iam.oidc.backchannel",
            reason = "missing_kid",
            "oidc.backchannel.verify.reject"
        );
        IamError::InvalidCredentials
    })?;

    let Some(jwk) = jwks.find(&kid) else {
        tracing::warn!(
            target: "iam.oidc.backchannel",
            issuer = %cfg.issuer,
            kid = %kid,
            reason = "unknown_kid",
            "oidc.backchannel.verify.reject"
        );
        return Err(IamError::InvalidCredentials);
    };
    let decoding_key = decoding_key_from_jwk(jwk)?;

    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[&cfg.issuer]);
    validation.set_audience(&[&cfg.audience]);
    // Per spec: exp is NOT required on logout_token. We require iss + aud.
    validation.required_spec_claims =
        HashSet::from(["iss".to_string(), "aud".to_string(), "iat".to_string()]);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = true;
    validation.leeway = cfg.leeway.as_secs();
    validation.algorithms = vec![header.alg];

    let decoded =
        decode::<RawLogoutClaims>(logout_token, &decoding_key, &validation).map_err(|e| {
            let reason = match e.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => "issuer",
                jsonwebtoken::errors::ErrorKind::InvalidAudience => "audience",
                jsonwebtoken::errors::ErrorKind::InvalidSignature => "signature",
                _ => "claims",
            };
            tracing::warn!(
                target: "iam.oidc.backchannel",
                issuer = %cfg.issuer,
                kid = %kid,
                reason = %reason,
                "oidc.backchannel.verify.reject"
            );
            IamError::InvalidCredentials
        })?;

    let raw = decoded.claims;

    // Spec §2.4: a back-channel logout_token MUST NOT contain `nonce`.
    if raw.nonce.is_some() {
        tracing::warn!(
            target: "iam.oidc.backchannel",
            issuer = %cfg.issuer,
            reason = "nonce_present",
            "oidc.backchannel.verify.reject"
        );
        return Err(IamError::InvalidCredentials);
    }

    // events MUST contain the back-channel-logout event URI.
    let event_present = raw
        .events
        .as_ref()
        .is_some_and(|events| events.get(BACKCHANNEL_LOGOUT_EVENT).is_some());
    if !event_present {
        tracing::warn!(
            target: "iam.oidc.backchannel",
            issuer = %cfg.issuer,
            reason = "events_missing",
            "oidc.backchannel.verify.reject"
        );
        return Err(IamError::InvalidCredentials);
    }

    // At least one of sub / sid MUST be present.
    if raw.sub.is_none() && raw.sid.is_none() {
        tracing::warn!(
            target: "iam.oidc.backchannel",
            issuer = %cfg.issuer,
            reason = "no_sub_or_sid",
            "oidc.backchannel.verify.reject"
        );
        return Err(IamError::InvalidCredentials);
    }

    tracing::info!(
        target: "iam.oidc.backchannel",
        issuer = %raw.iss,
        kid = %kid,
        "oidc.backchannel.verify.accept"
    );
    Ok(LogoutTokenClaims {
        issuer: raw.iss,
        audience: raw.aud,
        subject: raw.sub,
        session_id: raw.sid,
        jti: raw.jti,
        issued_at: raw.iat,
    })
}

fn decoding_key_from_jwk(jwk: &Jwk) -> Result<DecodingKey, IamError> {
    match &jwk.algorithm {
        AlgorithmParameters::RSA(_)
        | AlgorithmParameters::EllipticCurve(_)
        | AlgorithmParameters::OctetKeyPair(_) => {
            DecodingKey::from_jwk(jwk).map_err(|_| IamError::InvalidCredentials)
        }
        AlgorithmParameters::OctetKey(_) => Err(IamError::InvalidCredentials),
    }
}

/// Raw claim set we deserialise off the back-channel `logout_token`. Kept
/// private — only [`LogoutTokenClaims`] crosses the module boundary.
#[derive(Debug, Deserialize, Serialize)]
struct RawLogoutClaims {
    iss: String,
    aud: String,
    iat: i64,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    sid: Option<String>,
    #[serde(default)]
    jti: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    events: Option<serde_json::Map<String, serde_json::Value>>,
}

// ---------------------------------------------------------------------------
// RP-initiated logout URL builder
// ---------------------------------------------------------------------------

/// Output of [`build_rp_logout_redirect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpLogoutRedirect {
    /// Absolute URL the user agent must be redirected to. The query
    /// string carries `id_token_hint`, `post_logout_redirect_uri`, and
    /// `state`.
    pub url: String,
    /// The opaque CSRF token the SP echoed into `state`. Callers MUST
    /// persist this against the session so the `?state=...` echo can be
    /// verified when the IdP bounces the user agent back.
    pub state: String,
}

/// Build the IdP `end_session_endpoint` URL for RP-initiated logout.
///
/// * `end_session_endpoint` — the IdP-published endpoint URL.
/// * `id_token` — the original `id_token` issued at login (the spec
///   names this `id_token_hint`). The SP never re-validates it; the IdP
///   uses it to identify the session.
/// * `post_logout_redirect_uri` — the URL the IdP redirects the user
///   agent back to once the IdP session has been terminated.
/// * `state` — opaque CSRF token. Generated fresh by the caller and
///   stored against the session.
#[must_use]
pub fn build_rp_logout_redirect(
    end_session_endpoint: &str,
    id_token: &str,
    post_logout_redirect_uri: &str,
    state: String,
) -> RpLogoutRedirect {
    let sep = if end_session_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    let mut url = String::with_capacity(end_session_endpoint.len() + 256);
    url.push_str(end_session_endpoint);
    url.push(sep);
    url.push_str("id_token_hint=");
    url.extend(url::form_urlencoded::byte_serialize(id_token.as_bytes()));
    url.push_str("&post_logout_redirect_uri=");
    url.extend(url::form_urlencoded::byte_serialize(
        post_logout_redirect_uri.as_bytes(),
    ));
    url.push_str("&state=");
    url.extend(url::form_urlencoded::byte_serialize(state.as_bytes()));
    RpLogoutRedirect { url, state }
}

// ---------------------------------------------------------------------------
// SAML LogoutRequest parser
// ---------------------------------------------------------------------------

/// A parsed SAML 2.0 `<samlp:LogoutRequest>`. Signature verification is
/// handled separately by the existing SAML XMLDSig pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlLogoutRequest {
    /// `ID` attribute of the `<samlp:LogoutRequest>` element. Used for
    /// replay protection.
    pub id: String,
    /// `Issuer` element content (IdP's EntityID).
    pub issuer: String,
    /// `NameID` element content.
    pub name_id: String,
    /// `SessionIndex` element content. Optional — when absent the SP MUST
    /// terminate every session it has for the principal.
    pub session_index: Option<String>,
}

/// Parse the XML body of a SAML 2.0 LogoutRequest into a flat
/// [`SamlLogoutRequest`].
///
/// This routine does NOT verify the embedded XML Signature — the caller
/// is expected to invoke the existing SAML SP signature path
/// (`sx_iam::service::saml::response::*` or a per-binding equivalent)
/// before trusting the parsed values. Splitting the two responsibilities
/// keeps the parser pure and makes replay-cache integration trivial.
pub fn parse_saml_logout_request(
    xml: &str,
) -> Result<SamlLogoutRequest, crate::service::saml::SamlError> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut id: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut name_id: Option<String> = None;
    let mut session_index: Option<String> = None;

    let mut in_request: u32 = 0;
    let mut in_issuer: u32 = 0;
    let mut in_name_id: u32 = 0;
    let mut in_session_index: u32 = 0;
    let mut buf_issuer = String::new();
    let mut buf_name_id = String::new();
    let mut buf_session_index = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e) | Event::Empty(e)) => {
                let local = local_name(e.name().as_ref()).to_vec();
                if local == b"LogoutRequest" {
                    in_request = in_request.saturating_add(1);
                    for attr in e.attributes().flatten() {
                        if local_name(attr.key.as_ref()) == b"ID" {
                            if let Ok(v) = attr.decoded_and_normalized_value(
                                quick_xml::XmlVersion::default(),
                                reader.decoder(),
                            ) {
                                id = Some(v.into_owned());
                            }
                        }
                    }
                } else if local == b"Issuer" && in_request > 0 {
                    in_issuer = in_issuer.saturating_add(1);
                } else if local == b"NameID" && in_request > 0 {
                    in_name_id = in_name_id.saturating_add(1);
                } else if local == b"SessionIndex" && in_request > 0 {
                    in_session_index = in_session_index.saturating_add(1);
                }
            }
            Ok(Event::End(e)) => {
                let local = local_name(e.name().as_ref()).to_vec();
                if local == b"Issuer" && in_issuer > 0 {
                    in_issuer -= 1;
                    if in_issuer == 0 && !buf_issuer.is_empty() {
                        issuer = Some(std::mem::take(&mut buf_issuer));
                    }
                } else if local == b"NameID" && in_name_id > 0 {
                    in_name_id -= 1;
                    if in_name_id == 0 && !buf_name_id.is_empty() {
                        name_id = Some(std::mem::take(&mut buf_name_id));
                    }
                } else if local == b"SessionIndex" && in_session_index > 0 {
                    in_session_index -= 1;
                    if in_session_index == 0 && !buf_session_index.is_empty() {
                        session_index = Some(std::mem::take(&mut buf_session_index));
                    }
                } else if local == b"LogoutRequest" && in_request > 0 {
                    in_request -= 1;
                }
            }
            Ok(Event::Text(t)) => {
                let s = t
                    .xml_content(quick_xml::XmlVersion::default())
                    .map_err(|e| {
                        crate::service::saml::SamlError::XmlMalformed(format!("logout text: {e}"))
                    })?;
                if in_issuer > 0 {
                    buf_issuer.push_str(&s);
                } else if in_name_id > 0 {
                    buf_name_id.push_str(&s);
                } else if in_session_index > 0 {
                    buf_session_index.push_str(&s);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(crate::service::saml::SamlError::XmlMalformed(format!(
                    "logout: {e}"
                )));
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(SamlLogoutRequest {
        id: id.ok_or_else(|| {
            crate::service::saml::SamlError::XmlMalformed("LogoutRequest/@ID missing".into())
        })?,
        issuer: issuer.ok_or_else(|| {
            crate::service::saml::SamlError::XmlMalformed("LogoutRequest/Issuer missing".into())
        })?,
        name_id: name_id.ok_or_else(|| {
            crate::service::saml::SamlError::XmlMalformed("LogoutRequest/NameID missing".into())
        })?,
        session_index,
    })
}

fn local_name(name: &[u8]) -> &[u8] {
    match name.iter().position(|b| *b == b':') {
        Some(i) => name.get(i + 1..).unwrap_or(name),
        None => name,
    }
}

// ---------------------------------------------------------------------------
// SAML LogoutResponse parser
// ---------------------------------------------------------------------------

/// Successful-completion status URI per SAML 2.0 Core §3.2.2.2.
pub const SAML_STATUS_SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";

/// A parsed SAML 2.0 `<samlp:LogoutResponse>`. Signature verification is
/// handled separately by
/// [`crate::service::saml::verify_logout_response_signature`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlLogoutResponse {
    /// `ID` attribute of the `<samlp:LogoutResponse>` element. Used for
    /// replay protection.
    pub id: String,
    /// `InResponseTo` attribute. Echoes the original `<LogoutRequest>`'s
    /// ID so the SP can correlate. Optional in theory; SAML 2.0 Core says
    /// the receiver SHOULD include it. We surface `None` when absent.
    pub in_response_to: Option<String>,
    /// `Issuer` element content (IdP's EntityID).
    pub issuer: String,
    /// `StatusCode/@Value` — the status URI. Most commonly
    /// [`SAML_STATUS_SUCCESS`]. Callers MUST verify this before treating
    /// the response as a successful confirmation.
    pub status_code: String,
}

impl SamlLogoutResponse {
    /// Whether the IdP confirmed the logout — i.e. `StatusCode` equals
    /// the SAML 2.0 success URI.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.status_code == SAML_STATUS_SUCCESS
    }
}

/// Parse the XML body of a SAML 2.0 `<samlp:LogoutResponse>` into a flat
/// [`SamlLogoutResponse`].
///
/// Like [`parse_saml_logout_request`], this is a pure parser — the
/// caller must invoke [`crate::service::saml::verify_logout_response_signature`]
/// (or an equivalent XMLDSig path) before trusting the parsed values.
pub fn parse_saml_logout_response(
    xml: &str,
) -> Result<SamlLogoutResponse, crate::service::saml::SamlError> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut id: Option<String> = None;
    let mut in_response_to: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut status_code: Option<String> = None;

    let mut in_response: u32 = 0;
    let mut in_issuer: u32 = 0;
    let mut buf_issuer = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e) | Event::Empty(e)) => {
                let local = local_name(e.name().as_ref()).to_vec();
                if local == b"LogoutResponse" {
                    in_response = in_response.saturating_add(1);
                    for attr in e.attributes().flatten() {
                        let key = local_name(attr.key.as_ref()).to_vec();
                        if key == b"ID" {
                            if let Ok(v) = attr.decoded_and_normalized_value(
                                quick_xml::XmlVersion::default(),
                                reader.decoder(),
                            ) {
                                id = Some(v.into_owned());
                            }
                        } else if key == b"InResponseTo" {
                            if let Ok(v) = attr.decoded_and_normalized_value(
                                quick_xml::XmlVersion::default(),
                                reader.decoder(),
                            ) {
                                in_response_to = Some(v.into_owned());
                            }
                        }
                    }
                } else if local == b"Issuer" && in_response > 0 {
                    in_issuer = in_issuer.saturating_add(1);
                } else if local == b"StatusCode" && in_response > 0 {
                    // StatusCode is empty-element style; the URI lives
                    // in the @Value attribute. Read it on both Start
                    // and Empty (same handler).
                    for attr in e.attributes().flatten() {
                        if local_name(attr.key.as_ref()) == b"Value" {
                            if let Ok(v) = attr.decoded_and_normalized_value(
                                quick_xml::XmlVersion::default(),
                                reader.decoder(),
                            ) {
                                // First StatusCode wins — nested
                                // StatusCodes (sub-statuses) are
                                // ignored for the MVP.
                                if status_code.is_none() {
                                    status_code = Some(v.into_owned());
                                }
                            }
                        }
                    }
                }
            }
            Ok(Event::End(e)) => {
                let local = local_name(e.name().as_ref()).to_vec();
                if local == b"Issuer" && in_issuer > 0 {
                    in_issuer -= 1;
                    if in_issuer == 0 && !buf_issuer.is_empty() {
                        issuer = Some(std::mem::take(&mut buf_issuer));
                    }
                } else if local == b"LogoutResponse" && in_response > 0 {
                    in_response -= 1;
                }
            }
            Ok(Event::Text(t)) => {
                let s = t
                    .xml_content(quick_xml::XmlVersion::default())
                    .map_err(|e| {
                        crate::service::saml::SamlError::XmlMalformed(format!(
                            "logout response text: {e}"
                        ))
                    })?;
                if in_issuer > 0 {
                    buf_issuer.push_str(&s);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(crate::service::saml::SamlError::XmlMalformed(format!(
                    "logout response: {e}"
                )));
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(SamlLogoutResponse {
        id: id.ok_or_else(|| {
            crate::service::saml::SamlError::XmlMalformed("LogoutResponse/@ID missing".into())
        })?,
        in_response_to,
        issuer: issuer.ok_or_else(|| {
            crate::service::saml::SamlError::XmlMalformed("LogoutResponse/Issuer missing".into())
        })?,
        status_code: status_code.ok_or_else(|| {
            crate::service::saml::SamlError::XmlMalformed(
                "LogoutResponse/Status/StatusCode/@Value missing".into(),
            )
        })?,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    // -----------------------------------------------------------------
    // RP-initiated redirect builder
    // -----------------------------------------------------------------

    #[test]
    fn rp_logout_redirect_appends_query_string() {
        let r = build_rp_logout_redirect(
            "https://idp.example.com/logout",
            "id-token-blob",
            "https://sx.example.com/login?logged_out=1",
            "csrf-abc".to_string(),
        );
        assert!(r.url.starts_with("https://idp.example.com/logout?"));
        assert!(r.url.contains("id_token_hint=id-token-blob"));
        assert!(r.url.contains("state=csrf-abc"));
        // Reserved URL characters are encoded.
        assert!(r.url.contains(
            "post_logout_redirect_uri=https%3A%2F%2Fsx.example.com%2Flogin%3Flogged_out%3D1"
        ));
        assert_eq!(r.state, "csrf-abc");
    }

    #[test]
    fn rp_logout_redirect_uses_amp_when_endpoint_already_has_query() {
        let r = build_rp_logout_redirect(
            "https://idp.example.com/logout?realm=sx",
            "tok",
            "https://sx/login",
            "s".into(),
        );
        assert!(r
            .url
            .starts_with("https://idp.example.com/logout?realm=sx&"));
    }

    // -----------------------------------------------------------------
    // SAML LogoutRequest parser
    // -----------------------------------------------------------------

    #[test]
    fn parse_saml_logout_request_pulls_out_id_issuer_nameid_session_index() {
        let xml = r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_req-1" Version="2.0" IssueInstant="2026-06-13T00:00:00Z" Destination="https://sp.example.com/slo"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID><samlp:SessionIndex>sess-42</samlp:SessionIndex></samlp:LogoutRequest>"#;
        let parsed = parse_saml_logout_request(xml).unwrap();
        assert_eq!(parsed.id, "_req-1");
        assert_eq!(parsed.issuer, "https://idp.example.com");
        assert_eq!(parsed.name_id, "alice@example.com");
        assert_eq!(parsed.session_index.as_deref(), Some("sess-42"));
    }

    #[test]
    fn parse_saml_logout_request_omits_session_index_when_absent() {
        let xml = r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_x" Version="2.0" IssueInstant="2026-06-13T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:NameID>bob@example.com</saml:NameID></samlp:LogoutRequest>"#;
        let parsed = parse_saml_logout_request(xml).unwrap();
        assert_eq!(parsed.name_id, "bob@example.com");
        assert!(parsed.session_index.is_none());
    }

    // -----------------------------------------------------------------
    // SAML LogoutResponse parser
    // -----------------------------------------------------------------

    #[test]
    fn parse_saml_logout_response_pulls_out_id_in_response_to_issuer_status() {
        let xml = r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp-1" Version="2.0" IssueInstant="2026-06-13T00:00:00Z" InResponseTo="_req-1" Destination="https://sp.example.com/slo"><saml:Issuer>https://idp.example.com</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>"#;
        let parsed = parse_saml_logout_response(xml).unwrap();
        assert_eq!(parsed.id, "_resp-1");
        assert_eq!(parsed.in_response_to.as_deref(), Some("_req-1"));
        assert_eq!(parsed.issuer, "https://idp.example.com");
        assert_eq!(parsed.status_code, SAML_STATUS_SUCCESS);
        assert!(parsed.is_success());
    }

    #[test]
    fn parse_saml_logout_response_surfaces_non_success_status() {
        let xml = r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp-2" Version="2.0" IssueInstant="2026-06-13T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/></samlp:Status></samlp:LogoutResponse>"#;
        let parsed = parse_saml_logout_response(xml).unwrap();
        assert!(!parsed.is_success());
        assert!(parsed.status_code.ends_with("Requester"));
    }

    #[test]
    fn parse_saml_logout_response_handles_missing_in_response_to() {
        // Per spec InResponseTo is SHOULD, not MUST — the parser surfaces None.
        let xml = r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp-3" Version="2.0" IssueInstant="2026-06-13T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>"#;
        let parsed = parse_saml_logout_response(xml).unwrap();
        assert!(parsed.in_response_to.is_none());
    }

    #[test]
    fn parse_saml_logout_response_rejects_missing_status_code() {
        let xml = r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp-4" Version="2.0" IssueInstant="2026-06-13T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer></samlp:LogoutResponse>"#;
        let err = parse_saml_logout_response(xml).expect_err("no status code");
        assert!(matches!(
            err,
            crate::service::saml::SamlError::XmlMalformed(_)
        ));
    }

    #[test]
    fn parse_saml_logout_request_rejects_missing_name_id() {
        let xml = r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_x" Version="2.0" IssueInstant="2026-06-13T00:00:00Z"><saml:Issuer>https://idp.example.com</saml:Issuer></samlp:LogoutRequest>"#;
        let err = parse_saml_logout_request(xml).expect_err("missing nameid");
        assert!(matches!(
            err,
            crate::service::saml::SamlError::XmlMalformed(_)
        ));
    }

    // -----------------------------------------------------------------
    // OIDC back-channel logout_token verifier (HS-based fixtures with
    // an injected JWK set that mirrors how the production verifier
    // would dispatch on `kid`). We sign with RS256 because symmetric
    // algs are rejected categorically.
    // -----------------------------------------------------------------

    /// Same 2048-bit test key used by the OIDC verifier unit tests.
    const TEST_RSA_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCqmMzkx3mbAlye
aLOygtaQ983yFOVkwDs9DubEt3rdCi/FxQ7kP9QjBBIvsZM2NgEhEOdVxW+pRvJ8
RjDF0J4EO8abSCxo7BBGMppgcyxLxrKhTCaVi+HvjtMNViBsJdSz61+nnatJXVfq
eRxxl3hysSFJCGAuejeK3Z2ZzmGnwGN+YaoVVIRIv4NLPnXBJli1cJzAACFRbJKc
GNAUrW5CDB0f2fLJSMeymC9vsLFiz6gbFGidcQdDSMoWHzZ9DKrqyudIt4nPio9f
5ELefC88rzbszp2Lgqcz5uQ8mJyWHO13TTPEiMjOL+/RvgWTgdRhDMJFhMg8YNCo
m9h1TOSZAgMBAAECggEABID7oiZu3D6qAmUeKbjzpaNjLfsAVOJQgLkgCCLAxRfn
y7il1F+9L85OVXEX2Lsrg7Ysvf++xfkZaFpD30nAYuPPR3TL9lpVcihTxCGE8nxc
utkrXhtHBAebubsJE1iFgW6rVB37omMrBxB65aKo+NyFYKZuf/T0+oRat4TX4MFj
5rStmRyBdaIQA+dfs25DAm340lasbcCj8sSB8ni9SeSxRPGsaDoJnHw+6sHxCJ5u
eyDNUE/Lk6azIdaQTbmicPDa2S3qHyS1UmdHI6pd8/bs7UrulBHAiIacLiFoQJ7M
uV9Apx9MZZTtZST7fO5G6UmLTTSsswnMzyHgD+Cv0QKBgQDl4D4u5r0UxPS8Oorq
Dlq5jeCkOHSrHHejS0P0focaAaxRhslKzoBCEcYa+4uSZKqivaH4EHzJZ+9Nlphb
wEc4tBLBZ70kUp2ZdzLxKHQMMGWmGJbLHhlWmIC8IDnuU3VCOUkO5ti/5TOsHQbN
g7ZcPUZNiPJPNA5wuWj8MS4lKQKBgQC9+/UjKkkOXxnlL6D9/rEMF4eyf7dKxGSS
MGqdtKnQWdnB38LO/nKB/MxfjgP/LcSWEPpndX4bTdKinEnFAApHKj2k9uSD/vhF
sqXureleWVlPARU2ZFyU1J0DSfWJP384Dixim6sJ0l4WW7F8BlXlYrtzYvF9Jmgo
3dqhKxjB8QKBgQDSXQHK3fEOvqbQUiqpwnUX9VQsNFXf+O8rCkenyNpN3FYbTWOM
B6mrzKQkMSoqz+CviSZd4oivr2N492V6IV2L8I5xW0Plp4z90e1Wb5SzSt7avwnP
2z2I14qHnl4lUU6vScknz+1uvoso6G8/R1ds1c4uSjKkdJj6Y1JF56O48QKBgEB+
kDFn4XUng7rx+E1BcQkR09cc1DRlh165YPg4pI0+c1YFiDSM3IKUNy0ZIPI3r0zi
Zp9Im47ZVHAvbjuaT+LozBR8XAcTP2UpyHrGPzrwSgkv7OuSFnvP0Z2UNe5px95X
sWmoPuAOsjIU3qOj4vUEF26MYD6EE0gMSHP+FWGBAoGAc4gvSYJHq1pQw7P/JHPk
rU0/9i8URf0eRPwHQTtBa3AjFIRXRIHKCOmj+3TFeYg2+1nSxFDbFMZuvbcdHZB5
XxubfFDM/zI1lx60G8M0/nCm3D+50moXiTJMfjFth97v7rOzYPv3rkmoOacPJzAY
j5zu3nHyNHrJ7Aoe+QnmfIo=
-----END PRIVATE KEY-----";

    const TEST_RSA_JWK_N: &str = "qpjM5Md5mwJcnmizsoLWkPfN8hTlZMA7PQ7mxLd63QovxcUO5D_UIwQSL7GTNjYBIRDnVcVvqUbyfEYwxdCeBDvGm0gsaOwQRjKaYHMsS8ayoUwmlYvh747TDVYgbCXUs-tfp52rSV1X6nkccZd4crEhSQhgLno3it2dmc5hp8BjfmGqFVSESL-DSz51wSZYtXCcwAAhUWySnBjQFK1uQgwdH9nyyUjHspgvb7CxYs-oGxRonXEHQ0jKFh82fQyq6srnSLeJz4qPX-RC3nwvPK827M6di4KnM-bkPJiclhztd00zxIjIzi_v0b4Fk4HUYQzCRYTIPGDQqJvYdUzkmQ";
    const TEST_RSA_JWK_E: &str = "AQAB";

    fn jwks_with(kid: &str) -> JwkSet {
        let json = json!({
            "keys": [{
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": TEST_RSA_JWK_N,
                "e": TEST_RSA_JWK_E,
            }]
        });
        serde_json::from_value(json).unwrap()
    }

    fn now_secs() -> i64 {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap()
    }

    fn sign(kid: &str, claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_PEM.as_bytes()).unwrap();
        encode(&header, &claims, &key).unwrap()
    }

    fn cfg() -> LogoutTokenVerifierConfig {
        LogoutTokenVerifierConfig {
            issuer: "https://idp.example.com/realms/sx".into(),
            audience: "sx-dashboard".into(),
            leeway: Duration::from_secs(5),
        }
    }

    fn valid_claims() -> serde_json::Value {
        json!({
            "iss": "https://idp.example.com/realms/sx",
            "aud": "sx-dashboard",
            "iat": now_secs(),
            "jti": "logout-1",
            "sub": "user-123",
            "sid": "sess-abc",
            "events": { BACKCHANNEL_LOGOUT_EVENT: {} },
        })
    }

    #[test]
    fn accepts_well_formed_logout_token() {
        let jwks = jwks_with("kid-1");
        let token = sign("kid-1", valid_claims());
        let claims = verify_logout_token(&cfg(), &jwks, &token).expect("valid");
        assert_eq!(claims.issuer, "https://idp.example.com/realms/sx");
        assert_eq!(claims.subject.as_deref(), Some("user-123"));
        assert_eq!(claims.session_id.as_deref(), Some("sess-abc"));
        assert_eq!(claims.jti.as_deref(), Some("logout-1"));
    }

    #[test]
    fn rejects_wrong_issuer() {
        let jwks = jwks_with("kid-1");
        let mut c = valid_claims();
        c["iss"] = json!("https://attacker.example.com");
        let token = sign("kid-1", c);
        let err = verify_logout_token(&cfg(), &jwks, &token).expect_err("bad iss");
        assert_eq!(err, IamError::InvalidCredentials);
    }

    #[test]
    fn rejects_wrong_audience() {
        let jwks = jwks_with("kid-1");
        let mut c = valid_claims();
        c["aud"] = json!("not-our-aud");
        let token = sign("kid-1", c);
        let err = verify_logout_token(&cfg(), &jwks, &token).expect_err("bad aud");
        assert_eq!(err, IamError::InvalidCredentials);
    }

    #[test]
    fn rejects_missing_events() {
        let jwks = jwks_with("kid-1");
        let mut c = valid_claims();
        c.as_object_mut().unwrap().remove("events");
        let token = sign("kid-1", c);
        let err = verify_logout_token(&cfg(), &jwks, &token).expect_err("no events");
        assert_eq!(err, IamError::InvalidCredentials);
    }

    #[test]
    fn rejects_events_without_backchannel_uri() {
        let jwks = jwks_with("kid-1");
        let mut c = valid_claims();
        c["events"] = json!({ "http://example.com/event": {} });
        let token = sign("kid-1", c);
        let err = verify_logout_token(&cfg(), &jwks, &token).expect_err("wrong event");
        assert_eq!(err, IamError::InvalidCredentials);
    }

    #[test]
    fn rejects_when_nonce_present() {
        let jwks = jwks_with("kid-1");
        let mut c = valid_claims();
        c["nonce"] = json!("xyz");
        let token = sign("kid-1", c);
        let err = verify_logout_token(&cfg(), &jwks, &token).expect_err("nonce forbidden");
        assert_eq!(err, IamError::InvalidCredentials);
    }

    #[test]
    fn rejects_when_no_sub_and_no_sid() {
        let jwks = jwks_with("kid-1");
        let mut c = valid_claims();
        c.as_object_mut().unwrap().remove("sub");
        c.as_object_mut().unwrap().remove("sid");
        let token = sign("kid-1", c);
        let err = verify_logout_token(&cfg(), &jwks, &token).expect_err("no sub/sid");
        assert_eq!(err, IamError::InvalidCredentials);
    }

    #[test]
    fn rejects_unknown_kid() {
        let jwks = jwks_with("kid-known");
        let token = sign("kid-unknown", valid_claims());
        let err = verify_logout_token(&cfg(), &jwks, &token).expect_err("kid not in jwks");
        assert_eq!(err, IamError::InvalidCredentials);
    }

    #[test]
    fn rejects_symmetric_algorithm_token() {
        // Forge an HS256 header — the verifier should refuse before
        // even consulting the JWKS.
        let key = EncodingKey::from_secret(b"shared");
        let token = encode(&Header::new(Algorithm::HS256), &valid_claims(), &key).unwrap();
        let jwks = jwks_with("kid-1");
        let err = verify_logout_token(&cfg(), &jwks, &token).expect_err("HS256 rejected");
        assert_eq!(err, IamError::InvalidCredentials);
    }
}
