//! SAML 2.0 Service Provider (SP) core.
//!
//! This module implements the cryptographic and protocol primitives a
//! SAML SP needs in order to participate in a SP-initiated SSO flow with
//! an external IdP (Identity Provider). It is deliberately scoped to the
//! *core* — HTTP endpoint wiring, per-tenant configuration storage and
//! the monolith adapter live elsewhere.
//!
//! ## What this module covers (P0-004 MVP)
//!
//! * [`SamlSpConfig`] — the runtime configuration the SP needs (entity id,
//!   IdP SSO / SLO URLs, IdP's X.509 PEM-encoded signing certificate,
//!   chosen signing algorithm).
//! * [`request::build_authn_request`] — builds a base64-encoded,
//!   DEFLATE-compressed `SAMLRequest` suitable for the `HTTP-Redirect`
//!   binding (SAML 2.0 Bindings §3.4).
//! * [`metadata::parse_metadata_xml`] — emits an SP metadata XML document
//!   describing this SP's `EntityDescriptor`.
//! * [`response::verify_assertion`] — parses an XML SAML response, rejects
//!   common XSW (XML Signature Wrapping) shapes, verifies the embedded
//!   XML Signature against the configured IdP certificate, validates the
//!   `Conditions/AudienceRestriction` + `NotBefore` / `NotOnOrAfter`
//!   window with a configurable clock skew, and surfaces a flat
//!   [`response::ParsedAssertion`].
//! * [`SamlError`] — public, thiserror-derived error surface.
//!
//! ## What this module deliberately does NOT do
//!
//! * No `axum` / HTTP endpoint glue — see `sx-api`.
//! * No per-tenant config persistence — see `sx-storage`.
//! * No SLO (Single Logout) endpoint — only the SLO URL is stored.
//! * No replay-cache backend — the [`SamlError::ReplayAssertion`] variant
//!   exists so callers can plug a cache and surface a uniform error.
//!
//! ## Security notes
//!
//! The verifier intentionally **rejects** multiple top-level `Assertion`
//! elements (a classic XSW vector — a signed valid assertion plus an
//! unsigned attacker-controlled assertion sharing the IDREF), enforces
//! `Conditions/NotBefore` / `NotOnOrAfter` with skew tolerance, and
//! validates the `Audience` against the SP entity id.
//!
//! The XML Signature verification implemented here is a *minimal*
//! `RSA-SHA{1,256,384}` over the canonical `<Assertion>` byte range
//! captured during parsing. The MVP slice does NOT implement the full
//! W3C XMLDSig canonicalisation pipeline (exc-c14n) — instead the
//! signed-bytes range is captured verbatim from the input. This is
//! acceptable for production IdPs that do not re-serialise the signed
//! subtree between sign and transmit; if your IdP does, swap in a full
//! exc-c14n canonicaliser before promoting this past MVP.

#![allow(
    // The SAML XML format is verbose; the per-function complexity
    // budget is fine for this domain.
    clippy::too_many_lines,
    // The SAML/XMLDSig domain has many acronyms (IdP, SP, ACS, SLO,
    // XSW, XMLDSig, NameID …). Backticking every one of them in
    // narrative comments would hurt readability for no security gain.
    clippy::doc_markdown,
)]

pub mod acs;
pub mod fuzz_entry;
pub mod metadata;
pub mod observer;
// TOP5-#1-PHASE-1C: adapter that hands `pre_parse_gates` to the
// `sx-xmlsec` `LayeredVerifier` surface. Dormant in PHASE-1C — the
// production path in `response::verify_assertion` still calls the gate
// directly. PHASE-2A's shadow-mode dispatcher will pick this up.
pub mod preparse_for_xmlsec;
pub mod replay;
pub mod request;
pub mod response;
pub mod slo;
// TOP5-#1-PHASE-2A: factory that builds a `Box<dyn XmlDsigVerifier>`
// of the shape declared in `saml.xmldsig.verifier`. Dormant in
// PHASE-2A — the production path in `response::verify_assertion`
// still invokes the hand-rolled verifier directly. PHASE-2B's
// cutover will route `acs::process_acs_response` through this
// factory.
pub mod verifier_factory;

use std::time::Duration;

use thiserror::Error;

pub use acs::{
    decode_saml_response, process_acs_response, process_acs_response_with_verifier, AcsOutcome,
    AttributeMapping, InResponseToPolicy,
};
pub use fuzz_entry::{verify_saml_response, MAX_RESPONSE_BYTES};
pub use metadata::parse_metadata_xml;
pub use observer::{
    classify_attack, NoopSamlAttackObserver, SamlAttackEvent, SamlAttackKind, SamlAttackObserver,
    SharedSamlAttackObserver,
};
// TOP5-#1-PHASE-1C: closure-builder that adapts `pre_parse_gates` to
// `sx-xmlsec::LayeredVerifier`. PHASE-2A's shadow-mode dispatcher
// constructs `LayeredVerifier::new(XmlSec1Verifier, make_preparse_gates_closure())`.
pub use preparse_for_xmlsec::make_preparse_gates_closure;
pub use replay::{AssertionReplayCache, InMemoryReplayCache, InsertOutcome};
pub use request::build_authn_request;
pub use response::{
    verify_assertion, verify_assertion_with_verifier, verify_logout_request_signature,
    verify_logout_response_signature, ParsedAssertion,
};
pub use slo::build_logout_request;
// TOP5-#1-PHASE-2A: re-export the factory + hand-rolled adapter so
// downstream wiring (PHASE-2B's cutover, integration tests) does not
// need to qualify the module path.
pub use verifier_factory::{build_verifier, HandRolledVerifier};

/// Default clock skew tolerance for assertion `NotBefore` / `NotOnOrAfter`.
///
/// SAML 2.0 deployments commonly allow ±5 minutes; we default to a more
/// conservative 2 minutes and let callers override per-tenant.
pub const DEFAULT_CLOCK_SKEW: Duration = Duration::from_secs(120);

/// The digest / signature algorithm pair this SP advertises and accepts
/// for signed assertions.
///
/// * [`SamlSigningAlgo::Sha256`] — RFC 4051 / W3C XMLDSig `rsa-sha256` +
///   `sha256` digest. **This is the recommended default.**
/// * [`SamlSigningAlgo::Sha1`]   — `rsa-sha1` + `sha1`. Retained because
///   some legacy IdPs (notably older ADFS) still emit it; should be
///   feature-flagged off at the configuration layer for new tenants.
/// * [`SamlSigningAlgo::Sha384`] — `rsa-sha384` + `sha384`. Available for
///   tenants whose security baseline mandates SHA-2 ≥384.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamlSigningAlgo {
    /// RSA-SHA256 / SHA-256 digest. **Recommended default.**
    Sha256,
    /// RSA-SHA1 / SHA-1 digest. Legacy; only enable for IdPs that
    /// cannot upgrade.
    Sha1,
    /// RSA-SHA384 / SHA-384 digest.
    Sha384,
}

impl SamlSigningAlgo {
    /// W3C XMLDSig `SignatureMethod/@Algorithm` URI for this pair.
    #[must_use]
    pub const fn signature_method_uri(&self) -> &'static str {
        match self {
            Self::Sha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            Self::Sha1 => "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
            Self::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
        }
    }

    /// W3C XMLDSig `DigestMethod/@Algorithm` URI for this pair.
    #[must_use]
    pub const fn digest_method_uri(&self) -> &'static str {
        match self {
            Self::Sha256 => "http://www.w3.org/2001/04/xmlenc#sha256",
            Self::Sha1 => "http://www.w3.org/2000/09/xmldsig#sha1",
            Self::Sha384 => "http://www.w3.org/2001/04/xmldsig-more#sha384",
        }
    }
}

/// Runtime configuration for the SAML SP.
///
/// All fields are derived from per-tenant configuration; this struct is
/// the boundary type the rest of `sx-iam` consumes. Storage of the cert
/// PEM and URLs is the caller's responsibility.
#[derive(Debug, Clone)]
pub struct SamlSpConfig {
    /// SP's stable entity identifier (also used as the `Audience`).
    pub entity_id: String,
    /// IdP's `SingleSignOnService` URL (where `AuthnRequest` is sent).
    pub sso_url: String,
    /// IdP's `SingleLogoutService` URL. Optional — some IdPs do not
    /// support SLO, or the tenant has not enabled it.
    pub slo_url: Option<String>,
    /// IdP's X.509 signing certificate, PEM-encoded
    /// (`-----BEGIN CERTIFICATE-----`).
    pub x509_cert_pem: String,
    /// Signing algorithm this SP advertises and accepts.
    pub signing_algo: SamlSigningAlgo,
}

/// Errors produced by the SAML SP core.
///
/// Variants are deliberately coarse — at the boundary, the HTTP layer
/// must not be able to distinguish "bad signature" from "wrong audience"
/// in a way that helps an attacker calibrate their forgery.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SamlError {
    /// XML did not parse, was empty, or violated structural expectations.
    #[error("saml: malformed xml: {0}")]
    XmlMalformed(String),

    /// XML Signature verification failed (cert mismatch, bad digest,
    /// signature value mismatch, unsupported algorithm).
    #[error("saml: signature invalid")]
    SignatureInvalid,

    /// `AudienceRestriction/Audience` did not match the configured SP
    /// `entity_id`.
    #[error("saml: audience mismatch")]
    AudienceMismatch,

    /// `NotBefore` is in the future, or `NotOnOrAfter` is in the past
    /// (allowing for the configured skew tolerance).
    #[error("saml: time window failed (not_before/not_on_or_after)")]
    TimeWindow,

    /// Assertion has already been seen by the SP's replay cache (caller
    /// responsibility — emitted by code that wraps the verifier).
    #[error("saml: replay assertion")]
    ReplayAssertion,

    /// More than one `<Assertion>` element was present in the response —
    /// classic XML Signature Wrapping (XSW) attack shape.
    #[error("saml: multiple assertions (XSW defence)")]
    MultipleAssertions,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn signing_algo_uris_unique() {
        let v = [
            SamlSigningAlgo::Sha256.signature_method_uri(),
            SamlSigningAlgo::Sha1.signature_method_uri(),
            SamlSigningAlgo::Sha384.signature_method_uri(),
        ];
        let unique: std::collections::HashSet<_> = v.iter().collect();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn signing_algo_digest_uris_unique() {
        let v = [
            SamlSigningAlgo::Sha256.digest_method_uri(),
            SamlSigningAlgo::Sha1.digest_method_uri(),
            SamlSigningAlgo::Sha384.digest_method_uri(),
        ];
        let unique: std::collections::HashSet<_> = v.iter().collect();
        assert_eq!(unique.len(), 3);
    }

    #[test]
    fn error_display_does_not_leak_xml_fragments() {
        let e = SamlError::AudienceMismatch;
        assert_eq!(e.to_string(), "saml: audience mismatch");
        let e2 = SamlError::SignatureInvalid;
        assert_eq!(e2.to_string(), "saml: signature invalid");
    }

    #[test]
    fn default_clock_skew_is_two_minutes() {
        assert_eq!(DEFAULT_CLOCK_SKEW, Duration::from_secs(120));
    }
}
