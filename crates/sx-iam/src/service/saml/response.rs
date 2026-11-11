//! SAML 2.0 `Response` / `Assertion` verifier.
//!
//! Verifies the embedded XML Signature, enforces audience and
//! time-window constraints, rejects the multi-`Assertion` XSW shape,
//! and returns a flat [`ParsedAssertion`] for the caller to consume.
//!
//! The signature verification is **deliberately minimal** for the MVP
//! slice:
//!
//! 1. The verifier finds the `<Assertion>` element start/end byte offsets
//!    in the input XML.
//! 2. It computes the digest over those exact bytes — i.e. the
//!    `<Assertion>...</Assertion>` slice as it appears on the wire.
//! 3. It parses `<SignedInfo>`, computes the digest of the
//!    `<SignedInfo>` slice, then verifies the RSA signature in
//!    `<SignatureValue>` against the configured IdP X.509 certificate.
//!
//! This skips the full W3C XMLDSig canonicalisation pipeline. A
//! follow-up will swap in a proper exc-c14n canonicaliser; the current
//! shape is sufficient for IdPs that do not re-serialise the signed
//! subtree, and importantly: even the minimal shape catches
//! tampering anywhere inside `<Assertion>` (since the digest is over
//! the literal slice), the multi-Assertion XSW shape (since the parser
//! refuses to proceed), and signature-substitution shapes (since
//! `<SignedInfo>` is itself digest-checked via the RSA verification
//! step).

use std::collections::HashMap;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64_STANDARD;
use base64::Engine as _;
use quick_xml::events::Event;
use quick_xml::Reader;
use rsa::pkcs1v15::Pkcs1v15Sign;
use rsa::pkcs8::DecodePublicKey;
use rsa::RsaPublicKey;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};
use sx_xmlsec::{SamlSpConfig as XmlSecSamlSpConfig, XmlDsigVerifier, XmlSecError};
use time::OffsetDateTime;

use super::{SamlError, SamlSigningAlgo, SamlSpConfig};

/// Successfully verified SAML assertion, with the fields the SP needs to
/// drive a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAssertion {
    /// `Subject/NameID` content. The format URI is dropped — the SP
    /// downstream only cares about the principal identifier.
    pub name_id: String,
    /// `AttributeStatement/Attribute` map. Each attribute name maps to
    /// the (possibly multi-valued) list of `<AttributeValue>` text
    /// contents.
    pub attributes: HashMap<String, Vec<String>>,
    /// `AuthnStatement/@SessionIndex`, when present.
    pub session_index: Option<String>,
    /// `Conditions/@NotOnOrAfter` — surfaced so the SP can clamp its
    /// session lifetime to the assertion's hard ceiling.
    pub not_on_or_after: OffsetDateTime,
}

/// Verify a SAML 2.0 assertion XML against the SP configuration.
///
/// * `xml` — the raw XML response body (typically the `<Response>` /
///   `<Assertion>` document delivered via the HTTP-POST binding).
/// * `expected_audience` — the SP entity id that MUST match
///   `Conditions/AudienceRestriction/Audience`.
/// * `clock_skew` — tolerance added to `NotBefore` (subtracted from
///   "now") and to `NotOnOrAfter` (added to "now") when validating the
///   time window.
///
/// The IdP signing certificate, expected signing algorithm, and SP
/// entity id are taken from `sp_config`.
pub fn verify_assertion(
    sp_config: &SamlSpConfig,
    xml: &str,
    expected_audience: &str,
    clock_skew: Duration,
) -> Result<ParsedAssertion, SamlError> {
    // 1. Multi-Assertion XSW defence — fail fast before any expensive
    //    work, before any signature check.
    reject_multiple_assertions(xml)?;

    // 2. Locate the signed slice.
    let assertion_slice = extract_element_slice(xml, "Assertion")?;
    let signed_info_slice = extract_element_slice(xml, "SignedInfo")?;
    let signature_value_b64 = extract_text_in_element(xml, "SignatureValue")?;

    // 3. Parse cert and pull out the RSA public key.
    let rsa_pk = rsa_from_x509_pem(&sp_config.x509_cert_pem)?;

    // 4. Verify XML Signature: digest over <Assertion> bytes must
    //    match the <Reference><DigestValue>, and the RSA signature
    //    over <SignedInfo> bytes must verify with `rsa_pk`.
    verify_xmldsig(
        sp_config.signing_algo,
        assertion_slice,
        signed_info_slice,
        &signature_value_b64,
        xml,
        &rsa_pk,
    )?;

    // 5. Time window + audience checks.
    let conditions = parse_conditions(xml)?;
    enforce_time_window(&conditions, clock_skew)?;
    if !conditions.audiences.iter().any(|a| a == expected_audience) {
        return Err(SamlError::AudienceMismatch);
    }

    // 6. Subject / NameID, attributes, session index.
    let name_id = parse_name_id(xml)?;
    let attributes = parse_attribute_statement(xml);
    let session_index = parse_session_index(xml);

    Ok(ParsedAssertion {
        name_id,
        attributes,
        session_index,
        not_on_or_after: conditions.not_on_or_after,
    })
}

/// TOP5-#1-PHASE-2B: verify a SAML 2.0 assertion using a pluggable
/// [`XmlDsigVerifier`].
///
/// This is the verifier-trait-aware sibling of [`verify_assertion`]. The
/// composition root constructs a `Box<dyn XmlDsigVerifier>` ONCE at boot
/// via [`super::verifier_factory::build_verifier`] and passes the same
/// trait object into every ACS evaluation. When the configured mode is
/// [`sx_config::schema::XmlDsigVerifierKind::HandRolled`] (today's
/// production default), the verifier internally calls
/// [`verify_assertion`] and behaviour is byte-identical to the legacy
/// entry point — the trait dispatch is a thin wrapper.
///
/// Operationally:
///
/// * **Default config (`saml.xmldsig.verifier: handrolled`)** — this
///   function delegates to the hand-rolled [`verify_assertion`] verbatim,
///   then extracts the `ParsedAssertion` fields from `xml`. Performance
///   and behaviour are equivalent to calling [`verify_assertion`]
///   directly; the only added cost is one `Arc<dyn …>` indirection per
///   call, which is invisible against the RSA verify in the same path.
/// * **`shadow` config** — the verifier runs both hand-rolled (primary,
///   authoritative) and libxmlsec1 (secondary, observation). The primary
///   result is what reaches this function; mismatches surface via
///   `xmldsig_shadow_mismatch_total` and the `xmldsig.shadow.mismatch.*`
///   tracing events emitted from
///   [`sx_xmlsec::DualVerifier::verify`].
/// * **`xmlsec1` config** — the libxmlsec1-backed verifier is the only
///   one that runs. NOT recommended until the cutover SLO is met (zero
///   shadow-mode disagreements for 14 consecutive days against real
///   production traffic, per ADR-0022 §Decision).
///
/// ## Why the back-compat wrapper stays
///
/// [`verify_assertion`] remains the canonical low-level entry point and
/// is what `HandRolledVerifier` ultimately calls; downstream callers
/// that want byte-identical legacy semantics keep using it. This new
/// function is for the SAML SP composition-root path that wants the
/// trait-mediated dispatch + shadow-mode telemetry.
///
/// ## Errors
///
/// The trait verifier's [`XmlSecError`] is mapped back to [`SamlError`]
/// so the boundary surface in `sx-iam` is unchanged. The mapping is the
/// inverse of `verifier_factory::map_saml_error` and is intentionally
/// coarse — at the wire, the SP must not let the attacker distinguish
/// "bad signature" from "wrong audience" from "replay" (see
/// `EnabledSamlAdapter::map_saml_err` for the same policy at the HTTP
/// boundary).
pub fn verify_assertion_with_verifier(
    verifier: &dyn XmlDsigVerifier,
    sp_config: &SamlSpConfig,
    xml: &str,
    expected_audience: &str,
    clock_skew: Duration,
) -> Result<ParsedAssertion, SamlError> {
    // Translate the canonical sx-iam SamlSpConfig into the sx-xmlsec
    // placeholder shape the trait expects. The conversion drops
    // `signing_algo` — PHASE-2A's `HandRolledVerifier` adapter defaults
    // it back to Sha256 on the way through, which is the production
    // default. PHASE-2B keeps the translation here (rather than a
    // shared types crate) because the back-compat wrapper boundary is
    // the only place this round-trip happens today.
    let xmlsec_cfg = XmlSecSamlSpConfig {
        entity_id: sp_config.entity_id.clone(),
        sso_url: sp_config.sso_url.clone(),
        slo_url: sp_config.slo_url.clone(),
        x509_cert_pem: sp_config.x509_cert_pem.clone(),
    };

    // 1. Dispatch the verifier. Under default config (handrolled), this
    //    transitively calls `verify_assertion` and returns its result
    //    mapped to `VerifyOutcome`. Under `shadow`/`xmlsec1`, this
    //    dispatches to the DualVerifier or LayeredVerifier respectively.
    //    A failure here means the assertion is rejected.
    verifier
        .verify(xml.as_bytes(), &xmlsec_cfg, expected_audience, clock_skew)
        .map_err(map_xmlsec_error)?;

    // 2. The trait's `VerifyOutcome` does not carry the full
    //    `ParsedAssertion` shape (attributes, session index, time
    //    window). PHASE-2B widens it only AFTER the cutover SLO is met
    //    — until then we extract the fields here from the now-verified
    //    XML. The hand-rolled path has already validated signature +
    //    time + audience inside `verify_assertion`; this second pass
    //    only pulls out the user-visible projection (NameID, attrs).
    let conditions = parse_conditions(xml)?;
    let name_id = parse_name_id(xml)?;
    let attributes = parse_attribute_statement(xml);
    let session_index = parse_session_index(xml);

    Ok(ParsedAssertion {
        name_id,
        attributes,
        session_index,
        not_on_or_after: conditions.not_on_or_after,
    })
}

/// Map [`XmlSecError`] → [`SamlError`] at the verifier-trait boundary.
///
/// The mapping is the inverse of `verifier_factory::map_saml_error`.
/// Coarse on purpose — see [`verify_assertion_with_verifier`] for the
/// rationale and the senior plan §2.2 Class C note on why granular
/// variant divergence is collapsed during the shadow window.
fn map_xmlsec_error(err: XmlSecError) -> SamlError {
    match err {
        // SignatureInvalid + the FFI-mechanical failure modes all
        // collapse to `SamlError::SignatureInvalid` at the SP
        // boundary — the wire deliberately does not distinguish
        // "wrong signature" from "could not even attempt
        // verification" so an attacker cannot calibrate a forgery.
        // PHASE-2A's shadow-mode classifier (in `sx-xmlsec::DualVerifier`)
        // sees the granular variants BEFORE this collapse and surfaces
        // them on disagreement; the production-path mapping here is
        // the post-classifier coarse view.
        XmlSecError::SignatureInvalid
        | XmlSecError::VerifyFailed(_)
        | XmlSecError::KeysMngrFailed
        | XmlSecError::DsigCtxFailed
        | XmlSecError::InitFailed => SamlError::SignatureInvalid,
        XmlSecError::PreParseRejected(msg) => {
            // Pre-parse gates are the XSW / structural defence layer.
            // The classical XSW shape is multi-Assertion; report that
            // way for the audit-observer pipeline that already keys
            // off `MultipleAssertions`. Generic gate rejections map to
            // `XmlMalformed` to preserve the wire-stable surface.
            if msg.contains("multiple") || msg.contains("Assertion") {
                SamlError::MultipleAssertions
            } else {
                SamlError::XmlMalformed(msg)
            }
        }
        XmlSecError::XmlParseFailed(msg) => SamlError::XmlMalformed(msg),
    }
}

/// Verify the embedded XMLDSig over a SAML 2.0 `<samlp:LogoutRequest>`
/// element. Mirrors [`verify_assertion`] but covers `LogoutRequest` as
/// the signed element instead of `Assertion`.
///
/// The IdP-side `<Signature>` is enveloped on the same element (typical
/// shape for IdP-initiated SLO). The `enveloped-signature` transform is
/// applied implicitly by [`strip_signature_subtree`] on the digest path.
///
/// Returns `Ok(())` on success; on failure the error is collapsed to
/// [`SamlError::SignatureInvalid`] so the wire never distinguishes "bad
/// signature" from "wrong digest".
pub fn verify_logout_request_signature(
    sp_config: &SamlSpConfig,
    xml: &str,
) -> Result<(), SamlError> {
    let signed_slice = extract_element_slice(xml, "LogoutRequest")?;
    let signed_info_slice = extract_element_slice(xml, "SignedInfo")?;
    let signature_value_b64 = extract_text_in_element(xml, "SignatureValue")?;
    let rsa_pk = rsa_from_x509_pem(&sp_config.x509_cert_pem)?;
    verify_xmldsig(
        sp_config.signing_algo,
        signed_slice,
        signed_info_slice,
        &signature_value_b64,
        xml,
        &rsa_pk,
    )
}

/// Verify the embedded XMLDSig over a SAML 2.0 `<samlp:LogoutResponse>`.
///
/// Counterpart to [`verify_logout_request_signature`] for the receiver
/// side of SP-initiated SLO: after the SP POSTs a signed
/// `<LogoutRequest>` to the IdP, the IdP responds with a signed
/// `<LogoutResponse>` carrying the `InResponseTo` ref + a `<StatusCode>`.
/// The SP MUST verify that signature before trusting the status.
///
/// Failure modes collapse to [`SamlError::SignatureInvalid`] so the wire
/// never distinguishes "bad signature" from "wrong digest" — same
/// rationale as the assertion path.
pub fn verify_logout_response_signature(
    sp_config: &SamlSpConfig,
    xml: &str,
) -> Result<(), SamlError> {
    let signed_slice = extract_element_slice(xml, "LogoutResponse")?;
    let signed_info_slice = extract_element_slice(xml, "SignedInfo")?;
    let signature_value_b64 = extract_text_in_element(xml, "SignatureValue")?;
    let rsa_pk = rsa_from_x509_pem(&sp_config.x509_cert_pem)?;
    verify_xmldsig(
        sp_config.signing_algo,
        signed_slice,
        signed_info_slice,
        &signature_value_b64,
        xml,
        &rsa_pk,
    )
}

// ------------------------------------------------------------------
// Multi-assertion (XSW) defence
// ------------------------------------------------------------------

/// Return `Err(MultipleAssertions)` if the input XML contains more than
/// one element whose local name is `Assertion`. The check uses a
/// tokenising XML parser (not regex) so attribute-position / whitespace
/// games do not bypass it.
fn reject_multiple_assertions(xml: &str) -> Result<(), SamlError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut count: u32 = 0;
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e) | Event::Empty(e)) => {
                if local_name(e.name().as_ref()) == b"Assertion" {
                    count = count.saturating_add(1);
                    if count > 1 {
                        return Err(SamlError::MultipleAssertions);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(SamlError::XmlMalformed(format!("scan assertions: {e}")));
            }
            _ => {}
        }
        buf.clear();
    }
    if count == 0 {
        return Err(SamlError::XmlMalformed("no <Assertion> element".into()));
    }
    Ok(())
}

/// Strip the namespace prefix from an XML element name.
fn local_name(name: &[u8]) -> &[u8] {
    match name.iter().position(|b| *b == b':') {
        Some(i) => name.get(i + 1..).unwrap_or(name),
        None => name,
    }
}

// ------------------------------------------------------------------
// Byte-slice extraction for digest-over-literal
// ------------------------------------------------------------------

/// Return the `&str` slice of `xml` that covers `<local>...</local>`
/// inclusive of both tags. Uses a fresh tokenising parse so that the
/// byte offsets returned by `quick-xml`'s `buffer_position()` track the
/// original input verbatim.
fn extract_element_slice<'a>(xml: &'a str, local: &str) -> Result<&'a str, SamlError> {
    let bytes = xml.as_bytes();
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();

    let mut start: Option<usize> = None;
    let mut depth: u32 = 0;
    loop {
        // Position BEFORE reading the event — gives us the offset of the
        // event's first byte.
        let pos_before = usize::try_from(reader.buffer_position())
            .map_err(|e| SamlError::XmlMalformed(format!("pos: {e}")))?;
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                if local_name(e.name().as_ref()) == local.as_bytes() {
                    if start.is_none() {
                        start = Some(pos_before);
                    }
                    depth = depth.saturating_add(1);
                }
            }
            Ok(Event::End(e)) => {
                if local_name(e.name().as_ref()) == local.as_bytes() {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        let end = usize::try_from(reader.buffer_position())
                            .map_err(|err| SamlError::XmlMalformed(format!("pos end: {err}")))?;
                        let s_off = start.ok_or_else(|| {
                            SamlError::XmlMalformed(format!("{local}: end before start"))
                        })?;
                        let slice_bytes = bytes.get(s_off..end).ok_or_else(|| {
                            SamlError::XmlMalformed(format!("{local}: byte slice out of range"))
                        })?;
                        let s = std::str::from_utf8(slice_bytes)
                            .map_err(|err| SamlError::XmlMalformed(format!("utf8: {err}")))?;
                        return Ok(s);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(SamlError::XmlMalformed(format!("extract {local}: {e}"))),
            _ => {}
        }
        buf.clear();
    }
    Err(SamlError::XmlMalformed(format!(
        "element <{local}> not found"
    )))
}

/// Return the text content of `<local>...</local>` with whitespace
/// preserved between events. Used for `<SignatureValue>` and
/// `<DigestValue>` which carry base64 payloads.
fn extract_text_in_element(xml: &str, local: &str) -> Result<String, SamlError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut inside: u32 = 0;
    let mut out = String::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                if local_name(e.name().as_ref()) == local.as_bytes() {
                    inside = inside.saturating_add(1);
                }
            }
            Ok(Event::End(e)) => {
                if local_name(e.name().as_ref()) == local.as_bytes() {
                    inside = inside.saturating_sub(1);
                    if inside == 0 && !out.is_empty() {
                        return Ok(out);
                    }
                }
            }
            Ok(Event::Text(t)) => {
                if inside > 0 {
                    let unescaped = t
                        .xml_content(quick_xml::XmlVersion::default())
                        .map_err(|e| SamlError::XmlMalformed(format!("text: {e}")))?;
                    out.push_str(&unescaped);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(SamlError::XmlMalformed(format!("text {local}: {e}"))),
            _ => {}
        }
        buf.clear();
    }
    if out.is_empty() {
        return Err(SamlError::XmlMalformed(format!("<{local}> empty/missing")));
    }
    Ok(out)
}

/// Apply the `enveloped-signature` transform: remove the first
/// `<Signature>...</Signature>` subtree from `slice` and return the
/// result. If `slice` carries no inline `<Signature>`, it is returned
/// unchanged — that path covers Assertions whose signature lives on the
/// enclosing `<Response>` element.
///
/// The match is by local-name (`Signature`), so namespaced shapes
/// (`<ds:Signature>`) are stripped too.
fn strip_signature_subtree(slice: &str) -> Result<String, SamlError> {
    let bytes = slice.as_bytes();
    let mut reader = Reader::from_str(slice);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();

    let mut sig_start: Option<usize> = None;
    let mut depth: u32 = 0;
    loop {
        let pos_before = usize::try_from(reader.buffer_position())
            .map_err(|e| SamlError::XmlMalformed(format!("pos: {e}")))?;
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                if local_name(e.name().as_ref()) == b"Signature" {
                    if sig_start.is_none() {
                        sig_start = Some(pos_before);
                    }
                    depth = depth.saturating_add(1);
                } else if sig_start.is_some() && local_name(e.name().as_ref()) == b"Signature" {
                    depth = depth.saturating_add(1);
                }
            }
            Ok(Event::Empty(e)) => {
                if sig_start.is_none() && local_name(e.name().as_ref()) == b"Signature" {
                    // A self-closing Signature is degenerate but easy to
                    // handle: range is start..end-of-element.
                    let end = usize::try_from(reader.buffer_position())
                        .map_err(|err| SamlError::XmlMalformed(format!("pos end: {err}")))?;
                    let mut out = String::with_capacity(slice.len());
                    out.push_str(
                        std::str::from_utf8(bytes.get(..pos_before).unwrap_or(&[]))
                            .map_err(|e| SamlError::XmlMalformed(format!("utf8: {e}")))?,
                    );
                    out.push_str(
                        std::str::from_utf8(bytes.get(end..).unwrap_or(&[]))
                            .map_err(|e| SamlError::XmlMalformed(format!("utf8: {e}")))?,
                    );
                    return Ok(out);
                }
            }
            Ok(Event::End(e)) => {
                if local_name(e.name().as_ref()) == b"Signature" && sig_start.is_some() {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        let end = usize::try_from(reader.buffer_position())
                            .map_err(|err| SamlError::XmlMalformed(format!("pos end: {err}")))?;
                        let s_off = sig_start.ok_or_else(|| {
                            SamlError::XmlMalformed("strip sig: end before start".into())
                        })?;
                        let head_bytes = bytes.get(..s_off).unwrap_or(&[]);
                        let tail_bytes = bytes.get(end..).unwrap_or(&[]);
                        let head = std::str::from_utf8(head_bytes)
                            .map_err(|e| SamlError::XmlMalformed(format!("utf8: {e}")))?;
                        let tail = std::str::from_utf8(tail_bytes)
                            .map_err(|e| SamlError::XmlMalformed(format!("utf8: {e}")))?;
                        let mut out = String::with_capacity(head.len() + tail.len());
                        out.push_str(head);
                        out.push_str(tail);
                        return Ok(out);
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(SamlError::XmlMalformed(format!("strip sig: {e}"))),
            _ => {}
        }
        buf.clear();
    }
    // No inline Signature found — slice is unchanged.
    Ok(slice.to_string())
}

// ------------------------------------------------------------------
// XML Signature verification
// ------------------------------------------------------------------

/// Decode the IdP signing key PEM block and return the embedded RSA
/// public key. Two block types are accepted:
///
/// * `-----BEGIN CERTIFICATE-----`  — a full X.509 certificate (the
///   production path; every real IdP ships its signing material this way).
/// * `-----BEGIN PUBLIC KEY-----`   — a bare SPKI public-key block. Some
///   IdP fixtures expose just the public key (no cert chain), and the
///   SAML 2.0 metadata profile permits a `<KeyValue>` form that the SP
///   may have already projected to SPKI before storing it. Accepting
///   this shape costs nothing — the verifier only ever uses the pubkey
///   — and keeps the dev / test ergonomics sane.
///
/// Non-RSA keys are rejected as `SignatureInvalid` (the MVP is RSA-only).
fn rsa_from_x509_pem(pem: &str) -> Result<RsaPublicKey, SamlError> {
    let trimmed = pem.trim_start();
    if trimmed.starts_with("-----BEGIN PUBLIC KEY-----") {
        // Bare SPKI PEM — let the rsa crate parse it directly.
        return RsaPublicKey::from_public_key_pem(trimmed).map_err(|_| SamlError::SignatureInvalid);
    }
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .map_err(|_| SamlError::SignatureInvalid)?;
    let cert = pem.parse_x509().map_err(|_| SamlError::SignatureInvalid)?;
    let spki_der = cert.public_key().raw;
    RsaPublicKey::from_public_key_der(spki_der).map_err(|_| SamlError::SignatureInvalid)
}

/// Verify the XMLDSig over `assertion_slice` (the signed bytes) and
/// `signed_info_slice` (the bytes covered by the RSA signature), using
/// the digest extracted from `<Reference>/<DigestValue>` inside the
/// `<Signature>` element of `xml`.
fn verify_xmldsig(
    algo: SamlSigningAlgo,
    assertion_slice: &str,
    signed_info_slice: &str,
    signature_value_b64: &str,
    xml: &str,
    rsa_pk: &RsaPublicKey,
) -> Result<(), SamlError> {
    // 1. Confirm the SignedInfo's SignatureMethod/@Algorithm matches the
    //    configured algorithm — refuse to verify with an algorithm the
    //    operator did not opt into.
    let signed_info = signed_info_slice;
    if !signed_info.contains(&format!("Algorithm=\"{}\"", algo.signature_method_uri())) {
        return Err(SamlError::SignatureInvalid);
    }
    if !signed_info.contains(&format!("Algorithm=\"{}\"", algo.digest_method_uri())) {
        return Err(SamlError::SignatureInvalid);
    }

    // 2. Pull the expected DigestValue from the <Reference> inside
    //    <SignedInfo>.
    let digest_value_b64 = extract_text_in_element(xml, "DigestValue")?;
    let expected_digest = B64_STANDARD
        .decode(digest_value_b64.trim())
        .map_err(|_| SamlError::SignatureInvalid)?;

    // 3. Compute the digest over the Assertion bytes. We apply the
    //    `enveloped-signature` transform manually: the `<Signature>`
    //    subtree inside the Assertion (the standard SAML 2.0
    //    placement) must be excised before digesting — otherwise the
    //    digest would depend on its own value (chicken-and-egg).
    //
    //    For Assertions that ship the Signature OUTSIDE the Assertion
    //    (rare, but the WIP-era shape) the strip-Signature pass is a
    //    no-op and the digest covers the literal slice.
    let assertion_for_digest = strip_signature_subtree(assertion_slice)?;
    let computed_digest = digest_bytes(algo, assertion_for_digest.as_bytes());
    if computed_digest != expected_digest {
        return Err(SamlError::SignatureInvalid);
    }

    // 4. Decode the SignatureValue and RSA-verify over <SignedInfo>.
    let sig = B64_STANDARD
        .decode(signature_value_b64.split_whitespace().collect::<String>())
        .map_err(|_| SamlError::SignatureInvalid)?;
    let signed_info_digest = digest_bytes(algo, signed_info_slice.as_bytes());

    match algo {
        SamlSigningAlgo::Sha256 => rsa_pk
            .verify(Pkcs1v15Sign::new::<Sha256>(), &signed_info_digest, &sig)
            .map_err(|_| SamlError::SignatureInvalid),
        SamlSigningAlgo::Sha384 => rsa_pk
            .verify(Pkcs1v15Sign::new::<Sha384>(), &signed_info_digest, &sig)
            .map_err(|_| SamlError::SignatureInvalid),
        // `Pkcs1v15Sign::new::<Sha1>` requires `AssociatedOid`, which
        // the `sha1` crate omits to deter new SHA-1 use. We use the
        // explicit unprefixed scheme: the SHA-1 PKCS#1 v1.5 prefix is
        // included verbatim so the verification matches an IdP that
        // signed `DigestInfo(SHA-1)` per RFC 8017.
        SamlSigningAlgo::Sha1 => {
            // PKCS#1 v1.5 DigestInfo prefix for SHA-1 (RFC 8017 §9.2).
            const SHA1_PREFIX: &[u8] = &[
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                0x14,
            ];
            let scheme = Pkcs1v15Sign {
                hash_len: Some(20),
                prefix: SHA1_PREFIX.into(),
            };
            rsa_pk
                .verify(scheme, &signed_info_digest, &sig)
                .map_err(|_| SamlError::SignatureInvalid)
        }
    }
}

/// Compute the configured-algorithm digest of `data`.
fn digest_bytes(algo: SamlSigningAlgo, data: &[u8]) -> Vec<u8> {
    match algo {
        SamlSigningAlgo::Sha256 => Sha256::digest(data).to_vec(),
        SamlSigningAlgo::Sha1 => {
            let mut h = Sha1::new();
            sha1::Digest::update(&mut h, data);
            sha1::Digest::finalize(h).to_vec()
        }
        SamlSigningAlgo::Sha384 => Sha384::digest(data).to_vec(),
    }
}

// ------------------------------------------------------------------
// Conditions, audience, time window
// ------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Conditions {
    not_before: Option<OffsetDateTime>,
    not_on_or_after: OffsetDateTime,
    audiences: Vec<String>,
}

/// Parse the `<Conditions>` element: `@NotBefore`, `@NotOnOrAfter`, and
/// every `<AudienceRestriction>/<Audience>` text value.
fn parse_conditions(xml: &str) -> Result<Conditions, SamlError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();

    let mut nb: Option<OffsetDateTime> = None;
    let mut noa: Option<OffsetDateTime> = None;
    let mut audiences = Vec::new();
    let mut in_audience: u32 = 0;
    let mut in_conditions: u32 = 0;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e) | Event::Empty(e)) => {
                let ln = local_name(e.name().as_ref()).to_vec();
                if ln == b"Conditions" {
                    in_conditions = in_conditions.saturating_add(1);
                    for attr in e.attributes().flatten() {
                        let key = local_name(attr.key.as_ref()).to_vec();
                        let val = attr
                            .decoded_and_normalized_value(
                                quick_xml::XmlVersion::default(),
                                reader.decoder(),
                            )
                            .map_err(|err| SamlError::XmlMalformed(format!("attr: {err}")))?;
                        if key == b"NotBefore" {
                            nb = Some(parse_xs_datetime(&val)?);
                        } else if key == b"NotOnOrAfter" {
                            noa = Some(parse_xs_datetime(&val)?);
                        }
                    }
                } else if ln == b"Audience" && in_conditions > 0 {
                    in_audience = in_audience.saturating_add(1);
                }
            }
            Ok(Event::End(e)) => {
                let ln = local_name(e.name().as_ref()).to_vec();
                if ln == b"Audience" && in_audience > 0 {
                    in_audience -= 1;
                } else if ln == b"Conditions" && in_conditions > 0 {
                    in_conditions -= 1;
                }
            }
            Ok(Event::Text(t)) => {
                if in_audience > 0 {
                    let s = t
                        .xml_content(quick_xml::XmlVersion::default())
                        .map_err(|e| SamlError::XmlMalformed(format!("audience text: {e}")))?;
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        audiences.push(trimmed.to_string());
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(SamlError::XmlMalformed(format!("conditions: {e}"))),
            _ => {}
        }
        buf.clear();
    }

    let not_on_or_after =
        noa.ok_or_else(|| SamlError::XmlMalformed("Conditions/@NotOnOrAfter missing".into()))?;
    Ok(Conditions {
        not_before: nb,
        not_on_or_after,
        audiences,
    })
}

/// Enforce `NotBefore <= now + skew` and `now - skew < NotOnOrAfter`.
fn enforce_time_window(cond: &Conditions, skew: Duration) -> Result<(), SamlError> {
    let now = OffsetDateTime::now_utc();
    let skew_secs = i64::try_from(skew.as_secs()).unwrap_or(i64::MAX);
    let skew_dur = time::Duration::seconds(skew_secs);

    if let Some(nb) = cond.not_before {
        if nb > now + skew_dur {
            return Err(SamlError::TimeWindow);
        }
    }
    if cond.not_on_or_after <= now - skew_dur {
        return Err(SamlError::TimeWindow);
    }
    Ok(())
}

/// Parse an xs:dateTime in UTC. Accepts `YYYY-MM-DDTHH:MM:SS[.fff]Z`.
fn parse_xs_datetime(s: &str) -> Result<OffsetDateTime, SamlError> {
    let trimmed = s.trim();
    // Strip the trailing `Z` and optional fractional seconds; OffsetDateTime
    // supports a few formats but the simplest robust parse is via the
    // `Rfc3339` description.
    let parsed = OffsetDateTime::parse(trimmed, &time::format_description::well_known::Rfc3339);
    parsed.map_err(|e| SamlError::XmlMalformed(format!("xs:dateTime: {e}")))
}

// ------------------------------------------------------------------
// NameID, AttributeStatement, AuthnStatement
// ------------------------------------------------------------------

/// Parse the `<Subject>/<NameID>` text content.
fn parse_name_id(xml: &str) -> Result<String, SamlError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut in_subject: u32 = 0;
    let mut in_name_id: u32 = 0;
    let mut out = String::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let ln = local_name(e.name().as_ref()).to_vec();
                if ln == b"Subject" {
                    in_subject = in_subject.saturating_add(1);
                } else if ln == b"NameID" && in_subject > 0 {
                    in_name_id = in_name_id.saturating_add(1);
                }
            }
            Ok(Event::End(e)) => {
                let ln = local_name(e.name().as_ref()).to_vec();
                if ln == b"NameID" && in_name_id > 0 {
                    in_name_id -= 1;
                    if in_name_id == 0 && !out.is_empty() {
                        return Ok(out);
                    }
                } else if ln == b"Subject" && in_subject > 0 {
                    in_subject -= 1;
                }
            }
            Ok(Event::Text(t)) => {
                if in_name_id > 0 {
                    let s = t
                        .xml_content(quick_xml::XmlVersion::default())
                        .map_err(|e| SamlError::XmlMalformed(format!("nameid text: {e}")))?;
                    out.push_str(&s);
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(SamlError::XmlMalformed(format!("name_id: {e}")));
            }
            _ => {}
        }
        buf.clear();
    }
    if out.is_empty() {
        return Err(SamlError::XmlMalformed("Subject/NameID missing".into()));
    }
    Ok(out)
}

/// Parse `<AttributeStatement>/<Attribute>` into a name -> values map.
/// Multi-valued attributes (multiple `<AttributeValue>` children) are
/// preserved in document order.
fn parse_attribute_statement(xml: &str) -> HashMap<String, Vec<String>> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    let mut in_stmt: u32 = 0;
    let mut current_name: Option<String> = None;
    let mut in_value: u32 = 0;
    let mut value_buf = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e) | Event::Empty(e)) => {
                let ln = local_name(e.name().as_ref()).to_vec();
                if ln == b"AttributeStatement" {
                    in_stmt = in_stmt.saturating_add(1);
                } else if ln == b"Attribute" && in_stmt > 0 {
                    current_name = e
                        .attributes()
                        .flatten()
                        .find(|a| local_name(a.key.as_ref()) == b"Name")
                        .and_then(|a| {
                            a.decoded_and_normalized_value(
                                quick_xml::XmlVersion::default(),
                                reader.decoder(),
                            )
                            .ok()
                            .map(|v| v.to_string())
                        });
                } else if ln == b"AttributeValue" && in_stmt > 0 {
                    in_value = in_value.saturating_add(1);
                    value_buf.clear();
                }
            }
            Ok(Event::End(e)) => {
                let ln = local_name(e.name().as_ref()).to_vec();
                if ln == b"AttributeValue" && in_value > 0 {
                    in_value -= 1;
                    if in_value == 0 {
                        if let Some(name) = current_name.as_ref() {
                            out.entry(name.clone()).or_default().push(value_buf.clone());
                        }
                        value_buf.clear();
                    }
                } else if ln == b"Attribute" && in_stmt > 0 {
                    current_name = None;
                } else if ln == b"AttributeStatement" && in_stmt > 0 {
                    in_stmt -= 1;
                }
            }
            Ok(Event::Text(t)) => {
                if in_value > 0 {
                    if let Ok(s) = t.xml_content(quick_xml::XmlVersion::default()) {
                        value_buf.push_str(&s);
                    }
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    out
}

/// Parse `<AuthnStatement>/@SessionIndex`, if present.
fn parse_session_index(xml: &str) -> Option<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e) | Event::Empty(e)) => {
                if local_name(e.name().as_ref()) == b"AuthnStatement" {
                    for attr in e.attributes().flatten() {
                        if local_name(attr.key.as_ref()) == b"SessionIndex" {
                            if let Ok(v) = attr.decoded_and_normalized_value(
                                quick_xml::XmlVersion::default(),
                                reader.decoder(),
                            ) {
                                return Some(v.to_string());
                            }
                        }
                    }
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    None
}

// ------------------------------------------------------------------
// `OffsetDateTime` helpers for tests that don't want the `time` import.
// ------------------------------------------------------------------

impl ParsedAssertion {
    /// Convenience: parse an xs:dateTime string into the same format
    /// callers can compare against `not_on_or_after`. Returned for
    /// downstream use in adapters that prefer raw `OffsetDateTime`.
    pub fn parse_xs_datetime(s: &str) -> Result<OffsetDateTime, SamlError> {
        parse_xs_datetime(s)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ---- Pure helpers (no fixtures needed) ------------------------

    #[test]
    fn reject_multiple_assertions_passes_single() {
        let xml = "<r><Assertion>x</Assertion></r>";
        reject_multiple_assertions(xml).unwrap();
    }

    #[test]
    fn reject_multiple_assertions_fails_double() {
        let xml = "<r><Assertion>x</Assertion><Assertion>y</Assertion></r>";
        assert_eq!(
            reject_multiple_assertions(xml),
            Err(SamlError::MultipleAssertions)
        );
    }

    #[test]
    fn reject_multiple_assertions_handles_namespace_prefix() {
        let xml = "<r xmlns:saml=\"x\"><saml:Assertion>x</saml:Assertion>\
<saml:Assertion>y</saml:Assertion></r>";
        assert_eq!(
            reject_multiple_assertions(xml),
            Err(SamlError::MultipleAssertions)
        );
    }

    #[test]
    fn extract_element_slice_returns_inclusive_range() {
        let xml = "<r><A>hello</A></r>";
        let s = extract_element_slice(xml, "A").unwrap();
        assert_eq!(s, "<A>hello</A>");
    }

    #[test]
    fn parse_xs_datetime_parses_z_form() {
        let dt = parse_xs_datetime("2026-01-01T00:00:00Z").unwrap();
        assert_eq!(dt.year(), 2026);
    }

    #[test]
    fn enforce_time_window_rejects_expired() {
        let past = OffsetDateTime::now_utc() - time::Duration::hours(1);
        let cond = Conditions {
            not_before: None,
            not_on_or_after: past,
            audiences: vec![],
        };
        assert_eq!(
            enforce_time_window(&cond, Duration::from_secs(60)),
            Err(SamlError::TimeWindow)
        );
    }

    #[test]
    fn enforce_time_window_accepts_future_not_on_or_after() {
        let future = OffsetDateTime::now_utc() + time::Duration::hours(1);
        let cond = Conditions {
            not_before: None,
            not_on_or_after: future,
            audiences: vec![],
        };
        enforce_time_window(&cond, Duration::from_secs(60)).unwrap();
    }

    #[test]
    fn enforce_time_window_skew_allows_just_expired() {
        // NotOnOrAfter is 30s in the past, but skew is 120s — accept.
        let past = OffsetDateTime::now_utc() - time::Duration::seconds(30);
        let cond = Conditions {
            not_before: None,
            not_on_or_after: past,
            audiences: vec![],
        };
        enforce_time_window(&cond, Duration::from_secs(120)).unwrap();
    }

    // ---- Signed-fixture tests live in tests/saml_verify.rs --------
}
