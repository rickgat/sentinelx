//! PHASE-1C: adapter for `pre_parse_gates` → `sx-xmlsec`.
//!
//! This module bridges the byte-level [`super::fuzz_entry::pre_parse_gates`]
//! (XSW, XEE, transform-allow-list, Reference-URI binding,
//! deprecated-algorithm, single-Signature, embedded-X.509 hygiene)
//! onto the [`XmlDsigVerifier`](sx_xmlsec::XmlDsigVerifier) trait
//! surface — specifically the closure slot that
//! [`LayeredVerifier`](sx_xmlsec::LayeredVerifier) consumes.
//!
//! ## Why this lives in `sx-iam`
//!
//! The gate logic is owned by [`super::fuzz_entry::pre_parse_gates`].
//! Moving it down into `sx-xmlsec` would create a dependency cycle —
//! `sx-iam` will (post PHASE-2A) depend on `sx-xmlsec` to host the
//! shadow-mode dispatcher, so `sx-xmlsec` must stay free of any
//! `sx-iam` import. The seam is a closure: this module builds it,
//! `sx-xmlsec`'s [`LayeredVerifier`](sx_xmlsec::LayeredVerifier)
//! invokes it. Closure construction is the only place where the
//! `&str` + `SamlError` surface of `pre_parse_gates` is translated
//! into the `&[u8]` + `XmlSecError` surface the trait requires.
//!
//! ## Error mapping
//!
//! Both failure modes map to [`XmlSecError::PreParseRejected`] — the
//! variant added in PHASE-1C specifically so PHASE-2A's shadow-mode
//! audit-telemetry classifier can tell "gate rejected this" apart from
//! "libxml2 could not parse this" ([`XmlSecError::XmlParseFailed`]) or
//! "the cryptographic verifier rejected this"
//! ([`XmlSecError::SignatureInvalid`]). Splitting these categories
//! matters because the metric `xmldsig.shadow.gate_rejected` (PHASE-2A)
//! is the alarm bell for "fuzzer is hammering our structural defences",
//! whereas `xmldsig.shadow.parse_failed` indicates "fuzzer is poking
//! libxml2's grammar."
//!
//! ## Dormant by design
//!
//! PHASE-1C ships this adapter dormant. The production SAML SP path in
//! [`super::response::verify_assertion`] still calls
//! `pre_parse_gates` directly. PHASE-2A will wire the closure into a
//! `LayeredVerifier<XmlSec1Verifier>` instance and dispatch it in
//! shadow-mode alongside the hand-rolled verifier. PHASE-2B will flip
//! the production flag to `xmlsec1`. Until then, this module exists
//! only to make the closure-construction seam reviewable in isolation.

use sx_xmlsec::{GatesFn, XmlSecError};

use super::fuzz_entry::pre_parse_gates;

/// Build a fresh gate closure suitable for injection into
/// [`sx_xmlsec::LayeredVerifier::new`].
///
/// The returned closure:
///
/// 1. Decodes `&[u8]` → `&str` via `str::from_utf8`. Non-UTF-8 input
///    is rejected with [`XmlSecError::PreParseRejected`] carrying a
///    `"non-utf8 SAML body"` hint. SAML 2.0's HTTP bindings mandate
///    UTF-8 encoded XML; rejecting at the closure boundary keeps the
///    inner verifier's surface narrow.
/// 2. Delegates to [`pre_parse_gates`]. The byte-level gates run
///    exactly the same checks they run in the production
///    `verify_saml_response` byte-input entry point — DOCTYPE / DTD
///    rejection, C14N 1.1 strict mode, transform allow-list,
///    Reference-URI binding, deprecated-algorithm rejection,
///    single-Signature, embedded-X.509 hygiene. Any rejection is
///    mapped to [`XmlSecError::PreParseRejected`] with a short hint
///    (the inner `SamlError` message is included via `format!` — it
///    is already short and allocation-light).
///
/// The closure is `Send + Sync` so it can be invoked from PHASE-2A's
/// shadow-mode `async` handler, which runs the layered and
/// hand-rolled verifiers concurrently on the same input.
#[must_use]
pub fn make_preparse_gates_closure() -> GatesFn {
    Box::new(|xml: &[u8]| -> Result<(), XmlSecError> {
        // SAML 2.0 HTTP bindings mandate UTF-8. Reject non-UTF-8 at
        // the closure boundary so the inner verifier never sees it.
        let s = std::str::from_utf8(xml)
            .map_err(|e| XmlSecError::PreParseRejected(format!("non-utf8 SAML body: {e}")))?;

        // Delegate to the byte-level gates the production
        // `verify_saml_response` entry point already runs. Any
        // rejection becomes `PreParseRejected` so PHASE-2A's
        // shadow-mode classifier can attribute it to the gate layer
        // separately from libxml2 parse failures and signature
        // mismatches.
        pre_parse_gates(s)
            .map_err(|e| XmlSecError::PreParseRejected(format!("pre-parse gate rejected: {e}")))
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::service::saml::fuzz_entry::xsw_corpus;

    #[test]
    fn closure_rejects_xsw_payload() {
        // XSW #1 carries two `<Assertion>` elements — one signed
        // wrapper-Assertion and one attacker payload. The byte-level
        // gates reject this shape (multiple `<Signature>` elements,
        // Reference URI binding mismatch, etc.) and the closure maps
        // the rejection to `PreParseRejected`.
        let closure = make_preparse_gates_closure();
        let xml = xsw_corpus::XSW1.as_bytes();

        let result = closure(xml);
        match result {
            Err(XmlSecError::PreParseRejected(msg)) => {
                // The closure prefixes "pre-parse gate rejected:" to
                // the inner `SamlError` Display; assert the prefix so
                // we know the gate layer (not the UTF-8 check) fired.
                assert!(
                    msg.starts_with("pre-parse gate rejected:"),
                    "expected gate-rejection prefix, got {msg}",
                );
            }
            other => panic!("expected PreParseRejected for XSW1, got {other:?}"),
        }
    }

    #[test]
    fn closure_passes_valid_single_assertion() {
        // Minimal single-Assertion SAML Response with a single
        // <Signature>, C14N 1.1, RSA-SHA256, enveloped-signature
        // transform, and Reference URI `#_a1` matching the
        // Assertion's @ID. `pre_parse_gates` does NOT verify the
        // signature value, so a placeholder SignatureValue is fine.
        // The embedded <X509Certificate> is omitted — that path is
        // optional in the gates.
        let xml = r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
<saml:Assertion ID="_a1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<ds:Reference URI="#_a1">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>AAAA</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>AAAA</ds:SignatureValue>
</ds:Signature></saml:Assertion>
</samlp:Response>"##;

        let closure = make_preparse_gates_closure();
        let result = closure(xml.as_bytes());
        assert!(
            result.is_ok(),
            "valid single-Assertion SAML Response should pass the gate layer, got {result:?}",
        );
    }
}
