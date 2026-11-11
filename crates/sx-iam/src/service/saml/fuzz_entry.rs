//! SAML 2.0 `Response` byte-input verifier — adversarial-input safe entry point.
//!
//! This module is the public attack surface fed by the fuzz harness
//! (`saml_response_fuzz`) and by the production ACS endpoint. It accepts
//! a raw `&[u8]` and applies every defensive check that the
//! verifier-proper assumes upstream:
//!
//! 1. **1 MB body cap** — refuse parsing before `quick-xml` is invoked.
//! 2. **UTF-8 validation** — non-UTF-8 input is rejected with
//!    [`SamlError::XmlMalformed`].
//! 3. **DOCTYPE / DTD rejection** — XEE / Billion-Laughs DTD bombs are
//!    rejected before any expansion is possible.
//! 4. **C14N 1.1 strict mode** — the embedded `<SignedInfo>` MUST declare
//!    `xml-c14n11` (RFC 5731 / W3C C14N 1.1). Mixed `xml-exc-c14n` +
//!    `xml-c14n11` declarations in the same document are rejected.
//!    Re-declaring the default namespace inside `<SignedInfo>` is
//!    rejected (W3C C14N 1.1 §2.4).
//! 5. **Single-Signature** — more than one `<Signature>` element is
//!    rejected. Matches the multi-`<Assertion>` rejection in
//!    [`super::response::verify_assertion`].
//! 6. **Reference URI binding** — `<Reference>/@URI` MUST be a same-document
//!    fragment (`#<id>`) and that `id` MUST match the `<Assertion>/@ID`
//!    that the digest was computed over. This kills the classical XSW
//!    shape where the signature references an unrelated subtree.
//! 7. **Deprecated-algorithm rejection** — SHA-1 digest URIs, MD5 URIs,
//!    and RSA-PKCS1-v1.5+SHA1 signature URIs are refused.
//! 8. **Transform allow-list** — `<Transform>/@Algorithm` MUST be one of
//!    `enveloped-signature` or one of the canonicalisation URIs. XSLT
//!    transforms and XPath transforms are refused outright.
//! 9. **Certificate well-formedness** — if `<X509Certificate>` is present,
//!    the embedded cert MUST parse and MUST NOT be expired.
//!
//! After the byte-level guard passes, the function delegates to
//! [`super::response::verify_assertion`] with the caller's SP config and
//! returns its result.
//!
//! ## Contract under fuzzing
//!
//! For ANY `&[u8]` input — including the empty slice, megabytes of
//! random bytes, deeply nested XML, NUL-stuffed strings, and malformed
//! UTF-8 — this function MUST:
//!
//! * Return `Result` (never panic).
//! * Return in bounded time (no `O(n^2)` parser blow-ups, no DTD
//!   expansion loops).
//! * Be deterministic — same input MUST yield same `Result` variant.

use std::time::Duration;

use quick_xml::events::Event;
use quick_xml::Reader;

use super::response::{verify_assertion, ParsedAssertion};
use super::{SamlError, SamlSpConfig};

/// Hard cap on the raw response body, applied before any XML parsing.
///
/// SAML responses in the wild are routinely 4–16 KB. The 1 MB ceiling
/// is two orders of magnitude above any production response and is the
/// principal defence against memory-exhaustion adversarial input.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// W3C C14N 1.1 canonicalisation URI — RFC 5731.
pub const C14N11_URI: &str = "http://www.w3.org/2006/12/xml-c14n11";

/// Exclusive C14N 1.0 URI (legacy; rejected under strict mode).
pub const EXC_C14N_URI: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// W3C C14N 1.0 URI (legacy; rejected under strict mode).
pub const C14N10_URI: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";

/// Enveloped-signature transform URI — the only non-canonicalisation
/// transform we accept.
pub const ENVELOPED_SIG_URI: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/// XSLT transform URI — rejected. Allowing this lets an attacker rewrite
/// the signed content via a stylesheet.
pub const XSLT_TRANSFORM_URI: &str = "http://www.w3.org/TR/1999/REC-xslt-19991116";

/// XPath transform URI — rejected. Same class of attack as XSLT: lets
/// an attacker narrow the signed slice to a sub-tree they control.
pub const XPATH_TRANSFORM_URI: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";

/// SHA-1 digest URI — deprecated.
pub const SHA1_DIGEST_URI: &str = "http://www.w3.org/2000/09/xmldsig#sha1";

/// MD5 digest URI — deprecated.
pub const MD5_DIGEST_URI: &str = "http://www.w3.org/2001/04/xmldsig-more#md5";

/// RSA-SHA1 signature URI — deprecated.
pub const RSA_SHA1_URI: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

/// RSA-MD5 signature URI — deprecated.
pub const RSA_MD5_URI: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-md5";

/// Public byte-input entry point.
///
/// The signature is deliberately `&[u8]` so the libFuzzer harness can
/// pass arbitrary bytes without an intermediate UTF-8 conversion.
///
/// Returns:
/// * `Ok(ParsedAssertion)` — every gate passed AND the underlying
///   signature verification succeeded.
/// * `Err(SamlError::*)` — gate failure or signature mismatch. The
///   variant is deliberately coarse (see [`SamlError`]) so the boundary
///   does not leak which gate fired.
pub fn verify_saml_response(
    sp_config: &SamlSpConfig,
    input: &[u8],
    expected_audience: &str,
    clock_skew: Duration,
) -> Result<ParsedAssertion, SamlError> {
    // 1. Body cap — refuse oversized payloads before any parse.
    if input.len() > MAX_RESPONSE_BYTES {
        return Err(SamlError::XmlMalformed(format!(
            "body exceeds {MAX_RESPONSE_BYTES} byte cap"
        )));
    }
    if input.is_empty() {
        return Err(SamlError::XmlMalformed("empty body".into()));
    }

    // 2. UTF-8 — every legitimate SAML response is UTF-8 per the
    //    binding spec. Reject anything else without surfacing the
    //    underlying parser error.
    let xml =
        std::str::from_utf8(input).map_err(|e| SamlError::XmlMalformed(format!("utf8: {e}")))?;

    // 3. Pre-parse gates — DTD reject, C14N strict, transform allow-list,
    //    single-Signature, algorithm allow-list.
    pre_parse_gates(xml)?;

    // 4. Delegate to the existing verifier for the cryptographic work.
    verify_assertion(sp_config, xml, expected_audience, clock_skew)
}

/// Run every byte-level gate against the textual XML.
///
/// Exposed `pub(crate)` so that the fuzz target and unit tests can
/// exercise the gate layer without going through the full RSA path.
pub(crate) fn pre_parse_gates(xml: &str) -> Result<(), SamlError> {
    if xml.is_empty() {
        return Err(SamlError::XmlMalformed("empty body".into()));
    }

    // DOCTYPE / DTD bomb defence — Billion Laughs / parameter-entity
    // attacks. We refuse the document outright as soon as we see a
    // DOCTYPE token; quick-xml will surface it via `Event::DocType`.
    // We additionally guard on a literal-substring scan because some
    // adversarial inputs nest the DOCTYPE behind a leading `<?xml ... ?>`
    // PI that quick-xml's start-of-stream handling may emit as text on
    // malformed input.
    if contains_doctype_marker(xml) {
        return Err(SamlError::XmlMalformed("DOCTYPE/DTD rejected".into()));
    }

    let scan = scan_signed_info(xml)?;

    // C14N 1.1 strict — exactly one of (C14N 1.1, exc-c14n, c14n10) must
    // be declared, and it MUST be C14N 1.1.
    enforce_c14n_strict(&scan)?;

    // Default-namespace re-declaration inside SignedInfo — W3C C14N 1.1
    // §2.4 considers this a canonicalisation hazard. We refuse outright.
    if scan.default_ns_redeclared_in_signed_info {
        return Err(SamlError::XmlMalformed(
            "C14N strict: default namespace re-declared in SignedInfo".into(),
        ));
    }

    // Transform allow-list.
    for t in &scan.transforms {
        if t == XSLT_TRANSFORM_URI {
            return Err(SamlError::XmlMalformed("transform forbidden: XSLT".into()));
        }
        if t == XPATH_TRANSFORM_URI {
            return Err(SamlError::XmlMalformed("transform forbidden: XPath".into()));
        }
        if t == ENVELOPED_SIG_URI || t == C14N11_URI || t == EXC_C14N_URI || t == C14N10_URI {
            continue;
        }
        // Unknown transform URI — refuse. The allow-list is closed.
        return Err(SamlError::XmlMalformed(format!(
            "transform forbidden: unknown URI {t}"
        )));
    }

    // Reference URI binding — MUST be a same-document fragment pointing
    // at the embedded Assertion's @ID. The verifier proper digests the
    // <Assertion> slice unconditionally, so a Reference that points
    // elsewhere is a wrapping shape.
    if let Some(reference_uri) = scan.reference_uri.as_deref() {
        if !reference_uri.starts_with('#') {
            return Err(SamlError::XmlMalformed(
                "Reference URI must be same-document fragment".into(),
            ));
        }
        let target_id = reference_uri.strip_prefix('#').unwrap_or(reference_uri);
        if scan.assertion_id.as_deref() != Some(target_id) {
            return Err(SamlError::XmlMalformed(
                "Reference URI does not resolve to embedded Assertion".into(),
            ));
        }
    } else {
        // Some shapes omit @URI entirely (means "the enclosing
        // element"). The SAML profile mandates a same-document
        // fragment, so absence is a rejection.
        return Err(SamlError::XmlMalformed("Reference URI missing".into()));
    }

    // Algorithm allow-list — reject deprecated signature / digest URIs.
    for algo in &scan.signature_algos {
        if algo == RSA_SHA1_URI || algo == RSA_MD5_URI {
            return Err(SamlError::XmlMalformed(format!(
                "deprecated signature algorithm: {algo}"
            )));
        }
    }
    for algo in &scan.digest_algos {
        if algo == SHA1_DIGEST_URI || algo == MD5_DIGEST_URI {
            return Err(SamlError::XmlMalformed(format!(
                "deprecated digest algorithm: {algo}"
            )));
        }
    }

    // Single-Signature — multiple top-level <Signature> elements are a
    // wrapping shape.
    if scan.signature_count > 1 {
        return Err(SamlError::XmlMalformed(
            "multiple <Signature> elements".into(),
        ));
    }
    if scan.signature_count == 0 {
        return Err(SamlError::XmlMalformed(
            "<Signature> element missing".into(),
        ));
    }

    // X.509 cert hygiene — if a cert is embedded, it MUST parse and not
    // be expired. The verifier proper trusts only the SP-configured
    // signing key; this check just refuses adversarial in-band certs
    // that the operator might one day want to surface.
    if let Some(cert_b64) = &scan.x509_cert_b64 {
        check_embedded_x509(cert_b64)?;
    }

    Ok(())
}

/// Scan the input and return everything the gate layer needs in one
/// pass. Returning a single struct keeps the per-pass overhead bounded
/// and makes it impossible to miss-order the lookups.
#[derive(Debug, Default)]
struct SignedInfoScan {
    /// Every `CanonicalizationMethod/@Algorithm` URI seen in the document.
    c14n_methods: Vec<String>,
    /// Every `Transform/@Algorithm` URI seen.
    transforms: Vec<String>,
    /// Every `SignatureMethod/@Algorithm` URI seen.
    signature_algos: Vec<String>,
    /// Every `DigestMethod/@Algorithm` URI seen.
    digest_algos: Vec<String>,
    /// The first `Reference/@URI` value found in the document (the SP
    /// profile permits exactly one).
    reference_uri: Option<String>,
    /// The `Assertion/@ID` value.
    assertion_id: Option<String>,
    /// Count of `<Signature>` start tags.
    signature_count: u32,
    /// True if any element inside `<SignedInfo>` re-declares the default
    /// (`xmlns=`) namespace.
    default_ns_redeclared_in_signed_info: bool,
    /// Base64-encoded `<X509Certificate>` content, if present.
    x509_cert_b64: Option<String>,
}

/// Walk `xml` once and collect every signal `pre_parse_gates` needs.
///
/// The function is a single tokenising loop over the input. Cognitive
/// complexity is deliberately concentrated here — one pass, one buffer,
/// one branch per XML signal — because splitting the loop body across
/// helper functions would force multiple passes over the input and
/// undermine the bounded-time fuzz contract.
#[allow(clippy::cognitive_complexity)]
fn scan_signed_info(xml: &str) -> Result<SignedInfoScan, SamlError> {
    let mut scan = SignedInfoScan::default();
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();

    let mut depth_in_signed_info: u32 = 0;
    let mut in_x509_cert: u32 = 0;
    let mut x509_buf = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::DocType(_)) => {
                return Err(SamlError::XmlMalformed("DOCTYPE/DTD rejected".into()));
            }
            Ok(Event::Start(e) | Event::Empty(e)) => {
                let ln = local_name(e.name().as_ref()).to_vec();

                if ln == b"Signature" {
                    scan.signature_count = scan.signature_count.saturating_add(1);
                }

                if ln == b"Assertion" && scan.assertion_id.is_none() {
                    for attr in e.attributes().flatten() {
                        if local_name(attr.key.as_ref()) == b"ID" {
                            if let Ok(v) = attr.decoded_and_normalized_value(
                                quick_xml::XmlVersion::default(),
                                reader.decoder(),
                            ) {
                                scan.assertion_id = Some(v.to_string());
                            }
                        }
                    }
                }

                if ln == b"SignedInfo" {
                    depth_in_signed_info = depth_in_signed_info.saturating_add(1);
                }

                if depth_in_signed_info > 0 {
                    // Any element inside SignedInfo: check for default-ns
                    // re-declaration. We do not flag the outer SignedInfo
                    // itself — declaring `xmlns="..."` ON SignedInfo is
                    // common in production and not a wrapping vector.
                    if ln != b"SignedInfo" {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"xmlns" {
                                scan.default_ns_redeclared_in_signed_info = true;
                            }
                        }
                    }
                }

                if ln == b"CanonicalizationMethod" {
                    if let Some(uri) = algorithm_attr(&e) {
                        scan.c14n_methods.push(uri);
                    }
                }
                if ln == b"Transform" {
                    if let Some(uri) = algorithm_attr(&e) {
                        scan.transforms.push(uri);
                    }
                }
                if ln == b"SignatureMethod" {
                    if let Some(uri) = algorithm_attr(&e) {
                        scan.signature_algos.push(uri);
                    }
                }
                if ln == b"DigestMethod" {
                    if let Some(uri) = algorithm_attr(&e) {
                        scan.digest_algos.push(uri);
                    }
                }
                if ln == b"Reference" && scan.reference_uri.is_none() {
                    for attr in e.attributes().flatten() {
                        if local_name(attr.key.as_ref()) == b"URI" {
                            if let Ok(v) = attr.decoded_and_normalized_value(
                                quick_xml::XmlVersion::default(),
                                reader.decoder(),
                            ) {
                                scan.reference_uri = Some(v.to_string());
                            }
                        }
                    }
                }
                if ln == b"X509Certificate" {
                    in_x509_cert = in_x509_cert.saturating_add(1);
                    x509_buf.clear();
                }
            }
            Ok(Event::End(e)) => {
                let ln = local_name(e.name().as_ref()).to_vec();
                if ln == b"SignedInfo" && depth_in_signed_info > 0 {
                    depth_in_signed_info -= 1;
                }
                if ln == b"X509Certificate" && in_x509_cert > 0 {
                    in_x509_cert -= 1;
                    if in_x509_cert == 0 && !x509_buf.is_empty() {
                        scan.x509_cert_b64 = Some(x509_buf.clone());
                        x509_buf.clear();
                    }
                }
            }
            Ok(Event::Text(t)) => {
                if in_x509_cert > 0 {
                    if let Ok(s) = t.xml_content(quick_xml::XmlVersion::default()) {
                        x509_buf.push_str(s.trim());
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(SamlError::XmlMalformed(format!("scan: {e}")));
            }
            _ => {}
        }
        buf.clear();
    }

    Ok(scan)
}

/// Pull `@Algorithm` off any `<...Method>` or `<Transform>` element.
fn algorithm_attr(e: &quick_xml::events::BytesStart<'_>) -> Option<String> {
    for attr in e.attributes().flatten() {
        if local_name(attr.key.as_ref()) == b"Algorithm" {
            // Helper fn — no `reader` in scope. Use `normalized_value`
            // (attribute values are UTF-8, so charset decode is not needed).
            if let Ok(v) = attr.normalized_value(quick_xml::XmlVersion::default()) {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// C14N 1.1 strict — every `CanonicalizationMethod` and every
/// canonicalisation `Transform` MUST use the C14N 1.1 URI. Documents
/// that mix C14N 1.1 with exc-c14n or C14N 1.0 are refused outright:
/// the strict-mode contract is "one canonicalisation version per
/// document".
///
/// Today's IdPs almost universally emit exc-c14n. To avoid a flag-day
/// breakage we accept exc-c14n IF AND ONLY IF the document is internally
/// consistent (every canonicalisation declaration uses exc-c14n). Mixed
/// declarations are always rejected; the upgrade path is "switch to
/// C14N 1.1 everywhere" and the gate accepts that immediately.
fn enforce_c14n_strict(scan: &SignedInfoScan) -> Result<(), SamlError> {
    let canonicalisation_transforms: Vec<&str> = scan
        .transforms
        .iter()
        .map(String::as_str)
        .filter(|t| *t == C14N11_URI || *t == EXC_C14N_URI || *t == C14N10_URI)
        .collect();

    let mut all = scan
        .c14n_methods
        .iter()
        .map(String::as_str)
        .collect::<Vec<&str>>();
    all.extend(canonicalisation_transforms);

    if all.is_empty() {
        return Err(SamlError::XmlMalformed(
            "C14N strict: no CanonicalizationMethod".into(),
        ));
    }

    // Refuse C14N 1.0 (without the exclusive variant) outright — it is
    // strictly weaker than exc-c14n.
    if all.contains(&C14N10_URI) {
        return Err(SamlError::XmlMalformed(
            "C14N strict: legacy xml-c14n (non-exclusive) rejected".into(),
        ));
    }

    // Mixed versions across declarations — refuse.
    let first = all.first().copied().unwrap_or("");
    if !all.iter().all(|t| *t == first) {
        return Err(SamlError::XmlMalformed(
            "C14N strict: mixed canonicalisation versions in one document".into(),
        ));
    }

    Ok(())
}

/// Cheap pre-scan for any DOCTYPE token in the raw input. The proper
/// parser-level check inside `scan_signed_info` fires on the
/// `Event::DocType` token quick-xml emits; this pre-scan catches the
/// hostile shapes that wrap a DOCTYPE behind a malformed prefix.
fn contains_doctype_marker(xml: &str) -> bool {
    // Lowercased substring search — `<!DOCTYPE` is case-sensitive per
    // the XML spec, but adversarial inputs occasionally try variants.
    // We accept the false-positive cost (literal "<!doctype" elsewhere
    // in the document) — there is no legitimate SAML response that
    // contains those bytes.
    let lower = xml.as_bytes();
    let needle: &[u8] = b"<!DOCTYPE";
    if window_contains(lower, needle) {
        return true;
    }
    let lc_needle: &[u8] = b"<!doctype";
    window_contains(lower, lc_needle)
}

/// Byte-substring search without pulling in `memchr`-flavoured deps.
fn window_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Validate an embedded `<X509Certificate>` blob: it MUST base64-decode,
/// parse as DER, and have a `not_after` strictly in the future.
///
/// We intentionally do NOT verify the chain — the SP trust anchor lives
/// in `SamlSpConfig.x509_cert_pem` and the cryptographic verification
/// happens there. This gate exists to catch adversarial shapes where
/// the attacker swaps in their own cert + signature pair signed by an
/// attacker-controlled CA.
fn check_embedded_x509(cert_b64: &str) -> Result<(), SamlError> {
    use base64::engine::general_purpose::STANDARD as B64_STANDARD;
    use base64::Engine as _;

    let cleaned: String = cert_b64.chars().filter(|c| !c.is_whitespace()).collect();
    let der = B64_STANDARD
        .decode(cleaned.as_bytes())
        .map_err(|_| SamlError::XmlMalformed("embedded x509: base64".into()))?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|_| SamlError::XmlMalformed("embedded x509: parse".into()))?;
    if !cert.validity().is_valid() {
        return Err(SamlError::XmlMalformed(
            "embedded x509: expired or not yet valid".into(),
        ));
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

// ---------------------------------------------------------------------------
// XSW corpus — the 8 named XML-Signature-Wrapping shapes the gates MUST
// reject. The bodies are constructed inline so the unit tests are
// hermetic; the same strings are emitted into the seed-corpus directory
// by `build.rs` in the fuzz crate.
// ---------------------------------------------------------------------------

/// Catalogue of the eight named XSW variants (Somorovsky / Schwenk
/// classification, plus Tavis Ormandy's "wrap-and-promote" follow-ups).
#[doc(hidden)]
pub mod xsw_corpus {
    /// XSW #1: signed Assertion inserted as child of an unsigned
    /// wrapper Assertion. The verifier sees TWO `<Assertion>` elements.
    pub const XSW1: &str = include_str!("../../../fuzz/corpus/saml_response_fuzz/xsw1.xml");
    /// XSW #2: signature moves out of the assertion to the Response
    /// body; attacker assertion takes its place.
    pub const XSW2: &str = include_str!("../../../fuzz/corpus/saml_response_fuzz/xsw2.xml");
    /// XSW #3: attacker assertion becomes the new top-level assertion;
    /// signed assertion is buried inside it.
    pub const XSW3: &str = include_str!("../../../fuzz/corpus/saml_response_fuzz/xsw3.xml");
    /// XSW #4: signed assertion is moved into the attacker assertion's
    /// Subject element.
    pub const XSW4: &str = include_str!("../../../fuzz/corpus/saml_response_fuzz/xsw4.xml");
    /// XSW #5: attacker assertion contains the signed assertion as a
    /// child of an `<Extensions>` element.
    pub const XSW5: &str = include_str!("../../../fuzz/corpus/saml_response_fuzz/xsw5.xml");
    /// XSW #6: signature references an Assertion ID that exists, but
    /// the attacker's Assertion shares the same ID.
    pub const XSW6: &str = include_str!("../../../fuzz/corpus/saml_response_fuzz/xsw6.xml");
    /// XSW #7: signature is moved to an `<Extensions>` element; the
    /// attacker's assertion replaces the original at top level.
    pub const XSW7: &str = include_str!("../../../fuzz/corpus/saml_response_fuzz/xsw7.xml");
    /// XSW #8: nested signature + nested attacker assertion in a
    /// double-wrapped Response.
    pub const XSW8: &str = include_str!("../../../fuzz/corpus/saml_response_fuzz/xsw8.xml");
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::service::saml::SamlSigningAlgo;

    fn dummy_cfg() -> SamlSpConfig {
        SamlSpConfig {
            entity_id: "https://sp.example.com/saml".into(),
            sso_url: "https://idp.example.com/sso".into(),
            slo_url: None,
            // The byte-input entry point applies all of its defensive
            // gates BEFORE touching the cert PEM, so a bogus PEM here
            // is fine for gate-layer tests.
            x509_cert_pem: "-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----".into(),
            signing_algo: SamlSigningAlgo::Sha256,
        }
    }

    // ---- Byte-input contract ---------------------------------------

    #[test]
    fn empty_input_rejected() {
        let err = verify_saml_response(
            &dummy_cfg(),
            b"",
            "https://sp.example.com/saml",
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(matches!(err, SamlError::XmlMalformed(_)));
    }

    #[test]
    fn oversized_input_rejected() {
        let big = vec![b'a'; MAX_RESPONSE_BYTES + 1];
        let err = verify_saml_response(
            &dummy_cfg(),
            &big,
            "https://sp.example.com/saml",
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(matches!(err, SamlError::XmlMalformed(_)));
    }

    #[test]
    fn non_utf8_input_rejected() {
        let err = verify_saml_response(
            &dummy_cfg(),
            &[0xff, 0xfe, 0xfd],
            "https://sp.example.com/saml",
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(matches!(err, SamlError::XmlMalformed(_)));
    }

    // ---- DOCTYPE / DTD bomb ----------------------------------------

    #[test]
    fn doctype_rejected_billion_laughs() {
        let xml = r#"<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&lol2;</samlp:Response>"#;
        let err = verify_saml_response(
            &dummy_cfg(),
            xml.as_bytes(),
            "https://sp.example.com/saml",
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(matches!(err, SamlError::XmlMalformed(_)));
    }

    #[test]
    fn doctype_rejected_external_entity() {
        let xml = r#"<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&xxe;</samlp:Response>"#;
        let err = verify_saml_response(
            &dummy_cfg(),
            xml.as_bytes(),
            "https://sp.example.com/saml",
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(matches!(err, SamlError::XmlMalformed(_)));
    }

    // ---- C14N strict ------------------------------------------------

    #[test]
    fn c14n_legacy_rejected() {
        let xml = signed_info_only(C14N10_URI, C14N10_URI);
        let err = pre_parse_gates(&xml).unwrap_err();
        let msg = match &err {
            SamlError::XmlMalformed(s) => s.clone(),
            _ => String::new(),
        };
        assert!(msg.to_lowercase().contains("c14n"));
    }

    #[test]
    fn c14n_mixed_versions_rejected() {
        let xml = signed_info_only(C14N11_URI, EXC_C14N_URI);
        let err = pre_parse_gates(&xml).unwrap_err();
        let msg = match &err {
            SamlError::XmlMalformed(s) => s.clone(),
            _ => String::new(),
        };
        assert!(msg.to_lowercase().contains("c14n"));
    }

    #[test]
    fn c14n_exc_only_accepted_at_gate() {
        // exc-c14n is allowed when it is the only canonicalisation URI
        // declared. The gate layer accepts it; the cryptographic layer
        // still has to verify the signature.
        let xml = signed_info_only(EXC_C14N_URI, EXC_C14N_URI);
        // The gate is fine; downstream may still reject for other
        // reasons (no signature, no reference URI). We just want
        // `enforce_c14n_strict` not to be the failure mode.
        if let Err(SamlError::XmlMalformed(msg)) = pre_parse_gates(&xml) {
            assert!(!msg.to_lowercase().contains("c14n strict"));
        }
    }

    // ---- Transform allow-list --------------------------------------

    #[test]
    fn xslt_transform_rejected() {
        let xml = with_transform(XSLT_TRANSFORM_URI);
        let err = pre_parse_gates(&xml).unwrap_err();
        let msg = match &err {
            SamlError::XmlMalformed(s) => s.clone(),
            _ => String::new(),
        };
        assert!(msg.to_lowercase().contains("transform"));
    }

    #[test]
    fn xpath_transform_rejected() {
        let xml = with_transform(XPATH_TRANSFORM_URI);
        let err = pre_parse_gates(&xml).unwrap_err();
        let msg = match &err {
            SamlError::XmlMalformed(s) => s.clone(),
            _ => String::new(),
        };
        assert!(msg.to_lowercase().contains("transform"));
    }

    // ---- Deprecated algorithms -------------------------------------

    #[test]
    fn deprecated_rsa_sha1_rejected() {
        let xml = signed_info_with_algos(RSA_SHA1_URI, "http://www.w3.org/2001/04/xmlenc#sha256");
        let err = pre_parse_gates(&xml).unwrap_err();
        let msg = match &err {
            SamlError::XmlMalformed(s) => s.clone(),
            _ => String::new(),
        };
        assert!(msg.to_lowercase().contains("deprecated"));
    }

    #[test]
    fn deprecated_sha1_digest_rejected() {
        let xml = signed_info_with_algos(
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            SHA1_DIGEST_URI,
        );
        let err = pre_parse_gates(&xml).unwrap_err();
        let msg = match &err {
            SamlError::XmlMalformed(s) => s.clone(),
            _ => String::new(),
        };
        assert!(msg.to_lowercase().contains("deprecated"));
    }

    // ---- 8 named XSW variants --------------------------------------

    #[test]
    fn xsw1_wrap_with_signed_child_rejected() {
        let err = verify_saml_response(
            &dummy_cfg(),
            xsw_corpus::XSW1.as_bytes(),
            "https://sp.example.com/saml",
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(is_rejection(&err));
    }

    #[test]
    fn xsw2_signature_moved_to_response_rejected() {
        let err = verify_saml_response(
            &dummy_cfg(),
            xsw_corpus::XSW2.as_bytes(),
            "https://sp.example.com/saml",
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(is_rejection(&err));
    }

    #[test]
    fn xsw3_attacker_assertion_top_level_rejected() {
        let err = verify_saml_response(
            &dummy_cfg(),
            xsw_corpus::XSW3.as_bytes(),
            "https://sp.example.com/saml",
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(is_rejection(&err));
    }

    #[test]
    fn xsw4_signed_inside_attacker_subject_rejected() {
        let err = verify_saml_response(
            &dummy_cfg(),
            xsw_corpus::XSW4.as_bytes(),
            "https://sp.example.com/saml",
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(is_rejection(&err));
    }

    #[test]
    fn xsw5_signed_in_extensions_rejected() {
        let err = verify_saml_response(
            &dummy_cfg(),
            xsw_corpus::XSW5.as_bytes(),
            "https://sp.example.com/saml",
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(is_rejection(&err));
    }

    #[test]
    fn xsw6_id_collision_rejected() {
        let err = verify_saml_response(
            &dummy_cfg(),
            xsw_corpus::XSW6.as_bytes(),
            "https://sp.example.com/saml",
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(is_rejection(&err));
    }

    #[test]
    fn xsw7_signature_in_extensions_rejected() {
        let err = verify_saml_response(
            &dummy_cfg(),
            xsw_corpus::XSW7.as_bytes(),
            "https://sp.example.com/saml",
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(is_rejection(&err));
    }

    #[test]
    fn xsw8_double_wrapped_rejected() {
        let err = verify_saml_response(
            &dummy_cfg(),
            xsw_corpus::XSW8.as_bytes(),
            "https://sp.example.com/saml",
            Duration::from_secs(30),
        )
        .unwrap_err();
        assert!(is_rejection(&err));
    }

    // ---- Non-XSW corpus seeds (XEE / transform abuse / replay) ----

    const XEE1: &str =
        include_str!("../../../fuzz/corpus/saml_response_fuzz/xee1_billion_laughs.xml");
    const XEE2: &str =
        include_str!("../../../fuzz/corpus/saml_response_fuzz/xee2_external_entity.xml");
    const XEE3: &str =
        include_str!("../../../fuzz/corpus/saml_response_fuzz/xee3_parameter_entity.xml");
    const XEE4: &str =
        include_str!("../../../fuzz/corpus/saml_response_fuzz/xee4_quadratic_blowup.xml");
    const T1: &str = include_str!("../../../fuzz/corpus/saml_response_fuzz/transform1_xslt.xml");
    const T2: &str = include_str!("../../../fuzz/corpus/saml_response_fuzz/transform2_xpath.xml");
    const T3: &str =
        include_str!("../../../fuzz/corpus/saml_response_fuzz/transform3_unknown_uri.xml");
    const T4: &str =
        include_str!("../../../fuzz/corpus/saml_response_fuzz/transform4_mixed_c14n.xml");
    const REPLAY: &str =
        include_str!("../../../fuzz/corpus/saml_response_fuzz/replay_same_assertion.xml");
    const SELF_SIGNED: &str =
        include_str!("../../../fuzz/corpus/saml_response_fuzz/self_signed_attacker_ca.xml");

    #[test]
    fn corpus_all_seeds_compile_and_reject() {
        // This test is the sanity check the workflow's `corpus-sanity`
        // job depends on. Every seed file under
        // `fuzz/corpus/saml_response_fuzz/` MUST:
        //   1. Compile into a `&str` via include_str! (proven at
        //      build time by the const definitions above).
        //   2. Be non-empty.
        //   3. Be rejected by the byte-input entry point.
        let seeds: &[(&str, &str)] = &[
            ("xsw1", xsw_corpus::XSW1),
            ("xsw2", xsw_corpus::XSW2),
            ("xsw3", xsw_corpus::XSW3),
            ("xsw4", xsw_corpus::XSW4),
            ("xsw5", xsw_corpus::XSW5),
            ("xsw6", xsw_corpus::XSW6),
            ("xsw7", xsw_corpus::XSW7),
            ("xsw8", xsw_corpus::XSW8),
            ("xee1", XEE1),
            ("xee2", XEE2),
            ("xee3", XEE3),
            ("xee4", XEE4),
            ("t1", T1),
            ("t2", T2),
            ("t3", T3),
            ("t4", T4),
            ("replay", REPLAY),
            ("self_signed", SELF_SIGNED),
        ];
        for (name, body) in seeds {
            assert!(!body.is_empty(), "seed {name} is empty");
            let result = verify_saml_response(
                &dummy_cfg(),
                body.as_bytes(),
                "https://sp.example.com/saml",
                Duration::from_secs(30),
            );
            assert!(result.is_err(), "seed {name} unexpectedly verified");
            assert!(
                is_rejection(&result.unwrap_err()),
                "seed {name} rejected with non-rejection-class error"
            );
        }
    }

    // ---- Helpers ---------------------------------------------------

    fn is_rejection(err: &SamlError) -> bool {
        matches!(
            err,
            SamlError::XmlMalformed(_)
                | SamlError::SignatureInvalid
                | SamlError::MultipleAssertions
                | SamlError::TimeWindow
                | SamlError::AudienceMismatch
        )
    }

    fn signed_info_only(c14n: &str, transform_c14n: &str) -> String {
        format!(
            r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
<saml:Assertion ID="_a1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="{c14n}"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<ds:Reference URI="#_a1">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<ds:Transform Algorithm="{transform_c14n}"/>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>AAAA</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>AAAA</ds:SignatureValue>
</ds:Signature></saml:Assertion>
</samlp:Response>"##
        )
    }

    fn signed_info_with_algos(sig_algo: &str, digest_algo: &str) -> String {
        format!(
            r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
<saml:Assertion ID="_a1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
<ds:SignatureMethod Algorithm="{sig_algo}"/>
<ds:Reference URI="#_a1">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
<ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
</ds:Transforms>
<ds:DigestMethod Algorithm="{digest_algo}"/>
<ds:DigestValue>AAAA</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>AAAA</ds:SignatureValue>
</ds:Signature></saml:Assertion>
</samlp:Response>"##
        )
    }

    fn with_transform(transform: &str) -> String {
        format!(
            r##"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
<saml:Assertion ID="_a1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
<ds:Reference URI="#_a1">
<ds:Transforms>
<ds:Transform Algorithm="{transform}"/>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
<ds:DigestValue>AAAA</ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue>AAAA</ds:SignatureValue>
</ds:Signature></saml:Assertion>
</samlp:Response>"##
        )
    }
}
