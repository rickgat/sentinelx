//! Error type for the `sx-xmlsec` FFI boundary.
//!
//! `XmlSecError` mirrors the shape of the SAML-layer `SamlError` in
//! `crates/sx-iam/src/service/saml/mod.rs` — variants are deliberately
//! coarse so an HTTP-layer caller cannot distinguish "verifier failed
//! because the cert mismatched" from "verifier failed because libxmlsec1
//! could not allocate a context" in a way that would help an attacker
//! probe the underlying implementation. PHASE-1B will map this error
//! type into `SamlError` at the `sx-iam` integration seam.

use thiserror::Error;

/// Errors produced by the `sx-xmlsec` FFI layer and its safe wrappers.
///
/// Variants:
///
/// * [`Self::InitFailed`] — `xmlInitParser` / `xmlSecInit` /
///   `xmlSecOpenSSLAppInit` / `xmlSecOpenSSLInit` returned a non-zero
///   status. Process-wide; non-recoverable without restart. Caller MUST
///   bail out instead of retrying.
/// * [`Self::KeysMngrFailed`] — `xmlSecKeysMngrCreate` returned NULL
///   (out-of-memory in libxmlsec1) or a subsequent cert-load operation
///   rejected the PEM material.
/// * [`Self::DsigCtxFailed`] — `xmlSecDSigCtxCreate` returned NULL.
/// * [`Self::VerifyFailed`] — wrapped a non-cryptographic verification
///   error from `xmlSecDSigCtxVerify` (NULL inputs, malformed signature
///   node). Distinct from [`Self::SignatureInvalid`] which means "the C
///   library completed the verification and the signature did not
///   match." String payload is a short, allocation-light description;
///   it does NOT include the offending XML.
/// * [`Self::SignatureInvalid`] — cryptographic verification failed:
///   `xmlSecDSigCtxVerify` succeeded mechanically but `ctx->status`
///   reported `xmlSecDSigStatusInvalid`. This is the "tampered or
///   wrong-cert" case.
/// * [`Self::XmlParseFailed`] — libxml2 returned NULL from
///   `xmlReadMemory` (XML was not well-formed). String payload is a
///   short description; the raw XML is NOT included.
/// * [`Self::PreParseRejected`] — PHASE-1C: one of the byte-level
///   pre-parse gates (DOCTYPE / DTD bomb, C14N strict, transform
///   allow-list, single-Signature, Reference URI binding, deprecated
///   algorithm, embedded-X.509 hygiene, XSW shape) refused the input
///   before the libxmlsec1 verifier was invoked. Separated from
///   [`Self::XmlParseFailed`] so the PHASE-2A audit-telemetry pipeline
///   can distinguish "fuzzer is poking the XML grammar (libxml2 said
///   no)" from "fuzzer hit signed-info shenanigans (our gates said no)".
///   String payload is a short, allocation-light hint; the raw XML is
///   NOT included.
///
/// All variants are `Clone` + `PartialEq` to align with `SamlError`'s
/// derives — required by the differential-shadow comparator in PHASE-2A
/// (we compare error variants between hand-rolled and FFI verifiers
/// without cloning the underlying XML).
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum XmlSecError {
    /// libxml2 / libxmlsec1 process-global initialisation failed.
    #[error("xmlsec: init failed")]
    InitFailed,

    /// Keys manager could not be created or could not load the supplied
    /// cert material.
    #[error("xmlsec: keys manager unavailable")]
    KeysMngrFailed,

    /// XMLDSig verification context could not be created.
    #[error("xmlsec: dsig context unavailable")]
    DsigCtxFailed,

    /// Non-cryptographic verification error. Payload is a short,
    /// allocation-light hint (e.g., `"missing Signature element"`);
    /// raw XML must NOT be embedded.
    #[error("xmlsec: verify failed: {0}")]
    VerifyFailed(String),

    /// Cryptographic verification failed — the signature did not match
    /// the cert / digest. This is the canonical "rejection" outcome for
    /// adversarial input and aligns 1:1 with `SamlError::SignatureInvalid`
    /// in `crates/sx-iam`.
    #[error("xmlsec: signature invalid")]
    SignatureInvalid,

    /// XML did not parse via libxml2's `xmlReadMemory`. Payload is a
    /// short hint; raw XML is NOT embedded.
    #[error("xmlsec: xml parse failed: {0}")]
    XmlParseFailed(String),

    /// PHASE-1C: one of the byte-level pre-parse gates rejected the
    /// input before the libxmlsec1 verifier was invoked. Distinct from
    /// [`Self::XmlParseFailed`] so audit telemetry can tell "the input
    /// is not well-formed XML" apart from "the input is well-formed but
    /// matches a known XSW / XEE / transform-abuse shape we refuse
    /// outright". Payload is a short hint (e.g. `"DOCTYPE/DTD
    /// rejected"`); raw XML is NOT embedded.
    #[error("xmlsec: pre-parse gate rejected: {0}")]
    PreParseRejected(String),
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::XmlSecError;

    #[test]
    fn variants_are_displayable_and_do_not_leak_payloads() {
        // The Display impl must not include the inner String for
        // `XmlParseFailed`-like variants beyond a short marker — guard
        // against accidental Debug-style format growth.
        let cases = [
            (XmlSecError::InitFailed, "xmlsec: init failed"),
            (
                XmlSecError::KeysMngrFailed,
                "xmlsec: keys manager unavailable",
            ),
            (
                XmlSecError::DsigCtxFailed,
                "xmlsec: dsig context unavailable",
            ),
            (XmlSecError::SignatureInvalid, "xmlsec: signature invalid"),
        ];
        for (err, want) in cases {
            assert_eq!(err.to_string(), want);
        }
    }

    #[test]
    fn verify_failed_carries_short_hint() {
        let e = XmlSecError::VerifyFailed("missing Signature".to_owned());
        assert_eq!(e.to_string(), "xmlsec: verify failed: missing Signature");
    }

    #[test]
    fn xml_parse_failed_carries_short_hint() {
        let e = XmlSecError::XmlParseFailed("unexpected eof".to_owned());
        assert_eq!(e.to_string(), "xmlsec: xml parse failed: unexpected eof");
    }

    #[test]
    fn errors_are_comparable_for_shadow_classifier() {
        // PHASE-2A's classifier compares variants; ensure PartialEq holds.
        assert_eq!(XmlSecError::SignatureInvalid, XmlSecError::SignatureInvalid);
        assert_ne!(XmlSecError::SignatureInvalid, XmlSecError::InitFailed);
    }

    #[test]
    fn pre_parse_rejected_carries_short_hint_and_is_distinct() {
        let e = XmlSecError::PreParseRejected("DOCTYPE/DTD rejected".to_owned());
        assert_eq!(
            e.to_string(),
            "xmlsec: pre-parse gate rejected: DOCTYPE/DTD rejected"
        );
        // Distinct from XmlParseFailed so the shadow-mode classifier
        // attributes gate rejections separately from libxml2 rejections.
        assert_ne!(
            XmlSecError::PreParseRejected("x".to_owned()),
            XmlSecError::XmlParseFailed("x".to_owned()),
        );
    }
}
