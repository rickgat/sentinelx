//! TOP5-#1-PHASE-2A: factory that constructs a
//! [`sx_xmlsec::XmlDsigVerifier`] of the policy-declared shape.
//!
//! The factory consumes [`sx_config::schema::SamlConfig::xmldsig`] (a
//! [`XmlDsigVerifierKind`] enum) and returns a
//! `Box<dyn XmlDsigVerifier>` wired up for the requested mode:
//!
//! * [`XmlDsigVerifierKind::HandRolled`] → [`HandRolledVerifier`]
//!   wrapper around the existing `response::verify_assertion` call.
//!   No new behaviour; this is the PHASE-2B-cutover-friendly view of
//!   today's production verifier.
//! * [`XmlDsigVerifierKind::Shadow`] → [`DualVerifier`] with
//!   `HandRolledVerifier` as primary (authoritative) and the
//!   layered libxmlsec1 verifier as secondary (observation-only).
//!   Mismatches are surfaced via the
//!   `xmldsig_shadow_mismatch_total` Prometheus counter and the
//!   `xmldsig.shadow.mismatch.*` tracing events emitted by
//!   `DualVerifier::verify`.
//! * [`XmlDsigVerifierKind::XmlSec1`] →
//!   [`LayeredVerifier<XmlSec1Verifier>`] only. The gate closure is
//!   the same `make_preparse_gates_closure()` PHASE-1C wired so
//!   defence-in-depth byte-level gates still run before any C code.
//!
//! ## Dormant in PHASE-2A
//!
//! **The production path in `response::verify_assertion` does not
//! call this factory.** PHASE-2A introduces the factory + the config
//! field that selects between modes, but the production hand-rolled
//! call site remains untouched. PHASE-2B's gate cutover will be the
//! point where `acs::process_acs_response` (or its equivalent) starts
//! routing through `build_verifier`. Until then this module exists
//! purely so the shape of the eventual cutover can be reviewed in
//! isolation — and so the three integration tests below can assert
//! that the factory wires the right `XmlDsigVerifier::name()` for
//! each mode.
//!
//! ## On the `HandRolledVerifier` adapter shape
//!
//! The existing hand-rolled implementation in `response.rs` exposes
//! [`super::response::verify_assertion`] with the signature:
//!
//! ```text
//! pub fn verify_assertion(
//!     sp_config: &SamlSpConfig,         // sx-iam's SamlSpConfig
//!     xml: &str,
//!     expected_audience: &str,
//!     clock_skew: Duration,
//! ) -> Result<ParsedAssertion, SamlError>;
//! ```
//!
//! The trait wants:
//!
//! ```text
//! fn verify(
//!     &self,
//!     xml: &[u8],
//!     cfg: &sx_xmlsec::SamlSpConfig,    // placeholder type with a subset of fields
//!     audience: &str,
//!     skew: Duration,
//! ) -> Result<VerifyOutcome, XmlSecError>;
//! ```
//!
//! Two shape mismatches the adapter resolves:
//!
//! 1. **`&[u8]` → `&str`.** SAML 2.0's HTTP bindings mandate UTF-8;
//!    non-UTF-8 input is rejected as
//!    [`XmlSecError::XmlParseFailed("non-utf8 SAML body")`]. This is
//!    a tighter mapping than `pre_parse_gates` (which uses
//!    `PreParseRejected`) because at the hand-rolled adapter layer
//!    we are NOT running the byte-level pre-parse gates — the
//!    hand-rolled `verify_assertion` does that internally — so the
//!    failure is an XML-layer parse failure, not a gate rejection.
//! 2. **`sx_xmlsec::SamlSpConfig` ↔ `sx_iam::SamlSpConfig`.**
//!    PHASE-1A deliberately defined `sx_xmlsec::SamlSpConfig` as a
//!    placeholder with the same field shape MINUS `signing_algo`
//!    (which is a `sx-iam`-internal `SamlSigningAlgo` enum that
//!    `sx-xmlsec` cannot import without creating a dep cycle). The
//!    adapter reconstructs the `sx-iam` `SamlSpConfig` from the
//!    placeholder by defaulting `signing_algo` to `Sha256` — which
//!    is the PHASE-2A scope choice. **This is a known constraint
//!    PHASE-2B will resolve** by extracting a shared types crate
//!    (`sx-xmlsec-types`) or by adopting the
//!    `sx_iam::SamlSpConfig` as the canonical type and removing the
//!    placeholder. For PHASE-2A the choice does not matter because
//!    the factory output is not yet on the production path.
//!
//! [`XmlDsigVerifierKind`]: sx_config::schema::XmlDsigVerifierKind
//! [`HandRolledVerifier`]: crate::service::saml::verifier_factory::HandRolledVerifier
//! [`DualVerifier`]: sx_xmlsec::DualVerifier
//! [`LayeredVerifier<XmlSec1Verifier>`]: sx_xmlsec::LayeredVerifier

use std::time::Duration;

use sx_config::schema::{SamlConfig, XmlDsigVerifierKind};
use sx_xmlsec::{
    DualVerifier, LayeredVerifier, SamlSpConfig as XmlSecSamlSpConfig, VerifierMode, VerifyOutcome,
    XmlDsigVerifier, XmlSec1Verifier, XmlSecError,
};

use super::make_preparse_gates_closure;
use super::response::verify_assertion;
use super::{SamlError, SamlSigningAlgo, SamlSpConfig as IamSamlSpConfig};

/// Hand-rolled `XMLDSig` verifier adapter for the PHASE-2A shadow-mode
/// dispatcher.
///
/// Wraps the existing [`super::response::verify_assertion`] in the
/// [`XmlDsigVerifier`] surface so the
/// [`DualVerifier`](sx_xmlsec::DualVerifier) can dispatch it alongside
/// the libxmlsec1-backed implementation.
///
/// See the module-level docs for the adapter contract — in
/// particular the `SamlSpConfig` placeholder vs canonical-type
/// conversion and the `&[u8]` vs `&str` UTF-8 mapping.
#[derive(Debug, Default)]
pub struct HandRolledVerifier;

impl HandRolledVerifier {
    /// Construct a new hand-rolled adapter. Stateless — provided as
    /// a const for parity with `XmlSec1Verifier::new` (and for the
    /// rare future case where the hand-rolled side needs to hold a
    /// process-local resource like a parser arena).
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl XmlDsigVerifier for HandRolledVerifier {
    fn verify(
        &self,
        xml: &[u8],
        cfg: &XmlSecSamlSpConfig,
        audience: &str,
        skew: Duration,
    ) -> Result<VerifyOutcome, XmlSecError> {
        // SAML 2.0 HTTP bindings mandate UTF-8. Reject non-UTF-8 at
        // the adapter boundary with `XmlParseFailed` (not
        // `PreParseRejected` — the gate layer is NOT the boundary
        // here, the XML parser is).
        let xml_str = std::str::from_utf8(xml)
            .map_err(|e| XmlSecError::XmlParseFailed(format!("non-utf8 SAML body: {e}")))?;

        // Translate the `sx-xmlsec` placeholder SamlSpConfig into the
        // canonical `sx-iam` SamlSpConfig. PHASE-2A scope-choice:
        // `signing_algo` defaults to Sha256 since the placeholder
        // does not carry it. PHASE-2B will collapse this conversion
        // into a shared types crate (see module docs).
        let iam_cfg = IamSamlSpConfig {
            entity_id: cfg.entity_id.clone(),
            sso_url: cfg.sso_url.clone(),
            slo_url: cfg.slo_url.clone(),
            x509_cert_pem: cfg.x509_cert_pem.clone(),
            signing_algo: SamlSigningAlgo::Sha256,
        };

        // Delegate to the existing production verifier. Map
        // SamlError → XmlSecError so the shadow-mode classifier in
        // `DualVerifier` can compare variants without taking a
        // dependency on `sx-iam`.
        match verify_assertion(&iam_cfg, xml_str, audience, skew) {
            Ok(_parsed) => Ok(VerifyOutcome {
                verifier_name: "handrolled",
                // The hand-rolled verifier returning Ok implies a
                // successful cryptographic verdict; surface that as
                // `signature_valid = true` for the shadow-mode
                // classifier.
                signature_valid: true,
                signed_node_xpath: None,
                name_id: String::new(),
                not_on_or_after_unix: None,
            }),
            Err(e) => Err(map_saml_error(e)),
        }
    }

    fn name(&self) -> &'static str {
        // Stable lowercase snake_case — matches the
        // `XmlSec1Verifier::name()` convention and is consumed by
        // the shadow-mode `DualVerifier` classifier as a label.
        "handrolled"
    }
}

/// Map [`SamlError`] → [`XmlSecError`] so the shadow-mode comparator
/// sees a uniform error surface across the hand-rolled and FFI
/// verifiers. The mapping is coarse on purpose — see the module
/// docs and the senior plan §2.2 Class C bullet on why variant-level
/// granularity is deliberately collapsed in PHASE-2A.
fn map_saml_error(err: SamlError) -> XmlSecError {
    match err {
        SamlError::XmlMalformed(msg) => XmlSecError::XmlParseFailed(msg),
        SamlError::SignatureInvalid => XmlSecError::SignatureInvalid,
        SamlError::AudienceMismatch => XmlSecError::VerifyFailed("audience mismatch".to_owned()),
        SamlError::TimeWindow => XmlSecError::VerifyFailed("time window failed".to_owned()),
        SamlError::ReplayAssertion => XmlSecError::VerifyFailed("replay assertion".to_owned()),
        SamlError::MultipleAssertions => {
            XmlSecError::PreParseRejected("multiple assertions (XSW)".to_owned())
        }
    }
}

/// Construct an [`XmlDsigVerifier`] of the shape declared in
/// `cfg.xmldsig.verifier`.
///
/// Returns a `Box<dyn XmlDsigVerifier>` so the factory output can
/// be held in a single field regardless of the underlying impl.
///
/// # Errors
///
/// Returns [`XmlSecError::InitFailed`] when [`XmlSec1Verifier::new`]
/// fails on a `Shadow` or `XmlSec1` mode (typically because the
/// `xmlsec1` Cargo feature is on but the libxmlsec1 system package
/// is missing). [`XmlDsigVerifierKind::HandRolled`] cannot fail to
/// construct — it is a unit struct.
///
/// ## Dormant
///
/// PHASE-2A does NOT call this from the production path. PHASE-2B's
/// cutover wires it into the SAML SP `acs::process_acs_response`
/// flow.
pub fn build_verifier(cfg: &SamlConfig) -> Result<Box<dyn XmlDsigVerifier>, XmlSecError> {
    match cfg.xmldsig.verifier {
        XmlDsigVerifierKind::HandRolled => Ok(Box::new(HandRolledVerifier::new())),
        XmlDsigVerifierKind::Shadow => {
            // Primary = hand-rolled (authoritative). Secondary =
            // gate-layered libxmlsec1 (observation). The gate
            // closure is the same `pre_parse_gates`-derived closure
            // PHASE-1C exposed.
            let xmlsec1 = XmlSec1Verifier::new()?;
            let layered = LayeredVerifier::new(xmlsec1, make_preparse_gates_closure());
            let dual = DualVerifier::new(
                HandRolledVerifier::new(),
                layered,
                VerifierMode::PrimaryAuthoritative,
            );
            Ok(Box::new(dual))
        }
        XmlDsigVerifierKind::XmlSec1 => {
            // Gate-layered libxmlsec1 only. The
            // `LayeredVerifier::name()` impl is TRANSPARENT — it
            // returns the inner verifier's name — so the metric +
            // log labels match what the post-cutover production
            // sees. The factory tests rely on this transparency.
            let xmlsec1 = XmlSec1Verifier::new()?;
            let layered = LayeredVerifier::new(xmlsec1, make_preparse_gates_closure());
            Ok(Box::new(layered))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use sx_config::schema::XmlDsigConfig;

    fn cfg_with(kind: XmlDsigVerifierKind) -> SamlConfig {
        SamlConfig {
            xmldsig: XmlDsigConfig { verifier: kind },
            ..SamlConfig::default()
        }
    }

    #[test]
    fn build_handrolled_returns_handrolled_named() {
        let cfg = cfg_with(XmlDsigVerifierKind::HandRolled);
        let v = build_verifier(&cfg).expect("handrolled cannot fail to construct");
        assert_eq!(v.name(), "handrolled");
    }

    #[test]
    fn build_shadow_returns_dual_named() {
        // Under the default (stub-no-xmlsec1) build,
        // `XmlSec1Verifier::new()` succeeds — it just returns a
        // verifier whose `verify` is a no-op stub. PHASE-2A's
        // factory shape is independent of whether the FFI feature
        // is on.
        let cfg = cfg_with(XmlDsigVerifierKind::Shadow);
        let v = build_verifier(&cfg).expect("shadow build under default features");
        // `DualVerifier::name()` is `"dual:shadow"` — the
        // `dual:` prefix is the discriminator. We assert
        // `starts_with("dual:")` rather than the full literal so a
        // future PHASE-2B refinement (e.g. `dual:shadow:authoritative`)
        // does not break this contract test.
        assert!(
            v.name().starts_with("dual:"),
            "expected DualVerifier name with 'dual:' prefix, got {}",
            v.name(),
        );
    }

    #[test]
    fn build_xmlsec1_returns_layered_named() {
        let cfg = cfg_with(XmlDsigVerifierKind::XmlSec1);
        let v = build_verifier(&cfg).expect("xmlsec1 build under default features");
        // LayeredVerifier is TRANSPARENT — it reports the inner
        // verifier's name. That's `XmlSec1Verifier::name() == "xmlsec1"`.
        // PHASE-2B's metric labels rely on this so the post-cutover
        // stream is comparable to the shadow-window stream.
        assert_eq!(v.name(), "xmlsec1");
    }
}
