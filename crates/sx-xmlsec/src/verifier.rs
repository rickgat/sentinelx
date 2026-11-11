//! [`XmlDsigVerifier`] trait + PHASE-1B core verifier implementation.
//!
//! Per `docs/plans/top5-1-xmldsig-replacement.md` §2, the canonical
//! verifier-trait shape is:
//!
//! ```text
//! trait XmlDsigVerifier: Send + Sync {
//!     fn verify(&self, xml: &[u8], cfg: &SamlSpConfig, audience: &str, skew: Duration)
//!         -> Result<VerifyOutcome, XmlSecError>;
//!     fn name(&self) -> &'static str;
//! }
//! ```
//!
//! PHASE-1A defined the trait + a placeholder [`XmlSec1Verifier`] that
//! always returned `Err(XmlSecError::VerifyFailed("PHASE-1B"))`.
//! PHASE-1B (this phase) replaces the placeholder body with an actual
//! `xmlSecDSigCtxVerify` invocation using the FFI bindings declared in
//! [`crate::ffi`] and the RAII guards in [`crate::raii`]. The transform
//! allow-list ([`crate::transforms::apply_allow_list`]) runs once per
//! process before the first verify, refusing XSLT/XPath/XPath2.
//!
//! ### What this verifier DOES
//!
//! * Parse the input XML via `xmlReadMemory` with conservative parser
//!   flags (`XML_PARSE_NONET | XML_PARSE_NODICT`).
//! * Locate the `<Signature>` element via `xmlSecFindNode`.
//! * Load the IdP X.509 cert from `cfg.x509_cert_pem` into a fresh
//!   keys manager.
//! * Configure the global transform allow-list.
//! * Call `xmlSecDSigCtxVerify`. Inspect `ctx->status` for the
//!   cryptographic verdict.
//!
//! ### What this verifier does NOT do (yet)
//!
//! * Multi-Assertion XSW shape policing — still owned by
//!   `pre_parse_gates` in `sx-iam`. PHASE-1C will refactor those gates
//!   onto this surface.
//! * Audience / NotOnOrAfter / NotBefore evaluation — PHASE-1C.
//! * Signed-node identity comparison (Reference URI == Assertion@ID) —
//!   PHASE-1C. The current `VerifyOutcome::signed_node_xpath` is
//!   reserved for that wiring.
//!
//! ## SamlSpConfig: placeholder vs re-export
//!
//! The canonical `SamlSpConfig` struct lives in
//! `crates/sx-iam/src/service/saml/mod.rs` with shape
//! `{ entity_id, sso_url, slo_url, x509_cert_pem, signing_algo }`.
//! Re-exporting from `sx-iam` is the obvious move BUT would create a
//! cycle: `sx-iam` will ultimately depend on `sx-xmlsec` (post-PHASE-2A),
//! not the other way round.
//!
//! For PHASE-1A we define a minimal local placeholder with the same
//! field names so PHASE-1B can wire the FFI body without touching the
//! signature. The actual coupling between `sx-iam`'s `SamlSpConfig` and
//! this crate's view will be resolved in PHASE-2A by extracting a thin
//! `sx-xmlsec-types` crate (or by `sx-iam` depending on `sx-xmlsec` and
//! defining its own conversion). The placeholder here is INTENTIONALLY
//! kept minimal so the PHASE-2A author has a clean choice.

use std::time::Duration;

use crate::error::XmlSecError;

/// Placeholder for the SAML SP configuration the verifier consumes.
///
/// In PHASE-2A this becomes either:
///
/// 1. A re-export of `sx_iam::service::saml::SamlSpConfig` (via a new
///    `sx-xmlsec-types` crate the cycle-free boundary needs), OR
/// 2. A by-reference accept (`impl AsRef<SamlSpConfig>` style) so
///    `sx-iam` can keep ownership of the canonical struct.
///
/// The choice is deferred to PHASE-2A because it affects every
/// downstream call site and we want to make it once with full context.
#[derive(Debug, Clone)]
pub struct SamlSpConfig {
    /// SP's stable entity identifier; also the `Audience` value.
    pub entity_id: String,
    /// IdP's `SingleSignOnService` URL.
    pub sso_url: String,
    /// IdP's `SingleLogoutService` URL (optional — some IdPs do not
    /// support SLO).
    pub slo_url: Option<String>,
    /// IdP's X.509 signing certificate, PEM-encoded.
    pub x509_cert_pem: String,
}

/// Successful verification outcome.
///
/// PHASE-1B keeps this minimal — a handful of fields that downstream
/// code already extracts from `ParsedAssertion` in `sx-iam`. PHASE-1C
/// will grow this struct (attribute statements, session-index, etc.) in
/// lockstep with the pre-parse-gates refactor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyOutcome {
    /// The verifier implementation that produced this outcome — used by
    /// the PHASE-2A shadow-mode classifier to attribute Class A/B/C
    /// disagreements.
    pub verifier_name: &'static str,
    /// PHASE-1B: cryptographic verdict from `xmlSecDSigCtxVerify`. True
    /// iff `ctx->status == xmlSecDSigStatusSucceeded`. The value
    /// `false` is unreachable in the `Ok(VerifyOutcome)` branch —
    /// failure is reported as `Err(XmlSecError::SignatureInvalid)`. The
    /// field is retained so PHASE-2A's shadow-mode comparator has a
    /// stable boolean to log alongside the result variant.
    pub signature_valid: bool,
    /// PHASE-1C: XPath of the signed `<Assertion>` node (the consumed
    /// node), used by the gate layer to cross-check that the Reference
    /// URI inside `<Signature>` actually targets the same node the
    /// downstream code consumes. PHASE-1B leaves this `None`; the
    /// PHASE-1C refactor will populate it.
    pub signed_node_xpath: Option<String>,
    /// `NameID` extracted from the verified Assertion. Empty in
    /// PHASE-1B paths (PHASE-1C populates).
    pub name_id: String,
    /// `Conditions/@NotOnOrAfter` as a UNIX timestamp. `None` if the
    /// assertion did not carry one (rare; the SAML 2.0 core specifies
    /// it as required).
    pub not_on_or_after_unix: Option<i64>,
}

/// Trait every XMLDSig verifier in `sx-xmlsec` (and its callers) must
/// implement.
///
/// Implementors MUST be `Send + Sync` because shadow-mode (PHASE-2A)
/// invokes two verifiers concurrently on the same input, dispatched
/// from an `async` request handler.
pub trait XmlDsigVerifier: Send + Sync {
    /// Verify an XMLDSig-signed SAML payload.
    ///
    /// * `xml` — raw bytes of the SAML Response / Assertion.
    /// * `cfg` — SP configuration (IdP cert, entity_id, etc.).
    /// * `audience` — expected `Audience` value (typically equal to
    ///   `cfg.entity_id`; we keep them separate so the SP can verify
    ///   third-party-signed assertions where the audience is an
    ///   inner-tenant identifier).
    /// * `skew` — allowed clock-skew when evaluating `NotBefore` /
    ///   `NotOnOrAfter`.
    ///
    /// # Errors
    ///
    /// Returns the canonical [`XmlSecError`] variant on failure.
    /// PHASE-2A's shadow-mode classifier compares variants between
    /// hand-rolled and FFI verifiers; the contract is that both MUST
    /// return `Err` (any variant) for adversarial input — the variant
    /// itself need not match exactly.
    fn verify(
        &self,
        xml: &[u8],
        cfg: &SamlSpConfig,
        audience: &str,
        skew: Duration,
    ) -> Result<VerifyOutcome, XmlSecError>;

    /// Stable name of the verifier — used in tracing events and
    /// Prometheus labels by the shadow-mode wiring. Must be lowercase
    /// snake_case to match the existing tracing-field conventions in
    /// `crates/sx-telemetry`.
    fn name(&self) -> &'static str;
}

/// PHASE-1A placeholder libxmlsec1-backed verifier.
///
/// Currently `verify` always returns
/// `Err(XmlSecError::VerifyFailed("PHASE-1B"))`. PHASE-1B will replace
/// the body with a real `xmlSecDSigCtxVerify` call.
///
/// Construct via [`Self::new`]; it returns `Err(XmlSecError::InitFailed)`
/// if the library cannot be initialised (only when the `xmlsec1`
/// feature is enabled — see crate-level docs).
#[derive(Debug)]
pub struct XmlSec1Verifier {
    // Hold a `Library` handle when the FFI feature is on, so the
    // verifier owns the init lifetime. Under the default (feature OFF)
    // build, the struct still exists for trait-impl shape parity but
    // does not hold any FFI resources.
    #[cfg(feature = "xmlsec1")]
    _library: crate::init::Library,
}

impl XmlSec1Verifier {
    /// Construct a new verifier.
    ///
    /// # Errors
    ///
    /// When the `xmlsec1` feature is enabled, propagates
    /// [`XmlSecError::InitFailed`] from the library init. When the
    /// feature is OFF, always succeeds (the verifier is a pure
    /// placeholder).
    #[cfg(feature = "xmlsec1")]
    pub fn new() -> Result<Self, XmlSecError> {
        Ok(Self {
            _library: crate::init::Library::new()?,
        })
    }

    /// Construct a new verifier (stub-feature build).
    ///
    /// Returns `Result` to keep the signature stable across feature
    /// builds — the FFI build path can fail to init, the stub path
    /// cannot. PHASE-1B preserves this shape.
    #[cfg(not(feature = "xmlsec1"))]
    #[allow(clippy::unnecessary_wraps)]
    pub const fn new() -> Result<Self, XmlSecError> {
        Ok(Self {})
    }
}

impl XmlDsigVerifier for XmlSec1Verifier {
    #[cfg(feature = "xmlsec1")]
    fn verify(
        &self,
        xml: &[u8],
        cfg: &SamlSpConfig,
        _audience: &str,
        _skew: Duration,
    ) -> Result<VerifyOutcome, XmlSecError> {
        // PHASE-1B core verification body. Defence-in-depth note: the
        // gate-layer checks (`pre_parse_gates` in `sx-iam`) still run
        // BEFORE we get here in production — they reject XSW / XEE /
        // multi-Assertion shapes. This routine assumes well-formed
        // single-signature input and performs the cryptographic check.
        verify_xmlsec1(xml, cfg)
    }

    #[cfg(not(feature = "xmlsec1"))]
    fn verify(
        &self,
        _xml: &[u8],
        _cfg: &SamlSpConfig,
        _audience: &str,
        _skew: Duration,
    ) -> Result<VerifyOutcome, XmlSecError> {
        // Stub-feature build path. We deliberately keep returning a
        // deterministic error so PHASE-2A shadow-mode unit tests can
        // exercise dispatch without panicking when the FFI feature is
        // off. The string payload is "stub-no-xmlsec1" rather than the
        // original "PHASE-1B" marker because PHASE-1B IS landed —
        // the only reason verification returns Err here is that the
        // FFI feature is off, which is a build-config statement, not a
        // sprint-status statement.
        Err(XmlSecError::VerifyFailed("stub-no-xmlsec1".to_owned()))
    }

    fn name(&self) -> &'static str {
        "xmlsec1"
    }
}

/// PHASE-1B FFI verification body — only compiled when the `xmlsec1`
/// Cargo feature is on AND the build script linked libxmlsec1 +
/// libxml2.
///
/// The full happy-path lifecycle, with explicit cleanup ordering:
///
/// ```text
/// xmlReadMemory(xml)              -> OwnedDoc
///   xmlSecFindNode(root, ds:Signature) -> sig_node (borrow, no own)
///   xmlSecKeysMngrCreate              -> OwnedKeysMngr
///     xmlSecOpenSSLAppKeyLoadMemory(pem) -> OwnedKey
///     xmlSecKeysMngrAdoptKey(mngr, key)  -> ownership transfer
///                                          (OwnedKey::release; mngr drops it later)
///   apply_allow_list()                -> registry disable (once-per-process)
///   xmlSecDSigCtxCreate(mngr)         -> OwnedDsigCtx
///   xmlSecDSigCtxVerify(ctx, sig_node)
///   sx_xmlsec_dsig_ctx_status(ctx)    -> verdict
///   (drop ctx, mngr, doc in reverse order via RAII)
/// ```
///
/// Cleanup is RAII-driven so a `?`-early-return on any step releases
/// every prior allocation. The `OwnedKey::release` step at the
/// ownership-transfer line is the only place where `mem::forget` is
/// used; if `xmlSecKeysMngrAdoptKey` fails, the wrapper's normal `Drop`
/// reclaims the key.
// libxml2 parser options — conservative, no network, no entity
// expansion. The hex constants match the public `XML_PARSE_*` enum
// in libxml2's `parser.h`. `NONET` is 0x800, `NODICT` is 0x100. We
// deliberately do NOT set `NOENT` (which would expand external
// entities — XXE class).
#[cfg(feature = "xmlsec1")]
const XML_PARSE_NODICT: libc::c_int = 0x100;
#[cfg(feature = "xmlsec1")]
const XML_PARSE_NONET: libc::c_int = 0x800;

// Bound the input length to a c_int so the cast in verify_xmlsec1 is
// sound. 64 MiB is the absolute cap; the gate layer enforces a much
// smaller per-tenant ceiling.
#[cfg(feature = "xmlsec1")]
const MAX_INPUT: usize = 64 * 1024 * 1024;

// The XMLDSig namespace + signature-node name. Both must be
// NUL-terminated for `xmlSecFindNode`.
#[cfg(feature = "xmlsec1")]
const NODE_SIGNATURE: &[u8] = b"Signature\0";
#[cfg(feature = "xmlsec1")]
const NS_DSIG: &[u8] = b"http://www.w3.org/2000/09/xmldsig#\0";

#[cfg(feature = "xmlsec1")]
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn verify_xmlsec1(xml: &[u8], cfg: &SamlSpConfig) -> Result<VerifyOutcome, XmlSecError> {
    use crate::ffi::{
        sx_xmlsec_dsig_ctx_status, xmlReadMemory, xmlSecDSigCtxCreate, xmlSecDSigCtxVerify,
        xmlSecFindNode, xmlSecKeysMngrAdoptKey, xmlSecKeysMngrCreate,
        xmlSecOpenSSLAppKeyLoadMemory, XMLSEC_DSIG_STATUS_SUCCEEDED,
        XMLSEC_KEY_DATA_FORMAT_CERT_PEM,
    };
    use crate::raii::{OwnedDoc, OwnedDsigCtx, OwnedKey, OwnedKeysMngr};
    use crate::transforms::apply_allow_list;

    let parser_options = XML_PARSE_NONET | XML_PARSE_NODICT;

    if xml.len() > MAX_INPUT {
        return Err(XmlSecError::XmlParseFailed("input too large".to_owned()));
    }
    // Cast is sound: we just bounded length to fit in i32.
    let len_c = xml.len() as libc::c_int;

    // ----- 1. Parse XML -----
    //
    // SAFETY: `xml.as_ptr()` is valid for `xml.len()` bytes. We pass
    // NULL for url and encoding (auto-detect). Returns NULL on parse
    // failure.
    let doc_raw = unsafe {
        xmlReadMemory(
            xml.as_ptr().cast::<libc::c_char>(),
            len_c,
            std::ptr::null(),
            std::ptr::null(),
            parser_options,
        )
    };
    let doc = OwnedDoc::from_raw(doc_raw)
        .ok_or_else(|| XmlSecError::XmlParseFailed("xmlReadMemory returned NULL".to_owned()))?;

    // The libxml2 `xmlDocPtr` points at a struct whose first field
    // layout we don't depend on; we need the *root element* node. In
    // libxml2 the root-element accessor is `xmlDocGetRootElement`, but
    // since `xmlSecFindNode` walks a node subtree (not a doc), we can
    // pass the doc itself reinterpreted as a node pointer because
    // libxml2 uses a tagged-discriminant union where `xmlDocPtr` and
    // `xmlNodePtr` share the same `children` chain prefix. The
    // canonical libxmlsec1 sample code (`xmldsigverify` in the xmlsec1
    // examples) does exactly this:
    //
    //     xmlNodePtr node = xmlSecFindNode(xmlDocGetRootElement(doc),
    //                                      xmlSecNodeSignature,
    //                                      xmlSecDSigNs);
    //
    // We replicate via a cast — `xmlDocPtr` reinterpreted as
    // `xmlNodePtr` walks through the doc's children which include the
    // root element. The cast is documented as safe in libxml2 because
    // both types share the `xmlNode` prefix (`_xmlNode` in C). We do
    // NOT call `xmlDocGetRootElement` directly because adding another
    // FFI symbol for one cast is more surface area than the shared
    // prefix already gives us — the cast pattern appears in samael,
    // python-xmlsec, and the libxmlsec1 reference examples.
    //
    // SAFETY: `doc.as_ptr()` is a valid `xmlDocPtr`. Casting to
    // `xmlNodePtr` lets `xmlSecFindNode` walk the children chain;
    // libxml2's `_xmlDoc` struct begins with the same fields as
    // `_xmlNode` (the `_private` / `type` / `name` / `children`
    // prefix), so reading them through the `xmlNodePtr` is well-defined
    // under the libxml2 ABI.
    let root_as_node = doc.as_ptr().cast::<crate::ffi::xmlNode>();

    // ----- 2. Find <Signature> node -----
    //
    // SAFETY: `root_as_node` is non-NULL (derived from non-NULL `doc`)
    // and points into a libxml2 doc whose lifetime is bound to `doc`.
    // `NODE_SIGNATURE` and `NS_DSIG` are NUL-terminated byte slices
    // with `'static` lifetime. The returned pointer (if non-NULL)
    // points into `doc`'s tree and is valid for `doc`'s lifetime.
    let sig_node =
        unsafe { xmlSecFindNode(root_as_node, NODE_SIGNATURE.as_ptr(), NS_DSIG.as_ptr()) };
    if sig_node.is_null() {
        return Err(XmlSecError::VerifyFailed(
            "missing Signature element".to_owned(),
        ));
    }

    // ----- 3. Create keys manager and load the IdP cert -----
    //
    // SAFETY: `xmlSecKeysMngrCreate` has no preconditions. Returns
    // NULL on allocation failure.
    let mngr_raw = unsafe { xmlSecKeysMngrCreate() };
    let mngr = OwnedKeysMngr::from_raw(mngr_raw).ok_or(XmlSecError::KeysMngrFailed)?;

    // PEM bytes. We accept the cert as a Rust `String` in
    // `SamlSpConfig` — convert to `&[u8]` and feed directly. The cert
    // is NOT required to be NUL-terminated by
    // `xmlSecOpenSSLAppKeyLoadMemory`; we pass an explicit length.
    let pem_bytes = cfg.x509_cert_pem.as_bytes();
    if pem_bytes.is_empty() {
        return Err(XmlSecError::KeysMngrFailed);
    }

    // SAFETY: `pem_bytes` is valid for `pem_bytes.len()` bytes. We
    // pass NULL for the password (cert is unencrypted) and NULL for
    // the callback (no prompt). Returns NULL on parse failure.
    let key_raw = unsafe {
        xmlSecOpenSSLAppKeyLoadMemory(
            pem_bytes.as_ptr(),
            pem_bytes.len(),
            XMLSEC_KEY_DATA_FORMAT_CERT_PEM,
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    let key = OwnedKey::from_raw(key_raw).ok_or(XmlSecError::KeysMngrFailed)?;

    // Transfer ownership to the manager. If adopt SUCCEEDS, the
    // manager owns the key and we `release` so our `Drop` does not
    // double-free. If adopt FAILS, we leave the wrapper alive so its
    // `Drop` reclaims the key.
    //
    // SAFETY: `mngr.as_ptr()` and `key.as_ptr()` are both non-NULL.
    // The adopt function returns 0 on success, negative on failure.
    let rc_adopt = unsafe { xmlSecKeysMngrAdoptKey(mngr.as_ptr(), key.as_ptr()) };
    if rc_adopt < 0 {
        // `key` drops here, releasing the unadopted key.
        return Err(XmlSecError::KeysMngrFailed);
    }
    // Manager now owns the key — forget the wrapper.
    let _ = key.release();

    // ----- 4. Apply the transform allow-list -----
    apply_allow_list()?;

    // ----- 5. Create DSig context -----
    //
    // SAFETY: `mngr.as_ptr()` is non-NULL; the context takes a
    // *borrow* on the manager (does not adopt it) so the manager's
    // `Drop` later still frees its allocations.
    let ctx_raw = unsafe { xmlSecDSigCtxCreate(mngr.as_ptr()) };
    let ctx = OwnedDsigCtx::from_raw(ctx_raw).ok_or(XmlSecError::DsigCtxFailed)?;

    // ----- 6. Verify -----
    //
    // SAFETY: `ctx.as_ptr()` and `sig_node` are both non-NULL and tied
    // to live allocations. `xmlSecDSigCtxVerify` returns 0 if it
    // completed mechanically (regardless of cryptographic verdict) and
    // negative on hard error (NULL input, malformed signature node).
    let rc_verify = unsafe { xmlSecDSigCtxVerify(ctx.as_ptr(), sig_node) };
    if rc_verify < 0 {
        // Mechanical failure — could not even attempt verification.
        // Treat as `VerifyFailed` (not `SignatureInvalid`) because the
        // signature was not cryptographically rejected; the verifier
        // could not complete. The shadow-mode classifier in PHASE-2A
        // will compare this against the hand-rolled's variant.
        return Err(XmlSecError::VerifyFailed(
            "xmlSecDSigCtxVerify returned negative status".to_owned(),
        ));
    }

    // ----- 7. Read cryptographic verdict from ctx->status -----
    //
    // SAFETY: `ctx.as_ptr()` is non-NULL and we just called
    // `xmlSecDSigCtxVerify` on it (the shim's documented
    // precondition). The shim returns the integer enum value.
    let status = unsafe { sx_xmlsec_dsig_ctx_status(ctx.as_ptr()) };
    if status != XMLSEC_DSIG_STATUS_SUCCEEDED {
        return Err(XmlSecError::SignatureInvalid);
    }

    // ----- 8. Cleanup -----
    //
    // `ctx`, `mngr`, `doc` all drop in this order at end of scope.
    // The manager owns the key (adopted above); its `Drop` frees the
    // key. The doc owns the sig_node borrow; its `Drop` frees the doc
    // tree which includes the signature subtree.
    drop(ctx);
    drop(mngr);
    drop(doc);

    Ok(VerifyOutcome {
        verifier_name: "xmlsec1",
        signature_valid: true,
        signed_node_xpath: None,
        name_id: String::new(),
        not_on_or_after_unix: None,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Under the default `--no-default-features` build (no libxmlsec1
    /// linkage), `verify` returns a `stub-no-xmlsec1` marker error
    /// rather than panicking or silently succeeding. This protects
    /// PHASE-2A shadow-mode dispatch code from misinterpreting an
    /// unlinked verifier as a working one.
    #[cfg(not(feature = "xmlsec1"))]
    #[test]
    fn stub_verifier_returns_stub_marker() {
        let v = XmlSec1Verifier::new().unwrap();
        assert_eq!(v.name(), "xmlsec1");

        let cfg = SamlSpConfig {
            entity_id: "https://sp.example/metadata".to_owned(),
            sso_url: "https://idp.example/sso".to_owned(),
            slo_url: None,
            x509_cert_pem: String::new(),
        };
        let result = v.verify(
            b"<dummy/>",
            &cfg,
            "https://sp.example/metadata",
            Duration::from_secs(60),
        );
        match result {
            Err(XmlSecError::VerifyFailed(marker)) => {
                assert_eq!(marker, "stub-no-xmlsec1");
            }
            other => panic!("expected stub-no-xmlsec1 marker error, got {other:?}"),
        }
    }

    /// Under `--features xmlsec1` an empty PEM rejects with
    /// `KeysMngrFailed`. We do not assert anything about successful
    /// verification here — that lives in `tests/verifier_core.rs`,
    /// which gates on `target_os = "linux"` so it only runs in CI
    /// where libxmlsec1 is apt-installed.
    #[cfg(feature = "xmlsec1")]
    #[test]
    fn empty_cert_rejects_before_verify() {
        let v = match XmlSec1Verifier::new() {
            Ok(v) => v,
            // Init may legitimately fail on hosts where libxmlsec1 is
            // installed but the OpenSSL backend is missing. Treat that
            // as an environment skip rather than a test failure.
            Err(XmlSecError::InitFailed) => return,
            Err(other) => panic!("unexpected init error: {other:?}"),
        };
        let cfg = SamlSpConfig {
            entity_id: "https://sp.example/metadata".to_owned(),
            sso_url: "https://idp.example/sso".to_owned(),
            slo_url: None,
            x509_cert_pem: String::new(),
        };
        // Use an XML doc that at least parses, so we get past
        // xmlReadMemory and stress the empty-PEM branch.
        let xml = br#"<?xml version="1.0"?><root xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Signature/></root>"#;
        let result = v.verify(
            xml,
            &cfg,
            "https://sp.example/metadata",
            Duration::from_secs(60),
        );
        match result {
            Err(XmlSecError::KeysMngrFailed) => {}
            other => panic!("expected KeysMngrFailed for empty PEM, got {other:?}"),
        }
    }
}
