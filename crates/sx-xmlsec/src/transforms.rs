//! Transform allow-list — refuse XSLT / XPath / XPath2 globally.
//!
//! ## Why refuse XSLT and XPath transforms
//!
//! The XML Signature specification permits `<Transform>` elements inside
//! `<Reference>` blocks that arbitrarily rewrite the signed content
//! before digest computation. The three transforms below are the
//! historically-abused class:
//!
//! * **XSLT** (`http://www.w3.org/TR/1999/REC-xslt-19991116`) — runs an
//!   arbitrary stylesheet. A hostile signer can ship a stylesheet that
//!   rewrites the signed content *after* digest computation, so what
//!   the verifier validates is NOT what downstream code consumes. This
//!   is the canonical XSW class III attack.
//! * **XPath** (`http://www.w3.org/TR/1999/REC-xpath-19991116`) —
//!   selects a subset of the document. A hostile XPath can "sign one
//!   subtree, deliver another" — a different framing of the same
//!   identity-binding gap.
//! * **XPath Filter 2.0** (`http://www.w3.org/2002/06/xmldsig-filter2`)
//!   — the v2 selection transform. Same threat model as XPath.
//!
//! The standard C14N / exc-c14n / C14N 1.1 transforms are KEPT enabled
//! — they perform structural canonicalisation without semantic
//! rewriting, which is the legitimate use case.
//!
//! ## Why this is a global, not per-context, allow-list
//!
//! `xmlSecTransformIdsRegistryDisable` operates on the libxmlsec1
//! *process-global* transform registry. Once disabled, the transform is
//! unavailable to ALL `xmlSecDSigCtx` instances for the lifetime of the
//! process. This matches the security stance — we have NO legitimate
//! caller that wants XSLT or XPath transforms enabled. A per-context
//! allow-list (`xmlSecDSigCtxEnableReferenceTransformsList`) exists in
//! the libxmlsec1 API but is more restrictive than what we need and
//! more verbose to wire; the global-disable is the documented "I never
//! want this transform" path.
//!
//! ## Idempotency
//!
//! `xmlSecTransformIdsRegistryDisable` is documented as idempotent
//! (re-disabling an already-disabled transform is a no-op). We still
//! gate the call behind a `Once` to keep the FFI surface narrow and
//! make accidental repeated disabling visible in tests.

// Module is gated on `#[cfg(feature = "xmlsec1")]` at its declaration
// in `lib.rs`; we do NOT repeat the attribute here.
#![allow(unsafe_code)]

use std::sync::Once;

use crate::error::XmlSecError;
use crate::ffi::{
    xmlSecTransformIdsRegistryDisable, xmlSecTransformXPath2GetKlass, xmlSecTransformXPathGetKlass,
    xmlSecTransformXsltGetKlass,
};

/// Runs the global `xmlSecTransformIdsRegistryDisable` calls exactly
/// once per process. Subsequent calls observe the recorded outcome.
static DISABLE_ONCE: Once = Once::new();
static mut DISABLE_OK: bool = false;

/// Apply the transform allow-list: disable XSLT, XPath, and XPath2 in
/// the libxmlsec1 global transform registry.
///
/// Idempotent across the process: the actual FFI work happens on the
/// first call only; later calls re-check the recorded outcome.
///
/// # Errors
///
/// Returns [`XmlSecError::VerifyFailed`] with a short marker if any of
/// the three FFI calls returns a negative status. The verifier MUST
/// treat this as fatal — without the allow-list a hostile transform
/// could bypass the cryptographic check.
///
/// # Why this is safe to call before `xmlSecDSigCtxCreate`
///
/// The disable operates on the registry that `xmlSecDSigCtxCreate`
/// reads when materialising a context. As long as `apply_allow_list`
/// runs BEFORE the first `xmlSecDSigCtxCreate` (in lifecycle order:
/// `Library::new` → `apply_allow_list` → `XmlSecDSigCtxCreate`), every
/// context the process ever creates sees the same XSLT/XPath/XPath2
/// rejection.
pub fn apply_allow_list() -> Result<(), XmlSecError> {
    DISABLE_ONCE.call_once(|| {
        // SAFETY: `xmlSecTransformXsltGetKlass` returns a stable
        // process-global pointer to the registry entry for the XSLT
        // transform. Calling the getter has no preconditions beyond
        // `xmlSecInit` having succeeded — enforced by `Library::new`
        // which always precedes any verifier call.
        let xslt_id = unsafe { xmlSecTransformXsltGetKlass() };
        // SAFETY: `xmlSecTransformIdsRegistryDisable` accepts any
        // registered transform-id pointer; the getter above provided
        // one. Returns 0 on success, negative on failure.
        let rc_xslt = unsafe { xmlSecTransformIdsRegistryDisable(xslt_id) };
        if rc_xslt < 0 {
            return;
        }

        // SAFETY: same as XSLT — getter returns a stable pointer.
        let xpath_v1 = unsafe { xmlSecTransformXPathGetKlass() };
        let rc_xpath = unsafe { xmlSecTransformIdsRegistryDisable(xpath_v1) };
        if rc_xpath < 0 {
            return;
        }

        // SAFETY: same as XSLT — getter returns a stable pointer.
        let xpath_filter2 = unsafe { xmlSecTransformXPath2GetKlass() };
        let rc_xpath2 = unsafe { xmlSecTransformIdsRegistryDisable(xpath_filter2) };
        if rc_xpath2 < 0 {
            return;
        }

        // SAFETY: written exactly once inside `Once::call_once`; all
        // readers below go through the same `Once` and therefore see a
        // synchronised value (acquire/release fence is internal to
        // `Once`).
        unsafe {
            DISABLE_OK = true;
        }
    });

    // SAFETY: see above — synchronised read after the `Once` closure
    // has run.
    let ok = unsafe { DISABLE_OK };
    if ok {
        Ok(())
    } else {
        Err(XmlSecError::VerifyFailed(
            "transform-allow-list: registry-disable failed".to_owned(),
        ))
    }
}
