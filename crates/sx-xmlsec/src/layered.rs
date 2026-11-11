//! PHASE-1C: defence-in-depth composition of the byte-level pre-parse
//! gates with the libxmlsec1-backed [`XmlDsigVerifier`].
//!
//! ## Why a wrapper, not a flag on `XmlSec1Verifier`
//!
//! The pre-parse gates that catch the 8 named Somorovsky / Schwenk XSW
//! shapes — plus DOCTYPE / DTD bombs, transform-algorithm abuse,
//! deprecated-algorithm probes, and embedded-X.509 hygiene — live in
//! `sx-iam` (`fuzz_entry::pre_parse_gates`). Pushing the gate logic
//! down into `sx-xmlsec` would create a dependency cycle: `sx-xmlsec`
//! must stay free of any `sx-iam` import, otherwise the PHASE-2A
//! shadow-mode dispatcher (which will live in `sx-iam`) cannot hold a
//! `Box<dyn XmlDsigVerifier>` of a layered-verifier impl without
//! pulling its own crate in as a dep.
//!
//! The injection seam is the `gates` closure. `sx-iam` builds the
//! closure (it owns `pre_parse_gates`), `sx-xmlsec` runs it before the
//! inner verifier. The wrapper is transparent in [`XmlDsigVerifier::name`]
//! — it reports the inner verifier's name so the shadow-mode classifier
//! still attributes Class A/B/C disagreements correctly.
//!
//! ## Defence-in-depth contract
//!
//! Per `docs/plans/top5-1-xmldsig-replacement.md` §1.3 ("our
//! `pre_parse_gates` stay in place as defence-in-depth — they are
//! cheap, they catch entire classes of input before any C code runs,
//! and they make the FFI surface narrower"):
//!
//! 1. The gates run FIRST. They are pure Rust, allocation-light, and
//!    cannot reach the FFI surface.
//! 2. The inner `xmlsec1` verifier runs SECOND, but only if the gates
//!    pass. The C library never sees a DOCTYPE-laden, XSW-shaped, or
//!    XSLT-transform-laden document.
//! 3. The wrapper's `verify` is `?`-early-return at step (1), so step
//!    (2) is short-circuited on rejection. No partial state escapes.
//!
//! ## Wiring
//!
//! PHASE-1C ships this scaffold dormant — no production call site
//! wires it yet. PHASE-2A's shadow-mode dispatcher will construct:
//!
//! ```ignore
//! use sx_xmlsec::{LayeredVerifier, XmlSec1Verifier};
//! use sx_iam::service::saml::preparse_for_xmlsec::make_preparse_gates_closure;
//!
//! let inner = XmlSec1Verifier::new()?;
//! let layered = LayeredVerifier::new(inner, make_preparse_gates_closure());
//! ```
//!
//! and dispatch `layered.verify(...)` in parallel with the hand-rolled
//! verifier for comparison.

use std::time::Duration;

use crate::error::XmlSecError;
use crate::verifier::{SamlSpConfig, VerifyOutcome, XmlDsigVerifier};

/// Type alias for the gate closure injected by `sx-iam`.
///
/// The closure takes raw bytes (the same `&[u8]` the inner verifier
/// will see) and returns `Ok(())` if every gate passed, or
/// `Err(XmlSecError::PreParseRejected(_))` on the first failure. The
/// closure MUST be `Send + Sync` so it can be invoked from the
/// PHASE-2A shadow-mode `async` handler, which runs both verifiers
/// concurrently on the same input.
pub type GatesFn = Box<dyn Fn(&[u8]) -> Result<(), XmlSecError> + Send + Sync>;

/// Wraps any [`XmlDsigVerifier`] with a byte-level pre-parse gate
/// stage that runs first.
///
/// The wrapper is transparent: [`XmlDsigVerifier::name`] returns the
/// inner verifier's name. PHASE-2A's shadow-mode classifier reads
/// `name()` to label disagreements; it must see `"xmlsec1"` (or
/// whatever the inner reports), not a wrapper-specific label, so the
/// metric is comparable across builds where the dispatcher does or
/// does not use a layered wrapper.
pub struct LayeredVerifier<V: XmlDsigVerifier> {
    inner: V,
    /// Gate closure injection point so `sx-xmlsec` does not take a
    /// dependency on `sx-iam`. Construction is the caller's
    /// responsibility — see `sx_iam::service::saml::preparse_for_xmlsec`.
    gates: GatesFn,
}

impl<V: XmlDsigVerifier> LayeredVerifier<V> {
    /// Construct a layered verifier from an inner `XmlDsigVerifier`
    /// implementation and a gate closure.
    ///
    /// The closure is invoked on every `verify` call before the inner
    /// verifier is touched. There is intentionally no setter to swap
    /// the closure post-construction — the gate layer MUST be a
    /// compile-time-stable property of any wired verifier instance.
    pub fn new(inner: V, gates: GatesFn) -> Self {
        Self { inner, gates }
    }

    /// Borrow the inner verifier (for tests and shadow-mode
    /// introspection). Production callers should go through the
    /// [`XmlDsigVerifier`] trait — direct inner access is a smell that
    /// usually means the wrapper contract has leaked.
    #[must_use]
    pub const fn inner(&self) -> &V {
        &self.inner
    }
}

// Hand-written Debug so we don't require `V: Debug` and avoid printing
// the (closure-typed) gates field.
impl<V: XmlDsigVerifier> std::fmt::Debug for LayeredVerifier<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LayeredVerifier")
            .field("inner_name", &self.inner.name())
            .field("gates", &"<closure>")
            .finish()
    }
}

impl<V: XmlDsigVerifier> XmlDsigVerifier for LayeredVerifier<V> {
    fn verify(
        &self,
        xml: &[u8],
        cfg: &SamlSpConfig,
        audience: &str,
        skew: Duration,
    ) -> Result<VerifyOutcome, XmlSecError> {
        // Step 1: byte-level pre-parse gates. On rejection, return
        // immediately; the inner verifier is NEVER invoked. This is
        // the defence-in-depth contract: the C library never sees an
        // adversarially-shaped document.
        (self.gates)(xml)?;

        // Step 2: inner verifier (libxmlsec1 in production, stubbed in
        // tests). The gates have already removed every shape we
        // statically refuse; the inner verifier is responsible for the
        // cryptographic signature check.
        self.inner.verify(xml, cfg, audience, skew)
    }

    fn name(&self) -> &'static str {
        // Transparent: report the inner name so PHASE-2A's shadow-mode
        // classifier attributes results to the underlying verifier,
        // not the wrapper.
        self.inner.name()
    }
}

// Behavioural tests live in `tests/layered.rs` (integration tests) so
// they exercise the public re-exports through `sx_xmlsec::*` the same
// way PHASE-2A's shadow-mode dispatcher will. Keeping the unit-test
// module empty here avoids duplicating the stub-verifier scaffolding.
