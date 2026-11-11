//! `sx-xmlsec` — FFI scaffold for the staged replacement of the
//! hand-rolled XMLDSig verifier in `sx-iam` with `libxmlsec1`.
//!
//! See `docs/plans/top5-1-xmldsig-replacement.md` for the multi-phase
//! rollout plan. This crate ships PHASE-1A only:
//!
//! * FFI bindings to ~12 libxmlsec1 / libxml2 / OpenSSL-engine symbols
//!   ([`ffi`]).
//! * Safe `Library` init/shutdown handle ([`init::Library`]) gated on
//!   `std::sync::Once`.
//! * Coarse [`error::XmlSecError`] enum mirroring `SamlError`'s shape
//!   for clean shadow-mode comparison.
//! * The canonical [`verifier::XmlDsigVerifier`] trait and a
//!   placeholder [`verifier::XmlSec1Verifier`] impl that returns
//!   `Err(XmlSecError::VerifyFailed("PHASE-1B"))`.
//!
//! ## Features
//!
//! * **`xmlsec1`** (off by default) — link against the system
//!   `libxmlsec1` + `libxmlsec1-openssl` + `libxml2`. Required for any
//!   actual FFI call; expected to be turned on by the consuming
//!   `sx-iam` crate behind its own feature gate.
//! * **`vendored-libxmlsec1`** (off by default) — fallback for
//!   release-image builds where the system-package version is
//!   unavailable. PHASE-1A stubs this; PHASE-2B will harden the
//!   autotools / cmake compile.
//!
//! The default-off configuration is deliberate: workspace-wide
//! `cargo check --workspace --all-targets` MUST pass on developer
//! machines that have not installed `libxmlsec1-dev`. Enabling the
//! feature without the system packages installed produces a clear
//! `cargo:warning=` from `build.rs` and a stub linkage; FFI calls will
//! fail at link time, which is the intended loud-failure mode.
//!
//! ## What's NOT here yet (deferred to later phases)
//!
//! * HIGH-003 fuzz corpus replay against new verifier — PHASE-2B.
//! * ADR-0010 reversal — PHASE-2B.
//! * Production cutover of `verify_assertion` to the
//!   [`verifier::XmlDsigVerifier`] trait — PHASE-2B. PHASE-2A lands
//!   the [`dual::DualVerifier`] dispatcher + `verifier_factory` in
//!   `sx-iam` but the production call site STILL invokes the
//!   hand-rolled verifier directly. The config knob `saml.xmldsig.verifier`
//!   is policy-declaration only until PHASE-2B's gate cutover.
//!
//! ## What landed since PHASE-1A
//!
//! * Actual `xmlSecDSigCtxVerify` invocation — PHASE-1B.
//! * Transform allow-list enforcement
//!   (`xmlSecTransformIdsRegistryDisable`) — PHASE-1B.
//! * Pre-parse gates layering ([`layered::LayeredVerifier`]) —
//!   PHASE-1C. The wrapper is dormant until PHASE-2A wires the
//!   shadow-mode dispatcher.
//! * Shadow-mode [`dual::DualVerifier`] + `xmldsig_shadow_mismatch_total`
//!   counter — PHASE-2A. Dormant in production (the SAML SP path in
//!   `sx-iam` still calls the hand-rolled verifier directly); the
//!   `verifier_factory` in `sx-iam` constructs the dispatcher so
//!   PHASE-2B's gate cutover has a wired surface to flip.

#![cfg_attr(docsrs, feature(doc_cfg))]
// SAML / XMLDSig / libxmlsec1 terminology (NameID, IdP, SingleSignOnService,
// SubjectConfirmationData, …) appears throughout the doc comments. Forcing
// every camelCase-but-not-an-identifier term into backticks fights the
// linter rather than the reader — the established convention in the rest of
// `sx-iam` is to gloss SAML terms as prose. Keep parity here.
#![allow(clippy::doc_markdown)]

pub mod dual;
pub mod error;
pub mod layered;
pub mod verifier;

// The `ffi` module is feature-gated because (a) its `extern "C"`
// `#[link(...)]` directives drag in libxmlsec1 / libxml2 at link time
// and (b) it contains `unsafe` code which is disallowed at the
// workspace level. Both reasons disappear under the default
// no-feature build, which is the workspace-check-friendly path.
#[cfg(feature = "xmlsec1")]
pub mod ffi;

#[cfg(feature = "xmlsec1")]
pub mod init;

/// PHASE-1B: RAII drop wrappers around the raw libxmlsec1 / libxml2
/// handles. Gated on `xmlsec1` for the same reason as `ffi`.
#[cfg(feature = "xmlsec1")]
pub mod raii;

/// PHASE-1B: transform allow-list (refuse XSLT / XPath / XPath2). Gated
/// on `xmlsec1`.
#[cfg(feature = "xmlsec1")]
pub mod transforms;

// Public-surface re-exports — keep the import surface minimal so call
// sites that only need the trait do not pull in implementation
// details.
pub use dual::{DualVerifier, MismatchKind, VerifierMode, METRIC_XMLDSIG_SHADOW_MISMATCH};
pub use error::XmlSecError;
pub use layered::{GatesFn, LayeredVerifier};
pub use verifier::{SamlSpConfig, VerifyOutcome, XmlDsigVerifier, XmlSec1Verifier};
