//! Hand-written `extern "C"` bindings for the `libxmlsec1` / `libxml2`
//! symbols `sx-xmlsec` consumes.
//!
//! ## Why hand-written instead of `bindgen`
//!
//! Per `docs/plans/top5-1-xmldsig-replacement.md` §1.3:
//!
//! > Hand-written `extern "C"` bindings to ~12 symbols is ~400 LOC and
//! > lets us pin the surface forever.
//!
//! We are deliberately keeping the binding surface narrow and stable.
//! `bindgen` would pull in the full libxmlsec1 + libxml2 ABI (thousands of
//! symbols), which is the opposite of what we want for an FFI seam in an
//! auth-critical code path: every extra symbol is one we have to audit at
//! every libxmlsec1 bump. The 12-symbol surface below is the minimum that
//! lets PHASE-1B build a working `xmlSecDSigCtxVerify` wrapper. PHASE-1B
//! may extend the surface (e.g., transform registry disable for the
//! XSLT/XPath allow-list) but each new symbol gets the same treatment:
//! one line of `extern "C"`, one SAFETY comment if it ever appears inside
//! `unsafe { ... }`, and one mention in the crate's public surface
//! documentation.
//!
//! ## Linkage
//!
//! `#[link(...)]` directives below are emitted alongside the rustc
//! `-l xmlsec1` / `-l xmlsec1-openssl` / `-l xml2` flags that `build.rs`
//! produces via `pkg-config`. Keeping the linkage declaration here as
//! well makes the dependency explicit at the source level — anyone
//! reading `ffi.rs` can see the libraries this module pulls in without
//! having to chase the build script.
//!
//! ## Feature gating
//!
//! The entire FFI surface is gated behind the `xmlsec1` Cargo feature.
//! When the feature is OFF (the default workspace-wide), this module is
//! empty and no `#[link(...)]` directives are emitted, so the crate
//! compiles cleanly on developer machines without `libxmlsec1-dev`
//! installed.

// The module is gated at the `mod` declaration in `lib.rs`; we do NOT
// re-state `#![cfg(feature = "xmlsec1")]` here to avoid the
// `clippy::duplicated_attributes` lint. Anyone reading this file in
// isolation: this entire module compiles only when the `xmlsec1` Cargo
// feature is enabled.
//
// FFI surface — unsafe is intrinsic. Each `unsafe` callsite outside this
// module carries its own SAFETY comment.
#![allow(unsafe_code)]
// Symbol names are deliberately verbatim from the C headers so grep-ability
// stays high; the C convention is camelCase.
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use libc::{c_char, c_int, c_uchar};

// ---------------------------------------------------------------------------
// Opaque pointer types
// ---------------------------------------------------------------------------
//
// libxmlsec1 / libxml2 expose handles as raw pointers to forward-declared
// structs. We mirror that with zero-sized opaque types; the Rust side
// only ever stores `*mut Foo`, never dereferences directly. This is the
// pattern recommended by the Rustonomicon (`std::ffi::c_void` would also
// work but loses type-checking between handle kinds — a `xmlSecKeysMngr`
// must never be passed where a `xmlSecDSigCtx` is expected).

/// Opaque libxml2 document handle (`xmlDoc *` in C).
#[repr(C)]
#[derive(Debug)]
pub struct xmlDoc {
    _private: [u8; 0],
}

/// Opaque libxml2 node handle (`xmlNode *` in C).
#[repr(C)]
#[derive(Debug)]
pub struct xmlNode {
    _private: [u8; 0],
}

/// Opaque libxmlsec1 keys manager (`xmlSecKeysMngr *` in C). Stores the
/// trusted X.509 certificates the verifier matches against.
#[repr(C)]
#[derive(Debug)]
pub struct xmlSecKeysMngr {
    _private: [u8; 0],
}

/// Opaque libxmlsec1 XMLDSig verification context
/// (`xmlSecDSigCtx *` in C). One per verification call; not thread-safe.
#[repr(C)]
#[derive(Debug)]
pub struct xmlSecDSigCtx {
    _private: [u8; 0],
}

/// Opaque libxmlsec1 transform klass (`xmlSecTransformId` in C).
///
/// `xmlSecTransformId` is already a pointer in the C ABI; we re-export
/// it so the PHASE-1B allow-list code can name it without pulling in
/// the full libxmlsec1 header surface.
#[repr(C)]
#[derive(Debug)]
pub struct xmlSecTransformKlass {
    _private: [u8; 0],
}

// ---------------------------------------------------------------------------
// Type aliases matching the C public surface
// ---------------------------------------------------------------------------

/// `xmlDocPtr` in libxml2.
pub type xmlDocPtr = *mut xmlDoc;
/// `xmlNodePtr` in libxml2.
pub type xmlNodePtr = *mut xmlNode;
/// `xmlSecKeysMngrPtr` in libxmlsec1.
pub type xmlSecKeysMngrPtr = *mut xmlSecKeysMngr;
/// `xmlSecDSigCtxPtr` in libxmlsec1.
pub type xmlSecDSigCtxPtr = *mut xmlSecDSigCtx;
/// `xmlSecTransformId` in libxmlsec1 (already a pointer in C).
pub type xmlSecTransformIdPtr = *mut xmlSecTransformKlass;

// ---------------------------------------------------------------------------
// libxml2 bootstrap
// ---------------------------------------------------------------------------

#[link(name = "xml2")]
extern "C" {
    /// Initialise the libxml2 parser global state. Idempotent in
    /// libxml2 >= 2.9.10 but we still wrap it in a `std::sync::Once`
    /// (see `init.rs`) so the precondition contract is local to this
    /// crate.
    pub fn xmlInitParser();

    /// Tear down libxml2 parser global state. Called from
    /// `Library::drop` in reverse-init order. Calling this while other
    /// libxml2 documents are alive elsewhere in the process would
    /// double-free — we mitigate by initialising at most once per
    /// process via `Once` and never tearing down until the process
    /// exits.
    pub fn xmlCleanupParser();

    /// Parse an in-memory XML buffer into a libxml2 `xmlDoc`.
    ///
    /// * `buffer`  — pointer to UTF-8 (or otherwise-self-describing)
    ///   XML bytes. NOT required to be NUL-terminated; the `size`
    ///   argument bounds the read.
    /// * `size`    — byte length of `buffer`.
    /// * `url`     — optional base URL string (may be NULL); used only
    ///   for error messages and base-URI resolution. We pass NULL.
    /// * `encoding` — optional encoding hint string (may be NULL);
    ///   libxml2 auto-detects the encoding from the XML declaration
    ///   when NULL. We pass NULL.
    /// * `options` — libxml2 parser flags (`XML_PARSE_*`). We pass a
    ///   conservative-strict set in `verifier.rs`:
    ///   `XML_PARSE_NONET | XML_PARSE_NODICT`. We deliberately do NOT
    ///   pass `XML_PARSE_NOENT` (which would expand external entities
    ///   — the XXE shape we already defend against via `pre_parse_gates`).
    ///
    /// Returns NULL on parse failure. Ownership of the returned doc
    /// transfers to the caller; release with `xmlFreeDoc`.
    pub fn xmlReadMemory(
        buffer: *const c_char,
        size: c_int,
        url: *const c_char,
        encoding: *const c_char,
        options: c_int,
    ) -> xmlDocPtr;

    /// Free an `xmlDoc` and all its children. Safe to pass NULL
    /// (no-op).
    pub fn xmlFreeDoc(doc: xmlDocPtr);
}

// ---------------------------------------------------------------------------
// libxmlsec1 core bootstrap
// ---------------------------------------------------------------------------

#[link(name = "xmlsec1")]
extern "C" {
    /// Initialise libxmlsec1 globals. Must be called AFTER
    /// `xmlInitParser`. Returns 0 on success, negative on failure.
    pub fn xmlSecInit() -> c_int;

    /// Tear down libxmlsec1 globals. Must be called BEFORE
    /// `xmlCleanupParser`. Returns 0 on success.
    pub fn xmlSecShutdown() -> c_int;

    /// Create an empty keys manager. Returns NULL on allocation failure.
    /// The returned handle owns its allocations; release with
    /// `xmlSecKeysMngrDestroy`.
    pub fn xmlSecKeysMngrCreate() -> xmlSecKeysMngrPtr;

    /// Destroy a keys manager. Must NOT be called twice on the same
    /// handle. Safe to pass NULL (no-op).
    pub fn xmlSecKeysMngrDestroy(mngr: xmlSecKeysMngrPtr);

    /// Create an XMLDSig verification context bound to a keys manager.
    /// `mngr` MAY be NULL for contexts that ship their own KeyInfo
    /// resolver, but our integration always supplies one. Returns NULL
    /// on allocation failure.
    pub fn xmlSecDSigCtxCreate(mngr: xmlSecKeysMngrPtr) -> xmlSecDSigCtxPtr;

    /// Destroy a DSig context. Safe to pass NULL.
    pub fn xmlSecDSigCtxDestroy(ctx: xmlSecDSigCtxPtr);

    /// Verify an XMLDSig signature anchored at `node` within the parent
    /// document. Returns 0 on success (signature mechanically valid —
    /// caller still inspects `ctx->status` for the cryptographic
    /// pass/fail bit). Returns negative on context errors (NULL
    /// pointers, malformed signature node).
    pub fn xmlSecDSigCtxVerify(ctx: xmlSecDSigCtxPtr, node: xmlNodePtr) -> c_int;

    /// Walk the libxml2 DOM subtree rooted at `parent` and return the
    /// first descendant whose local-name matches `name` and whose
    /// namespace URI matches `ns_href`. Returns NULL if no such node
    /// exists.
    ///
    /// `name` and `ns_href` are NUL-terminated UTF-8 C strings (libxml2
    /// uses `xmlChar*` which is `unsigned char*`; we cast at the call
    /// site).
    pub fn xmlSecFindNode(
        parent: xmlNodePtr,
        name: *const c_uchar,
        ns_href: *const c_uchar,
    ) -> xmlNodePtr;

    /// Adopt a key into the keys manager's default keys store.
    /// Ownership of `key` transfers to the manager: on success the
    /// caller MUST NOT destroy `key`; on failure the caller MUST
    /// destroy it. Returns 0 on success, negative on failure.
    pub fn xmlSecKeysMngrAdoptKey(mngr: xmlSecKeysMngrPtr, key: xmlSecKeyPtr) -> c_int;

    /// Destroy a key. Used for the failure-path cleanup of a key that
    /// `xmlSecKeysMngrAdoptKey` refused to adopt.
    pub fn xmlSecKeyDestroy(key: xmlSecKeyPtr);

    /// Disable a transform id in the global transform registry. After
    /// this call, any `<Transform>` element in a signed document
    /// referencing the disabled algorithm fails the transform-resolution
    /// step inside `xmlSecDSigCtxVerify` — the verifier never executes
    /// the transform body.
    ///
    /// We use this to refuse XSLT, XPath, and XPath2 transforms (see
    /// `crate::transforms`). Returns 0 on success.
    pub fn xmlSecTransformIdsRegistryDisable(id: xmlSecTransformIdPtr) -> c_int;
}

// ---------------------------------------------------------------------------
// libxmlsec1 transform-id symbols
// ---------------------------------------------------------------------------
//
// In the libxmlsec1 C ABI, transform identifiers are returned by per-algorithm
// getter functions (`xmlSecTransformXsltGetKlass`, etc.). We bind the getters
// — that's the supported public surface — and wrap them in small `fn` calls
// that return the `xmlSecTransformIdPtr` for `transforms.rs` to feed into
// `xmlSecTransformIdsRegistryDisable`.

#[link(name = "xmlsec1")]
extern "C" {
    /// Returns the id of the XSLT transform
    /// (`http://www.w3.org/TR/1999/REC-xslt-19991116`). XSLT is an
    /// arbitrary-rewrite transform; we DISABLE it in the registry
    /// because a hostile signer could rewrite signed content after
    /// digest computation (XSW class III).
    pub fn xmlSecTransformXsltGetKlass() -> xmlSecTransformIdPtr;

    /// Returns the id of the XPath transform
    /// (`http://www.w3.org/TR/1999/REC-xpath-19991116`). XPath is a
    /// selection transform; a hostile XPath can re-scope what is
    /// "actually signed" relative to the consumed node. DISABLE.
    pub fn xmlSecTransformXPathGetKlass() -> xmlSecTransformIdPtr;

    /// Returns the id of the XPath Filter 2.0 transform
    /// (`http://www.w3.org/2002/06/xmldsig-filter2`). Same threat model
    /// as XPath. DISABLE.
    pub fn xmlSecTransformXPath2GetKlass() -> xmlSecTransformIdPtr;
}

// ---------------------------------------------------------------------------
// xmlSecDSigStatus enum
// ---------------------------------------------------------------------------
//
// The libxmlsec1 `xmlSecDSigStatus` enum is exposed in
// `<xmlsec/xmldsig.h>` as:
//
//   typedef enum {
//       xmlSecDSigStatusUnknown   = 0,
//       xmlSecDSigStatusSucceeded = 1,
//       xmlSecDSigStatusInvalid   = 2
//   } xmlSecDSigStatus;
//
// We restate the constants here so the verifier can compare `ctx.status`
// against them without re-binding the enum type itself.

/// Verification status was never set — `xmlSecDSigCtxVerify` was not
/// called or did not progress far enough to record an outcome.
pub const XMLSEC_DSIG_STATUS_UNKNOWN: c_int = 0;

/// Cryptographic verification succeeded: the signature matched the
/// computed digest under the supplied key.
pub const XMLSEC_DSIG_STATUS_SUCCEEDED: c_int = 1;

/// Cryptographic verification failed: the signature did NOT match —
/// "tampered or wrong-cert" outcome.
pub const XMLSEC_DSIG_STATUS_INVALID: c_int = 2;

// ---------------------------------------------------------------------------
// xmlSecKey opaque type
// ---------------------------------------------------------------------------

/// Opaque libxmlsec1 key handle (`xmlSecKey *` in C). Wraps a cert /
/// key pair loaded via `xmlSecOpenSSLAppKeyLoadMemory`.
#[repr(C)]
#[derive(Debug)]
pub struct xmlSecKey {
    _private: [u8; 0],
}

/// `xmlSecKeyPtr` in libxmlsec1.
pub type xmlSecKeyPtr = *mut xmlSecKey;

// ---------------------------------------------------------------------------
// xmlSecKeyDataFormat constants
// ---------------------------------------------------------------------------
//
// `xmlSecKeyDataFormat` is an integer enum in libxmlsec1 selecting the
// on-the-wire format of a loaded key. We use PEM for `x509_cert_pem`
// inputs. The full enum is wider; we only restate the value we use.

/// PEM-encoded certificate / key material
/// (`xmlSecKeyDataFormatCertPem` — value 4 in `<xmlsec/keysdata.h>`).
///
/// We use this for the IdP X.509 signing certificate fed in via
/// `SamlSpConfig::x509_cert_pem`. The constant matches the upstream
/// enum value; if a future libxmlsec1 minor release renumbers this
/// (highly unlikely; would be ABI-breaking) the
/// `library_init`/`verifier_core` integration tests would catch it.
pub const XMLSEC_KEY_DATA_FORMAT_CERT_PEM: c_int = 4;

// ---------------------------------------------------------------------------
// C shim — exposes opaque-struct field accessors
// ---------------------------------------------------------------------------
//
// See `c_shim.c` in the crate root for source + rationale. The shim is
// compiled by `build.rs` into a static library (`libsx_xmlsec_shim.a`)
// that gets linked into the final binary.

extern "C" {
    /// Read the cryptographic verification verdict from a DSig context.
    ///
    /// Returns one of the `XMLSEC_DSIG_STATUS_*` constants. Caller must
    /// guarantee `ctx` is non-NULL and `xmlSecDSigCtxVerify` was called
    /// on it. The shim performs no NULL check; relying on the Rust-side
    /// invariant that the verifier never constructs a context-pointer
    /// path through a non-null guard.
    pub fn sx_xmlsec_dsig_ctx_status(ctx: xmlSecDSigCtxPtr) -> c_int;
}

// ---------------------------------------------------------------------------
// libxmlsec1 OpenSSL crypto engine
// ---------------------------------------------------------------------------
//
// libxmlsec1 is cryptography-engine-agnostic; we link the OpenSSL backend
// because that's the one packaged on Debian/Ubuntu/RHEL. macOS via brew
// also ships an OpenSSL-backed `libxmlsec1` by default. Switching engines
// (NSS, GnuTLS) would require a different symbol set; if that ever
// becomes a release-image requirement we add a new feature flag here
// rather than reworking the trait.

#[link(name = "xmlsec1-openssl")]
extern "C" {
    /// Initialise the OpenSSL crypto engine for libxmlsec1. Must be
    /// called AFTER `xmlSecInit` and BEFORE any operation that uses
    /// OpenSSL-backed transforms. Returns 0 on success.
    pub fn xmlSecOpenSSLAppInit(config: *const c_uchar) -> c_int;

    /// Tear down the OpenSSL crypto engine. Returns 0 on success.
    pub fn xmlSecOpenSSLAppShutdown() -> c_int;

    /// Register OpenSSL-backed transforms with the libxmlsec1 registry.
    /// Must be called after `xmlSecOpenSSLAppInit` and before
    /// `xmlSecDSigCtxCreate`. Returns 0 on success.
    pub fn xmlSecOpenSSLInit() -> c_int;

    /// Unregister OpenSSL-backed transforms. Returns 0 on success.
    pub fn xmlSecOpenSSLShutdown() -> c_int;

    /// Load a key (PEM-encoded cert or private key) from an in-memory
    /// buffer using the OpenSSL backend.
    ///
    /// * `data`    — pointer to PEM bytes (NOT required to be
    ///   NUL-terminated).
    /// * `data_size` — byte length of `data`.
    /// * `format`  — one of the `XMLSEC_KEY_DATA_FORMAT_*` constants;
    ///   we pass `XMLSEC_KEY_DATA_FORMAT_CERT_PEM`.
    /// * `pwd`     — passphrase for encrypted PEM; NULL for unencrypted
    ///   certs.
    /// * `pwd_callback` / `pwd_callback_ctx` — callback for prompting;
    ///   we pass NULL/NULL because the cert is unencrypted.
    ///
    /// Returns NULL on failure. On success, ownership of the returned
    /// `xmlSecKeyPtr` transfers to the caller; release with
    /// `xmlSecKeyDestroy` OR transfer ownership to a keys manager via
    /// `xmlSecKeysMngrAdoptKey`.
    pub fn xmlSecOpenSSLAppKeyLoadMemory(
        data: *const c_uchar,
        data_size: usize,
        format: c_int,
        pwd: *const c_char,
        pwd_callback: *mut c_uchar,
        pwd_callback_ctx: *mut c_uchar,
    ) -> xmlSecKeyPtr;
}

// ---------------------------------------------------------------------------
// Symbol surface summary
// ---------------------------------------------------------------------------
//
// 24 functions bound after PHASE-1B (up from 13 in PHASE-1A):
//
//   libxml2 (4):    xmlInitParser, xmlCleanupParser, xmlReadMemory,
//                   xmlFreeDoc.
//   libxmlsec1 (11): xmlSecInit, xmlSecShutdown, xmlSecKeysMngrCreate,
//                    xmlSecKeysMngrDestroy, xmlSecDSigCtxCreate,
//                    xmlSecDSigCtxDestroy, xmlSecDSigCtxVerify,
//                    xmlSecFindNode, xmlSecKeysMngrAdoptKey,
//                    xmlSecKeyDestroy, xmlSecTransformIdsRegistryDisable.
//   libxmlsec1-openssl (5): xmlSecOpenSSLAppInit, xmlSecOpenSSLAppShutdown,
//                           xmlSecOpenSSLInit, xmlSecOpenSSLShutdown,
//                           xmlSecOpenSSLAppKeyLoadMemory.
//   transform-id getters (3): xmlSecTransformXsltGetKlass,
//                             xmlSecTransformXPathGetKlass,
//                             xmlSecTransformXPath2GetKlass.
//   c_shim (1):     sx_xmlsec_dsig_ctx_status (reads ctx->status).
//
// Authoritative count (recounted line-by-line against the `extern "C"`
// blocks in this file): 24 entries (4 + 11 + 5 + 3 + 1). The
// `BOUND_FN_COUNT` constant + regression test below pin the value.
//
// 6 opaque types declared (xmlDoc, xmlNode, xmlSecKeysMngr,
// xmlSecDSigCtx, xmlSecTransformKlass, xmlSecKey) plus their `*Ptr`
// aliases.
//
// Three named constants restate libxmlsec1 enums we compare against:
//   XMLSEC_DSIG_STATUS_{UNKNOWN,SUCCEEDED,INVALID},
//   XMLSEC_KEY_DATA_FORMAT_CERT_PEM.

/// Compile-time count of bound functions — used by the test suite as a
/// regression tripwire for accidental symbol additions / removals. Bump
/// this constant in lockstep with the `extern "C"` blocks above.
///
/// PHASE-1A: 13 (libxmlsec1 + libxml2 + libxmlsec1-openssl). PHASE-1B:
/// 24 (added xmlReadMemory, xmlFreeDoc, xmlSecFindNode,
/// xmlSecKeysMngrAdoptKey, xmlSecKeyDestroy,
/// xmlSecTransformIdsRegistryDisable, xmlSecTransformXsltGetKlass,
/// xmlSecTransformXPathGetKlass, xmlSecTransformXPath2GetKlass,
/// xmlSecOpenSSLAppKeyLoadMemory, sx_xmlsec_dsig_ctx_status). The last
/// of these is our own C shim; we count it because it's a `pub fn`
/// extern entry and the regression-tripwire test greps for `pub fn`.
pub const BOUND_FN_COUNT: usize = 24;
