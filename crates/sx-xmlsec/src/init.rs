//! Safe init / shutdown wrapper for libxml2 + libxmlsec1 + OpenSSL engine.
//!
//! ## Why this exists
//!
//! libxml2 and libxmlsec1 both maintain process-global state. The init
//! ordering matters:
//!
//! 1. `xmlInitParser` — libxml2 parser tables.
//! 2. `xmlSecInit` — libxmlsec1 core; depends on libxml2 being live.
//! 3. `xmlSecOpenSSLAppInit` — OpenSSL config bridging; depends on
//!    libxmlsec1 core.
//! 4. `xmlSecOpenSSLInit` — register OpenSSL-backed transforms with the
//!    libxmlsec1 registry; depends on the AppInit being live.
//!
//! Shutdown is the strict reverse. Calling them out of order leaves
//! dangling pointers in libxmlsec1's transform registry and crashes on
//! the next verify.
//!
//! The init functions are designed to be called once per process by
//! upstream C consumers (Apache, Keycloak's native bits, etc.). Inside a
//! Rust binary that may construct + drop a `Library` handle many times
//! across tests, we MUST guarantee at-most-once init AND we MUST avoid
//! shutting libxml2 down while another Rust crate (or another test in
//! the same binary) is still using it.
//!
//! ## Solution
//!
//! * Init runs at most once per process, guarded by `std::sync::Once`.
//! * Shutdown is intentionally a *no-op* in `Drop`. The process-wide
//!   shutdown sequence is too costly to invoke per-context and would
//!   race with concurrent verifiers. The OS reclaims everything at
//!   process exit. This matches how every long-lived libxmlsec1 consumer
//!   (Apache mod_xmlsec, Shibboleth SP) handles teardown.
//!
//! PHASE-1B will introduce per-verifier `xmlSecKeysMngrPtr` /
//! `xmlSecDSigCtxPtr` handles — those *do* get explicit destroy calls,
//! tied to their Rust wrapper's `Drop`. The `Library` handle here is the
//! process-level umbrella only.

// Module gated by `#[cfg(feature = "xmlsec1")]` at its declaration in
// `lib.rs`; we do not duplicate the attribute here (triggers
// `clippy::duplicated_attributes`).

use std::sync::Once;

use crate::error::XmlSecError;
use crate::ffi;

/// Tracks whether `init_globals` already succeeded. Set to true inside
/// the `Once` closure on success; remains false on failure (so a
/// subsequent caller observes the same error code path rather than
/// silently re-entering verification with half-initialised globals).
static INIT_ONCE: Once = Once::new();
static mut INIT_OK: bool = false;

/// Process-global init for libxml2 + libxmlsec1 + OpenSSL engine.
///
/// # Errors
///
/// Returns [`XmlSecError::InitFailed`] if any of the four init calls
/// returns a non-zero status. The state of partially-initialised globals
/// is left as the C library left it — the caller MUST treat this as
/// fatal for the process and bail out, since libxmlsec1 does not provide
/// a "retry from clean state" entry point.
///
/// # Safety / re-entry
///
/// Calls through to four `extern "C"` symbols that touch process-global
/// state. We guard with `std::sync::Once` so the actual C calls happen
/// at most once per process. On second and later calls this function
/// simply re-checks the recorded outcome.
fn init_globals() -> Result<(), XmlSecError> {
    INIT_ONCE.call_once(|| {
        // SAFETY: `xmlInitParser` has no preconditions and is documented
        // as idempotent in libxml2 >= 2.9.10. We have additionally
        // gated this through `Once` so it executes at most once per
        // process regardless of the libxml2 version.
        unsafe {
            ffi::xmlInitParser();
        }

        // SAFETY: `xmlSecInit` requires libxml2 to be live, which the
        // previous call guarantees. Returns 0 on success.
        let rc_sec = unsafe { ffi::xmlSecInit() };
        if rc_sec < 0 {
            return;
        }

        // SAFETY: `xmlSecOpenSSLAppInit` accepts a NULL config pointer
        // to use defaults (system OpenSSL config). We pass NULL.
        let rc_app = unsafe { ffi::xmlSecOpenSSLAppInit(std::ptr::null()) };
        if rc_app < 0 {
            return;
        }

        // SAFETY: `xmlSecOpenSSLInit` requires `xmlSecOpenSSLAppInit` to
        // have succeeded, which is true on this path.
        let rc_engine = unsafe { ffi::xmlSecOpenSSLInit() };
        if rc_engine < 0 {
            return;
        }

        // All four init calls succeeded; record success for subsequent
        // `Library::new` calls.
        //
        // SAFETY: `INIT_OK` is written exactly once, from inside
        // `Once::call_once`. All readers go through `Library::new`
        // which calls `init_globals` first; this enforces a
        // happens-before relationship via `Once`'s memory ordering.
        unsafe {
            INIT_OK = true;
        }
    });

    // SAFETY: see above — `INIT_OK` is written only inside
    // `Once::call_once` and read after that closure has completed
    // (which `Once::call_once` enforces via its internal acquire/release
    // fence), so reading it here is a synchronised access.
    let ok = unsafe { INIT_OK };
    if ok {
        Ok(())
    } else {
        Err(XmlSecError::InitFailed)
    }
}

/// Safe handle representing a fully-initialised libxml2 + libxmlsec1 +
/// OpenSSL engine for the current process.
///
/// Construct via [`Library::new`]. Many handles may be constructed
/// concurrently — they all share the same underlying process-global
/// state, which is initialised exactly once via [`Once`].
///
/// `Drop` is intentionally a no-op (see module docs). The OS reclaims
/// global state at process exit.
#[derive(Debug)]
pub struct Library {
    // Zero-sized witness — we keep a private field so the struct cannot
    // be constructed outside this module without going through
    // `Library::new`.
    _witness: (),
}

impl Library {
    /// Acquire a handle to the initialised library globals.
    ///
    /// # Errors
    ///
    /// [`XmlSecError::InitFailed`] if init failed on the first call in
    /// this process. Subsequent calls reuse that recorded result.
    pub fn new() -> Result<Self, XmlSecError> {
        init_globals()?;
        Ok(Self { _witness: () })
    }
}

impl Drop for Library {
    fn drop(&mut self) {
        // Intentionally empty — see module docs. Per-context cleanup
        // lives on the PHASE-1B `Verifier` types.
    }
}
