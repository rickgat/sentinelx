//! Integration tests for the `Library` init wrapper.
//!
//! These tests only have meaning when the `xmlsec1` feature is enabled
//! AND we are on a host where `libxmlsec1-dev` is installed. On the
//! default workspace-check path (feature off) they would have no
//! `Library` symbol to import — hence the module-level `cfg`.
//!
//! The tests are additionally gated on `target_os = "linux"` because:
//!
//! * CI runs on `ubuntu-latest` and the new install step in `ci.yml`
//!   apt-installs `libxmlsec1-dev` before `cargo test`.
//! * macOS dev workstations need `brew install libxmlsec1 libxml2`
//!   first, which not every contributor has done. Gating on Linux
//!   keeps the dev loop clean and CI strict.
//!
//! PHASE-1B may relax the macOS gate once the brew install line is in
//! `docs/runbooks/onboarding.md`.

#![cfg(all(feature = "xmlsec1", target_os = "linux"))]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sx_xmlsec::error::XmlSecError;

#[test]
fn library_init_does_not_panic() {
    // Constructing the Library handle must not panic on a Linux host
    // with libxmlsec1-dev installed. If init fails, we propagate as an
    // error — only the success case is asserted here so the test
    // surfaces "I can build but I can't init" as a clear failure
    // signature rather than a panic.
    let lib = sx_xmlsec::init::Library::new();
    assert!(
        lib.is_ok(),
        "Library::new() returned {lib:?} — \
         check apt-get install libxmlsec1-dev libxmlsec1-openssl libxml2-dev"
    );
    drop(lib);
}

#[test]
fn library_init_is_idempotent_across_handles() {
    // Multiple Library handles must coexist (different verifiers, or
    // different test threads); the underlying Once guard guarantees
    // at-most-once init.
    let a = sx_xmlsec::init::Library::new().expect("first init");
    let b = sx_xmlsec::init::Library::new().expect("second init");
    drop(a);
    drop(b);
}

#[test]
fn ffi_symbols_are_loadable() {
    // Smoke-test the bound FFI symbols by routing through Library init,
    // which exercises xmlInitParser + xmlSecInit +
    // xmlSecOpenSSLAppInit + xmlSecOpenSSLInit in the correct order.
    // If linkage is broken (e.g., libxmlsec1 absent at link time), this
    // test fails to build — exactly what we want.
    let result = sx_xmlsec::init::Library::new();
    match result {
        Ok(_) => {}
        Err(XmlSecError::InitFailed) => {
            panic!("Library init returned InitFailed — likely missing libxmlsec1-openssl runtime")
        }
        Err(other) => panic!("unexpected init error: {other:?}"),
    }
}
