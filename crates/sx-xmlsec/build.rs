// `println!` is the documented way to communicate with Cargo from a build
// script (`cargo:rustc-link-lib=`, `cargo:warning=`, `cargo:rerun-if-changed=`
// directives); the workspace clippy.toml disallows it for runtime code via
// `disallowed-macros`, but it is intrinsic here. Local opt-out keeps the
// workspace policy intact for every other source file.
#![allow(clippy::disallowed_macros)]

//! Build script for `sx-xmlsec` (TOP5-#1-PHASE-1A).
//!
//! Responsibilities (per `docs/plans/top5-1-xmldsig-replacement.md` §3):
//!
//! 1. Detect `libxmlsec1`, `xmlsec1-openssl`, and `libxml-2.0` via
//!    `pkg-config`. If all three resolve, emit `cargo:rustc-link-lib=`
//!    directives so the FFI symbols declared in `src/ffi.rs` resolve at
//!    link time.
//! 2. If `pkg-config` detection fails AND the `vendored-libxmlsec1`
//!    Cargo feature is enabled, build from a vendored tarball. PHASE-1A
//!    ships this branch as a `TODO!()` warning + stub linkage; PHASE-2B
//!    will wire `autotools` / `cmake` properly (`openssl-src`-style).
//! 3. If detection fails AND the vendored feature is off, emit a clear
//!    `cargo:warning=` and produce stub linkage so the crate still
//!    compiles for `cargo check --workspace`. FFI calls are unreachable
//!    in this configuration (`xmlsec1` Cargo feature is off, so the
//!    re-exports in `src/lib.rs` are also feature-gated).
//!
//! Design note: detection is keyed off the `xmlsec1` Cargo feature, NOT
//! a build-script env var, so that downstream crates can opt in with a
//! normal Cargo `features = ["xmlsec1"]` line without environment-fiddling.

fn main() {
    // Re-run when the build script itself changes.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=c_shim.c");
    // Re-run when developers explicitly set `LIBXMLSEC1_DIR` to override
    // discovery (matches the convention used by `openssl-sys` / `libz-sys`
    // for sovereign-customer airgap builds).
    println!("cargo:rerun-if-env-changed=LIBXMLSEC1_DIR");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_ALLOW_CROSS");

    let want_xmlsec1 = cfg!(feature = "xmlsec1");
    let want_vendored = cfg!(feature = "vendored-libxmlsec1");

    if !want_xmlsec1 {
        // Stub linkage path: crate compiles, FFI symbols are NOT linked,
        // and `src/lib.rs` feature-gates the re-exports so nothing tries
        // to call them. This is the default `cargo check --workspace`
        // path on developer machines without libxmlsec1 installed.
        println!(
            "cargo:warning=sx-xmlsec: `xmlsec1` Cargo feature is OFF; \
             building stub crate (no libxmlsec1 linkage). Enable the \
             `xmlsec1` feature in the consuming crate to link against \
             the system libxmlsec1."
        );
        return;
    }

    if want_vendored {
        // PHASE-2B will replace this with real vendored compilation. For
        // PHASE-1A the goal is a buildable scaffold + a load-bearing
        // warning so we don't ship a silent stub into the release image.
        println!(
            "cargo:warning=sx-xmlsec: `vendored-libxmlsec1` feature is \
             enabled but vendored compilation is stubbed in PHASE-1A. \
             Falling back to pkg-config detection. PHASE-2B will wire \
             the autotools build (see top5-1 plan §3 R1)."
        );
    }

    let (xmlsec_include_paths, xml2_include_paths) = detect_via_pkg_config();

    // PHASE-1B: compile the tiny C shim that exposes
    // `xmlSecDSigCtx::status` to Rust without forcing us to mirror the
    // full libxmlsec1 1.3.x struct layout. See `c_shim.c` for rationale.
    //
    // Skip compilation if pkg-config could NOT find the libxmlsec1
    // headers — the shim `#include`s `<xmlsec/xmldsig.h>` and would
    // hard-fail the build, masking the friendlier `cargo:warning=`
    // message above. Without the shim the Rust FFI link still fails
    // loudly later (missing `sx_xmlsec_dsig_ctx_status` symbol), which
    // is the intended failure mode.
    if xmlsec_include_paths.is_empty() && xml2_include_paths.is_empty() {
        println!(
            "cargo:warning=sx-xmlsec: skipping c_shim.c compile because \
             pkg-config did not find libxmlsec1 headers."
        );
    } else {
        compile_c_shim(&xmlsec_include_paths, &xml2_include_paths);
    }
}

/// Compile `c_shim.c` and link it into the crate.
///
/// Adds every include path discovered by `pkg-config` so `<xmlsec/...>`
/// and `<libxml/...>` headers resolve. Linker flags for `xmlsec1` /
/// `xmlsec1-openssl` / `xml2` are already emitted by `pkg-config::probe`,
/// so the shim's references resolve at the final link step.
fn compile_c_shim(xmlsec_includes: &[std::path::PathBuf], xml2_includes: &[std::path::PathBuf]) {
    let mut build = cc::Build::new();
    build.file("c_shim.c");
    for inc in xmlsec_includes {
        build.include(inc);
    }
    for inc in xml2_includes {
        build.include(inc);
    }
    // Treat compile warnings as a build break ONLY in dev profiles;
    // CI ships -Wall via cc's defaults. We rely on cc-rs defaults here
    // rather than handcrafting flags.
    build.compile("sx_xmlsec_shim");
}

/// Detect `libxmlsec1` + `xmlsec1-openssl` + `libxml-2.0` via `pkg-config`.
///
/// Emits `cargo:rustc-link-lib=` directives on success. On failure, emits
/// a `cargo:warning=` and produces stub linkage so the crate still
/// compiles — call sites that actually invoke FFI symbols will hit linker
/// errors, which is the intended loud-failure mode when a downstream
/// crate enables `xmlsec1` without the system packages installed.
///
/// Returns `(xmlsec_include_paths, libxml2_include_paths)` for the
/// downstream C-shim compile step. Empty vecs if detection failed.
fn detect_via_pkg_config() -> (Vec<std::path::PathBuf>, Vec<std::path::PathBuf>) {
    let mut cfg = pkg_config::Config::new();
    cfg.atleast_version("1.2.27"); // 1.2.27 contains the post-2017 XSW fix.

    let xmlsec1 = cfg.probe("xmlsec1");
    let xmlsec1_openssl = pkg_config::Config::new().probe("xmlsec1-openssl");
    let libxml2 = pkg_config::Config::new()
        .atleast_version("2.9.0")
        .probe("libxml-2.0");

    if let (Ok(xs), Ok(_), Ok(x2)) = (&xmlsec1, &xmlsec1_openssl, &libxml2) {
        // pkg-config already emitted the rustc-link-lib directives; we do
        // not need to repeat them. Surface a friendly status line so build
        // logs make it obvious what we picked up.
        println!(
            "cargo:warning=sx-xmlsec: detected libxmlsec1 + xmlsec1-openssl + libxml-2.0 via pkg-config (xmlsec1 feature ON, full FFI linkage)."
        );
        return (xs.include_paths.clone(), x2.include_paths.clone());
    }

    let mut missing: Vec<&str> = Vec::new();
    if xmlsec1.is_err() {
        missing.push("xmlsec1");
    }
    if xmlsec1_openssl.is_err() {
        missing.push("xmlsec1-openssl");
    }
    if libxml2.is_err() {
        missing.push("libxml-2.0");
    }
    println!(
        "cargo:warning=sx-xmlsec: pkg-config could NOT find: {}. \
         Install on Debian/Ubuntu: `sudo apt install libxmlsec1-dev \
         libxmlsec1-openssl libxml2-dev pkg-config`. On macOS: \
         `brew install libxmlsec1 libxml2 pkg-config`. The crate \
         will still compile but FFI calls will fail at link time.",
        missing.join(", ")
    );
    // Intentionally do NOT panic — PHASE-1A wants `cargo check` to
    // succeed even without system packages, so consumer crates (gated
    // by feature flag) can keep workspace-wide check green.
    (Vec::new(), Vec::new())
}
