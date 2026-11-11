/*
 * sx-xmlsec C shim — minimal accessor for libxmlsec1 struct fields whose
 * layout is "public, but big-and-embedded-nested" and therefore expensive
 * to mirror in Rust.
 *
 * Currently exposes ONE function:
 *
 *   int sx_xmlsec_dsig_ctx_status(const xmlSecDSigCtx *ctx);
 *
 * which simply returns `(int)ctx->status` (the cryptographic verification
 * verdict — one of xmlSecDSigStatus{Unknown,Succeeded,Invalid}).
 *
 * Rationale (PHASE-1B, see docs/plans/top5-1-xmldsig-replacement.md):
 *
 *   `xmlSecDSigCtx` is declared in `<xmlsec/xmldsig.h>` with its full
 *   layout visible. C callers read `ctx->status` directly. From Rust we
 *   would either (a) mirror the entire struct in `#[repr(C)]` — fragile
 *   across libxmlsec1 minor releases because the prefix contains
 *   embedded `xmlSecKeyInfoCtx` / `xmlSecTransformCtx` structs that
 *   themselves grow — or (b) write this tiny shim that pins the access
 *   pattern to "whatever layout the linked libxmlsec1 actually has."
 *   We pick (b).
 *
 *   The shim compiles ONLY when the `xmlsec1` Cargo feature is on
 *   (build.rs gates it). The `xmlsec1` feature also turns on pkg-config
 *   discovery of the libxmlsec1 / libxml2 headers + libs, so the shim
 *   can `#include <xmlsec/xmldsig.h>` and link cleanly.
 *
 * License: MIT (matches the rest of sx-xmlsec).
 */

#include <xmlsec/xmldsig.h>

/* Return the cryptographic verdict from a DSig context. Caller must
 * guarantee `ctx` is non-NULL and was returned by `xmlSecDSigCtxCreate`
 * and has had `xmlSecDSigCtxVerify` called on it. */
int sx_xmlsec_dsig_ctx_status(const xmlSecDSigCtx *ctx) {
    return (int)(ctx->status);
}
