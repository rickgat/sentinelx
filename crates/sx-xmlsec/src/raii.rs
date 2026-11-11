//! RAII wrappers around the raw libxmlsec1 / libxml2 handles.
//!
//! Each type below is a thin newtype around a raw pointer whose `Drop`
//! impl calls the matching `*_Destroy` / `*FreeDoc` function. This pulls
//! cleanup into the compiler-managed unwind path so a `?`-returning
//! verifier body cannot leak the doc / keys-manager / dsig-context on
//! the failure path.
//!
//! ## Invariants
//!
//! Every wrapper enforces ONE invariant: **the pointer is non-NULL and
//! was returned by the matching libxmlsec1/libxml2 constructor.** The
//! `*::new` constructors take the raw pointer and return `Option<Self>`
//! so the only way to materialise a wrapper is to have just successfully
//! allocated something. `Drop` then unconditionally calls the destroy
//! function on the non-NULL pointer.
//!
//! ## Why not `NonNull<T>`
//!
//! libxmlsec1's destroy functions are documented as NULL-safe, but we
//! cannot rely on that on every backend (notably some vendored builds
//! where the NULL check has been compiled out). Encoding non-NULL in the
//! type system via `NonNull` would be cleaner but the destructors take
//! `*mut T`; we'd convert at every call. The `Option<Self>` constructor
//! gives the same NULL-rejection guarantee with less ceremony.
//!
//! ## Why not the `cell` crate's `Owned` wrappers
//!
//! `cell`-flavoured smart pointers can't express "destroy with this
//! exact C function" cleanly. A bespoke 60-line module here is the
//! lowest-friction option that keeps the safety story local to the
//! crate.

// Module is gated on `#[cfg(feature = "xmlsec1")]` at its declaration
// in `lib.rs`; we do NOT repeat the attribute here (triggers
// `clippy::duplicated_attributes`).
//
// FFI raw-pointer plumbing — unsafe is intrinsic and every callsite
// carries a SAFETY comment.
#![allow(unsafe_code)]

use crate::ffi::{
    xmlDocPtr, xmlFreeDoc, xmlSecDSigCtxDestroy, xmlSecDSigCtxPtr, xmlSecKeyDestroy, xmlSecKeyPtr,
    xmlSecKeysMngrDestroy, xmlSecKeysMngrPtr,
};

/// Owned `xmlDoc` — calls `xmlFreeDoc` on drop.
///
/// SAFETY contract: `ptr` is non-NULL and was returned by `xmlReadMemory`.
#[derive(Debug)]
pub struct OwnedDoc {
    ptr: xmlDocPtr,
}

impl OwnedDoc {
    /// Construct from a freshly-returned `xmlReadMemory` pointer.
    ///
    /// Returns `None` if the pointer is NULL — the caller is expected to
    /// translate that into the appropriate `XmlSecError` variant.
    pub const fn from_raw(ptr: xmlDocPtr) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr })
        }
    }

    /// Borrow the raw pointer for FFI calls. The returned pointer is
    /// valid for the lifetime of `self`.
    pub const fn as_ptr(&self) -> xmlDocPtr {
        self.ptr
    }
}

impl Drop for OwnedDoc {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is non-NULL (guaranteed by `from_raw`) and
        // was returned by `xmlReadMemory` (the only documented
        // constructor for an `OwnedDoc`). `xmlFreeDoc` is documented as
        // freeing the doc + all its children; no other Rust handle into
        // this doc outlives `self` because we never expose `xmlNodePtr`
        // children except as borrows tied to `self`'s lifetime.
        unsafe {
            xmlFreeDoc(self.ptr);
        }
    }
}

/// Owned `xmlSecKeysMngr` — calls `xmlSecKeysMngrDestroy` on drop.
///
/// SAFETY contract: `ptr` is non-NULL and was returned by
/// `xmlSecKeysMngrCreate`.
#[derive(Debug)]
pub struct OwnedKeysMngr {
    ptr: xmlSecKeysMngrPtr,
}

impl OwnedKeysMngr {
    /// Construct from a freshly-returned `xmlSecKeysMngrCreate` pointer.
    ///
    /// Returns `None` if the pointer is NULL.
    pub const fn from_raw(ptr: xmlSecKeysMngrPtr) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr })
        }
    }

    /// Borrow the raw pointer for FFI calls. Valid for the lifetime of
    /// `self`.
    pub const fn as_ptr(&self) -> xmlSecKeysMngrPtr {
        self.ptr
    }
}

impl Drop for OwnedKeysMngr {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is non-NULL (guaranteed by `from_raw`) and
        // was returned by `xmlSecKeysMngrCreate`. Destroy is documented
        // as releasing all adopted keys; we transferred key ownership
        // to the manager via `xmlSecKeysMngrAdoptKey` so we MUST NOT
        // separately destroy those keys.
        unsafe {
            xmlSecKeysMngrDestroy(self.ptr);
        }
    }
}

/// Owned `xmlSecDSigCtx` — calls `xmlSecDSigCtxDestroy` on drop.
///
/// SAFETY contract: `ptr` is non-NULL and was returned by
/// `xmlSecDSigCtxCreate`.
#[derive(Debug)]
pub struct OwnedDsigCtx {
    ptr: xmlSecDSigCtxPtr,
}

impl OwnedDsigCtx {
    /// Construct from a freshly-returned `xmlSecDSigCtxCreate` pointer.
    ///
    /// Returns `None` if the pointer is NULL.
    pub const fn from_raw(ptr: xmlSecDSigCtxPtr) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr })
        }
    }

    /// Borrow the raw pointer for FFI calls. Valid for the lifetime of
    /// `self`.
    pub const fn as_ptr(&self) -> xmlSecDSigCtxPtr {
        self.ptr
    }
}

impl Drop for OwnedDsigCtx {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is non-NULL (guaranteed by `from_raw`) and
        // was returned by `xmlSecDSigCtxCreate`. The destroy function
        // is documented as releasing all internal allocations.
        unsafe {
            xmlSecDSigCtxDestroy(self.ptr);
        }
    }
}

/// Owned `xmlSecKey` — calls `xmlSecKeyDestroy` on drop.
///
/// SAFETY contract: `ptr` is non-NULL and was returned by
/// `xmlSecOpenSSLAppKeyLoadMemory` (or another libxmlsec1 key
/// constructor) AND has NOT been adopted into a keys manager via
/// `xmlSecKeysMngrAdoptKey`. Once adopted, the manager owns the key —
/// the caller MUST call `OwnedKey::release` BEFORE the manager destroys
/// itself, or the key will be double-freed.
///
/// The verifier in `verifier.rs` does exactly that: on successful adopt,
/// it `release`s the wrapper so the manager owns the key for the
/// lifetime of the context.
#[derive(Debug)]
pub struct OwnedKey {
    ptr: xmlSecKeyPtr,
}

impl OwnedKey {
    /// Construct from a freshly-returned `xmlSecOpenSSLAppKeyLoadMemory`
    /// pointer. Returns `None` if the pointer is NULL.
    pub const fn from_raw(ptr: xmlSecKeyPtr) -> Option<Self> {
        if ptr.is_null() {
            None
        } else {
            Some(Self { ptr })
        }
    }

    /// Borrow the raw pointer for FFI calls. Valid only while `self`
    /// owns the key — once `release` is called, the returned pointer
    /// MUST NOT be used through this wrapper again (the wrapper has
    /// already been consumed).
    pub const fn as_ptr(&self) -> xmlSecKeyPtr {
        self.ptr
    }

    /// Transfer ownership out of the RAII wrapper without destroying.
    ///
    /// The caller (the verifier in `verifier.rs`) calls this AFTER
    /// `xmlSecKeysMngrAdoptKey` succeeds, because the keys manager has
    /// taken ownership and `Drop` would now double-free.
    pub const fn release(self) -> xmlSecKeyPtr {
        let ptr = self.ptr;
        // Use `std::mem::forget` to skip the `Drop` impl. We MUST NOT
        // call `xmlSecKeyDestroy` here — the manager owns the key now.
        std::mem::forget(self);
        ptr
    }
}

impl Drop for OwnedKey {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` is non-NULL (guaranteed by `from_raw`) and
        // has NOT been released via `release()` (consuming method that
        // bypasses Drop via `mem::forget`). Therefore destroying here
        // is the unique-owner path.
        unsafe {
            xmlSecKeyDestroy(self.ptr);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // Unit-level tests run on every platform (they only touch
    // `from_raw(NULL) -> None`; no actual libxmlsec1 call). The integration
    // tests in `tests/verifier_core.rs` exercise the happy path on Linux.

    #[test]
    fn null_ptr_yields_none() {
        assert!(OwnedDoc::from_raw(std::ptr::null_mut()).is_none());
        assert!(OwnedKeysMngr::from_raw(std::ptr::null_mut()).is_none());
        assert!(OwnedDsigCtx::from_raw(std::ptr::null_mut()).is_none());
        assert!(OwnedKey::from_raw(std::ptr::null_mut()).is_none());
    }
}
