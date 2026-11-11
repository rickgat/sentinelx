//! Categorical errors for the [`crate`].
//!
//! [`RuntimeError`] variants are intentionally compact and never embed raw
//! payloads, HMAC bytes, or the signing-key material itself, so
//! [`std::fmt::Display`] output is always safe to emit at any `tracing`
//! level.

use thiserror::Error;

/// Category of failure surfaced by the Falco ingestion pipeline.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// The webhook payload was not valid JSON, or did not match the Falco
    /// alert schema.
    #[error("malformed Falco alert payload")]
    BadPayload,

    /// The webhook signature was missing, malformed, or did not match the
    /// recomputed HMAC over the body bytes.
    #[error("invalid runtime-webhook signature")]
    InvalidSignature,

    /// The webhook timestamp drifted outside the configured replay window.
    #[error("runtime-webhook timestamp outside replay window")]
    ReplayWindowExceeded,

    /// The tenant identifier on the request was missing or unknown to the
    /// signing-key store. The caller surfaces this as `401 Unauthorized`.
    #[error("unknown tenant for runtime ingestion")]
    UnknownTenant,

    /// The audit sink rejected the batch row. Treated as `5xx`.
    #[error("audit sink failed: {0}")]
    Audit(String),

    /// Any internal invariant violation (e.g. inconsistent timestamps).
    /// Treated as `5xx`.
    #[error("internal runtime-ingest failure: {0}")]
    Internal(String),
}
