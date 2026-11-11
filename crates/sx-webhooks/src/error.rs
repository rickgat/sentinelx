//! Error types for [`crate`].
//!
//! [`WebhookError`] is deliberately small and category-only — variants do
//! not carry raw bodies, headers, or signing-key material. This keeps any
//! propagated error safe to log at `tracing` level.

use thiserror::Error;

/// Categorical errors returned by every webhook entry point in this
/// crate.
///
/// Variants intentionally avoid embedding raw payloads or signing-key
/// material so [`std::fmt::Display`] output is always safe to log.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum WebhookError {
    /// The signature header was missing, malformed, or did not match the
    /// expected HMAC. Always returned via constant-time comparison so the
    /// error cannot leak timing information about the signing key.
    #[error("invalid webhook signature")]
    InvalidSignature,

    /// The body was not valid JSON, or did not match the expected schema
    /// for the declared provider event kind.
    #[error("malformed webhook payload")]
    BadPayload,

    /// The provider sent an event kind this crate does not yet model.
    /// Callers should typically treat this as a 202 Accepted no-op.
    #[error("unsupported webhook event: {0}")]
    Unsupported(String),

    /// Provider-specific replay-protection window was exceeded (Slack
    /// honours a 5-minute window per its documented v0 signing scheme).
    #[error("webhook timestamp outside replay window")]
    ReplayWindowExceeded,
}
