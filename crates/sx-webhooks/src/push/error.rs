//! Categorical error type for the mobile push channel.
//!
//! Variants intentionally avoid embedding device tokens, JWT bearer
//! strings, or credential material. Every variant is safe to log at any
//! `tracing` level: it conveys *what kind* of failure happened, not
//! *which secret* was involved.

use thiserror::Error;

/// Categorical errors returned by every entry point in
/// [`crate::push`].
#[derive(Debug, Error)]
pub enum PushError {
    /// Tenant lookup for APNs/FCM credentials failed (tenant unknown
    /// or no credentials registered).
    #[error("tenant has no push credentials configured")]
    MissingCredentials,

    /// The provided APNs signing key was malformed (not a valid PKCS#8
    /// EC private key, or the wrong curve).
    #[error("invalid APNs signing key")]
    InvalidApnsKey,

    /// JWT construction (ES256 for APNs, RS256 for FCM) failed.
    /// The underlying jsonwebtoken error is *not* embedded to avoid
    /// leaking key fingerprints.
    #[error("failed to build push provider JWT")]
    JwtBuild,

    /// The HTTP request to APNs or FCM failed before a response could
    /// be parsed (network error, TLS error, timeout). The underlying
    /// reqwest error is *not* embedded to avoid leaking bearer tokens
    /// possibly captured in the request context.
    #[error("push transport error")]
    Transport,

    /// APNs / FCM accepted the request but returned a 4xx/5xx status.
    /// The provider status code is preserved so the caller can decide
    /// whether to retry, but no body bytes are included.
    #[error("push provider rejected delivery: status {status}")]
    ProviderRejected {
        /// HTTP status code returned by the provider.
        status: u16,
    },

    /// A device registration referenced a tenant or device that does
    /// not exist.
    #[error("device registration not found")]
    UnknownDevice,

    /// The caller attempted to register a device for a platform that
    /// is not supported by this channel.
    #[error("unsupported mobile platform")]
    UnsupportedPlatform,
}
