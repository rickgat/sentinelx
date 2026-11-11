//! Error type shared by every [`crate::provider::SecretsProvider`]
//! implementation.
//!
//! The variants intentionally cover the four failure modes a typical
//! consumer cares about:
//!
//! * [`SecretsError::Transport`] — network/TLS/timeout failure when
//!   talking to the backend.
//! * [`SecretsError::Unauthorized`] — the backend rejected the request
//!   (Vault returns `403` for both *bad token* and *missing policy*; we
//!   collapse them here).
//! * [`SecretsError::NotFound`] — no secret exists at the requested
//!   path.
//! * [`SecretsError::Format`] — the backend's response could not be
//!   parsed into the expected shape (malformed JSON, missing fields,
//!   …).

use thiserror::Error;

/// Errors surfaced by [`crate::provider::SecretsProvider`] operations.
#[derive(Debug, Error)]
pub enum SecretsError {
    /// Underlying HTTP transport failure (DNS, TLS, timeout, …) or any
    /// other low-level I/O error talking to the backend.
    #[error("secrets transport error: {0}")]
    Transport(String),

    /// The backend rejected the request (HTTP `401` or `403`).
    ///
    /// Vault uses `403` for both an invalid token and for a token that
    /// lacks a policy granting access to the requested path. We collapse
    /// those into a single variant on the assumption that the caller's
    /// recovery path is identical.
    #[error("unauthorized: backend rejected the request")]
    Unauthorized,

    /// No secret exists at the requested path (HTTP `404`).
    #[error("secret not found at path: {0}")]
    NotFound(String),

    /// The backend's response could not be parsed into the expected
    /// shape (e.g. malformed JSON, missing `data.data`, value field of
    /// the wrong type).
    #[error("malformed secrets response: {0}")]
    Format(String),
}

impl SecretsError {
    /// Convenience constructor for transport errors that wraps any
    /// `Display` value.
    ///
    /// Public so downstream KMS adapters and envelope wrappers (e.g. the
    /// HIGH-008 `TaxiiAuthVault` test stub) can build the variant
    /// without an intermediate `String`.
    pub fn transport<E: std::fmt::Display>(err: E) -> Self {
        Self::Transport(err.to_string())
    }

    /// Convenience constructor for format errors that wraps any
    /// `Display` value.
    ///
    /// Public for the same reason as [`Self::transport`].
    pub fn format<E: std::fmt::Display>(err: E) -> Self {
        Self::Format(err.to_string())
    }
}

impl From<reqwest::Error> for SecretsError {
    fn from(err: reqwest::Error) -> Self {
        Self::transport(err)
    }
}

impl From<serde_json::Error> for SecretsError {
    fn from(err: serde_json::Error) -> Self {
        Self::format(err)
    }
}

impl From<sqlx::Error> for SecretsError {
    fn from(err: sqlx::Error) -> Self {
        Self::transport(err)
    }
}
