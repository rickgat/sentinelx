//! Error type shared by every adapter in [`crate`].
//!
//! The variants intentionally cover the four failure modes a typical
//! consumer of an outbound HTTP/UDP integration cares about:
//!
//! * [`IntegrationError::Transport`] — network/TLS/timeout/UDP-send
//!   failure when talking to the remote system.
//! * [`IntegrationError::Format`] — the remote responded but the body or
//!   payload could not be parsed/constructed into the expected shape
//!   (malformed JSON, missing field, invalid CEF input, …).
//! * [`IntegrationError::Unauthorized`] — the remote rejected the request
//!   on authn/authz grounds (HTTP `401`/`403`).
//! * [`IntegrationError::RateLimited`] — the remote returned `429 Too
//!   Many Requests`. The optional `retry_after_secs` field carries the
//!   parsed value of the `Retry-After` response header when present.

use thiserror::Error;

/// Errors surfaced by SIEM and ticketing adapters.
#[derive(Debug, Error)]
pub enum IntegrationError {
    /// Underlying HTTP/UDP transport failure.
    #[error("integration transport error: {0}")]
    Transport(String),

    /// The remote response (or the local payload being built) could not
    /// be parsed/serialized into the expected shape.
    #[error("integration format error: {0}")]
    Format(String),

    /// The remote rejected the request on authn/authz grounds (HTTP
    /// `401`/`403`).
    #[error("unauthorized: remote rejected the request")]
    Unauthorized,

    /// The remote returned `429 Too Many Requests`. If the `Retry-After`
    /// header was present and parsable as an integer number of seconds,
    /// it is exposed here so the caller can back off accordingly.
    #[error("rate limited (retry after {retry_after_secs:?}s)")]
    RateLimited {
        /// Parsed value of the `Retry-After` header, in seconds. `None`
        /// if the header was absent or unparsable.
        retry_after_secs: Option<u64>,
    },
}

impl IntegrationError {
    /// Convenience constructor for transport errors.
    pub(crate) fn transport<E: std::fmt::Display>(err: E) -> Self {
        Self::Transport(err.to_string())
    }

    /// Convenience constructor for format errors.
    pub(crate) fn format<E: std::fmt::Display>(err: E) -> Self {
        Self::Format(err.to_string())
    }
}

impl From<reqwest::Error> for IntegrationError {
    fn from(err: reqwest::Error) -> Self {
        Self::transport(err)
    }
}

impl From<serde_json::Error> for IntegrationError {
    fn from(err: serde_json::Error) -> Self {
        Self::format(err)
    }
}

impl From<std::io::Error> for IntegrationError {
    fn from(err: std::io::Error) -> Self {
        Self::transport(err)
    }
}
