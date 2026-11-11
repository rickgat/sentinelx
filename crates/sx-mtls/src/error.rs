//! Error type for the `sx-mtls` crate.
//!
//! `MtlsError` deliberately never carries any private-key bytes — only
//! filesystem paths, X.509 fingerprints, and human-readable reasons.

use std::path::PathBuf;

/// All failures surfaced by the `sx-mtls` crate.
#[derive(Debug, thiserror::Error)]
pub enum MtlsError {
    /// The supplied [`sx_config::MtlsConfig`] had `enabled = false`.
    /// Callers must check `cfg.enabled` before invoking
    /// [`crate::build_server_config`].
    #[error("mTLS is disabled in configuration")]
    Disabled,

    /// A configuration path could not be opened for reading.
    #[error("failed to read {path}: {reason}")]
    Io {
        /// The offending filesystem path.
        path: PathBuf,
        /// Human-readable reason. Never contains key bytes.
        reason: String,
    },

    /// A PEM file contained no valid certificate or private key.
    #[error("no PEM items decoded from {path}")]
    EmptyPem {
        /// The offending filesystem path.
        path: PathBuf,
    },

    /// A certificate's X.509 structure could not be parsed.
    #[error("failed to parse X.509 from {path}: {reason}")]
    InvalidCertificate {
        /// The offending filesystem path.
        path: PathBuf,
        /// Human-readable reason.
        reason: String,
    },

    /// A loaded certificate has already expired or is too close to its
    /// `not_after` boundary (less than the safety window of 30 days).
    #[error("certificate at {path} fails expiry check: {reason}")]
    CertificateExpiry {
        /// The offending filesystem path.
        path: PathBuf,
        /// Reason — includes the `not_after` timestamp.
        reason: String,
    },

    /// A private key could not be decoded from PEM.
    #[error("failed to load private key from {path}")]
    InvalidPrivateKey {
        /// The offending filesystem path. The key bytes themselves are
        /// **never** placed inside this variant.
        path: PathBuf,
    },

    /// `rustls` rejected the assembled `ServerConfig` (e.g. cert / key
    /// mismatch). The underlying string never includes key material.
    #[error("rustls rejected server configuration: {0}")]
    Rustls(String),

    /// The cert reloader's filesystem watcher could not be initialised
    /// or the configured path could not be watched.
    #[error("failed to start certificate reloader: {0}")]
    Watcher(String),
}

impl MtlsError {
    /// Wraps an `std::io::Error` for the given path.
    pub(crate) fn io(path: impl Into<PathBuf>, err: &std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            reason: err.to_string(),
        }
    }
}
