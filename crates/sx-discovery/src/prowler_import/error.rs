//! Error type for the Prowler import pipeline.

use thiserror::Error;

/// All errors produced by [`crate::prowler_import`].
#[derive(Debug, Error)]
pub enum ProwlerImportError {
    /// Upload exceeded the configured size limit.
    #[error("upload too large: {actual} bytes > {limit} bytes")]
    TooLarge {
        /// Bytes received before bailing.
        actual: u64,
        /// Configured limit.
        limit: u64,
    },

    /// Bytes were not valid UTF-8 / JSON, or did not match the Prowler v4
    /// finding schema even loosely.
    #[error("malformed prowler json: {0}")]
    Malformed(String),

    /// At least one finding referenced a cloud account / project /
    /// subscription that the importing tenant is not authorised for.
    #[error("cross-tenant rejection: tenant '{tenant}' is not registered for account '{account}'")]
    CrossTenant {
        /// Tenant id (UUID string).
        tenant: String,
        /// Provider-specific account identifier the finding referenced.
        account: String,
    },

    /// I/O failure while reading / writing the upload or persisted findings.
    #[error("io: {0}")]
    Io(String),

    /// The sink rejected one or more writes.
    #[error("sink: {0}")]
    Sink(String),
}

impl ProwlerImportError {
    /// Construct a [`Self::Malformed`] error.
    #[must_use]
    pub fn malformed(msg: impl Into<String>) -> Self {
        Self::Malformed(msg.into())
    }

    /// Construct a [`Self::Io`] error.
    #[must_use]
    pub fn io(msg: impl Into<String>) -> Self {
        Self::Io(msg.into())
    }

    /// Construct a [`Self::Sink`] error.
    #[must_use]
    pub fn sink(msg: impl Into<String>) -> Self {
        Self::Sink(msg.into())
    }
}
