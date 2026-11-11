//! Crate-level error type.
//!
//! Every fallible API in `sx-cloud` returns [`CloudError`]. Variants are
//! intentionally coarse so that adapter layers can map their wire-level
//! failures into one of a handful of shapes before crossing the use-case
//! boundary.

use thiserror::Error;

/// All errors produced by the cloud connectors.
#[derive(Debug, Error)]
pub enum CloudError {
    /// The connector was constructed with missing or malformed configuration
    /// (e.g. an empty region, an invalid project id).
    #[error("config: {0}")]
    Config(String),

    /// Authentication or authorization to the upstream provider failed
    /// (e.g. invalid AWS secret key, expired GCP bearer token).
    #[error("auth: {0}")]
    Auth(String),

    /// A low-level HTTP failure: connection refused, TLS handshake error,
    /// timeout, etc.
    #[error("http: {0}")]
    Http(String),

    /// The upstream returned a non-success status code with a body we
    /// preserved as-is for triage.
    #[error("upstream {status}: {body}")]
    Upstream {
        /// The HTTP status code returned by the provider.
        status: u16,
        /// The response body, truncated upstream where necessary.
        body: String,
    },

    /// The response could not be parsed: malformed XML / JSON, missing
    /// required field, etc.
    #[error("parse: {0}")]
    Parse(String),

    /// The crate's AWS SigV4 implementation produced an internally
    /// inconsistent signature. Treat as a bug.
    #[error("sigv4: {0}")]
    SigV4(String),

    /// An invariant in the connector layer was violated. Treat as a bug.
    #[error("internal: {0}")]
    Internal(String),
}

impl CloudError {
    /// Convenience constructor for [`CloudError::Config`].
    #[must_use]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Convenience constructor for [`CloudError::Auth`].
    #[must_use]
    pub fn auth(msg: impl Into<String>) -> Self {
        Self::Auth(msg.into())
    }

    /// Convenience constructor for [`CloudError::Http`].
    #[must_use]
    pub fn http(msg: impl Into<String>) -> Self {
        Self::Http(msg.into())
    }

    /// Convenience constructor for [`CloudError::Parse`].
    #[must_use]
    pub fn parse(msg: impl Into<String>) -> Self {
        Self::Parse(msg.into())
    }

    /// Convenience constructor for [`CloudError::SigV4`].
    #[must_use]
    pub fn sigv4(msg: impl Into<String>) -> Self {
        Self::SigV4(msg.into())
    }

    /// Convenience constructor for [`CloudError::Internal`].
    #[must_use]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

impl From<reqwest::Error> for CloudError {
    fn from(e: reqwest::Error) -> Self {
        Self::Http(e.to_string())
    }
}

impl From<serde_json::Error> for CloudError {
    fn from(e: serde_json::Error) -> Self {
        Self::Parse(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::CloudError;

    #[test]
    fn display_includes_reason() {
        assert_eq!(
            CloudError::config("missing region").to_string(),
            "config: missing region",
        );
        assert_eq!(
            CloudError::Upstream {
                status: 500,
                body: "boom".into(),
            }
            .to_string(),
            "upstream 500: boom",
        );
    }
}
