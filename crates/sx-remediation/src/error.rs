//! Crate-level error type.
//!
//! Every fallible API in this crate returns [`RemediationError`]. Variants are
//! intentionally coarse; adapter layers map vendor-specific failures into
//! the appropriate variant before crossing the use-case boundary.

use thiserror::Error;

/// All errors produced by the remediation crate.
#[derive(Debug, Error)]
pub enum RemediationError {
    /// A vendor source returned a transport-level failure (HTTP, DNS, TLS).
    #[error("transport error from {vendor}: {message}")]
    Transport {
        /// Vendor identifier (e.g. `"msrc"`, `"redhat"`).
        vendor: &'static str,
        /// Free-form message; never includes secrets.
        message: String,
    },

    /// The vendor returned a response that could not be parsed into the
    /// expected schema.
    #[error("malformed response from {vendor}: {message}")]
    Malformed {
        /// Vendor identifier.
        vendor: &'static str,
        /// Reason the response failed to parse.
        message: String,
    },

    /// The LLM produced output that failed schema validation, citation
    /// enforcement, or any other invariant check.
    #[error("invalid LLM output: {0}")]
    Invalid(String),

    /// A required configuration value was missing or out of range.
    #[error("config: {0}")]
    Config(String),

    /// The vendor returned a not-found response. Distinguished from
    /// [`RemediationError::Transport`] so the registry can quietly
    /// drop the source rather than logging a warning.
    #[error("advisory not found from {0}")]
    NotFound(&'static str),

    /// The vendor returned an authorisation failure (HTTP 401/403).
    #[error("unauthorized from {0}")]
    Unauthorized(&'static str),

    /// The vendor returned a rate-limit failure (HTTP 429).
    #[error("rate limited by {0}")]
    RateLimited(&'static str),

    /// Wraps a [`url::ParseError`] when building a vendor request URL.
    #[error("invalid url: {0}")]
    UrlBuild(String),

    /// Internal invariant violation. Treat as a bug.
    #[error("internal: {0}")]
    Internal(String),

    /// The caller supplied input that matched a sensitive-data pattern
    /// (PAN, SSN, NIK, etc.). Defense-in-depth check applied by the
    /// AI-assist surfaces (e.g. `service::explain::ExplainService`) BEFORE
    /// the input ever reaches an LLM.
    ///
    /// The variant carries only a short tag describing which detector
    /// fired (never the matched value) so the error itself cannot be used
    /// to exfiltrate the offending content.
    #[error("sensitive input rejected: {0}")]
    SensitiveInput(&'static str),
}

impl RemediationError {
    /// Construct a [`RemediationError::Transport`] variant.
    #[must_use]
    pub fn transport(vendor: &'static str, message: impl Into<String>) -> Self {
        Self::Transport {
            vendor,
            message: message.into(),
        }
    }

    /// Construct a [`RemediationError::Malformed`] variant.
    #[must_use]
    pub fn malformed(vendor: &'static str, message: impl Into<String>) -> Self {
        Self::Malformed {
            vendor,
            message: message.into(),
        }
    }

    /// Construct a [`RemediationError::Invalid`] variant.
    #[must_use]
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    /// Construct a [`RemediationError::Config`] variant.
    #[must_use]
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(message.into())
    }

    /// Construct a [`RemediationError::Internal`] variant.
    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }
}

#[cfg(test)]
mod tests {
    use super::RemediationError;

    #[test]
    fn display_transport() {
        let e = RemediationError::transport("msrc", "tcp reset");
        assert_eq!(e.to_string(), "transport error from msrc: tcp reset");
    }

    #[test]
    fn display_invalid() {
        let e = RemediationError::invalid("missing summary");
        assert_eq!(e.to_string(), "invalid LLM output: missing summary");
    }

    #[test]
    fn display_not_found() {
        let e = RemediationError::NotFound("ubuntu");
        assert_eq!(e.to_string(), "advisory not found from ubuntu");
    }
}
