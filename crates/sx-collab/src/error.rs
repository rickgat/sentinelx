//! Crate-level error type for `sx-collab`.

use thiserror::Error;

/// Errors produced by the OOB Collaborator.
///
/// Every fallible API in this crate returns [`CollabError`].  Variants are
/// intentionally coarse so they can be mapped cleanly into HTTP / gRPC
/// surfaces at the API boundary.
#[derive(Debug, Error)]
pub enum CollabError {
    /// An OOB token failed validation (wrong length, non-hex, etc.).
    #[error("invalid token: {0}")]
    InvalidToken(String),

    /// Configuration was missing or self-inconsistent.
    #[error("config: {0}")]
    Config(String),

    /// The DNS server failed to bind, start, or serve.
    #[error("dns server: {0}")]
    DnsServer(String),

    /// The HTTP server failed to bind, start, or serve.
    #[error("http server: {0}")]
    HttpServer(String),

    /// The SMTP server failed to bind, start, or serve.
    #[error("smtp server: {0}")]
    SmtpServer(String),

    /// A `CallbackSink` implementation failed.
    #[error("sink: {0}")]
    Sink(String),

    /// A `CallbackEncrypter` implementation failed.
    #[error("encrypter: {0}")]
    Encrypter(String),

    /// Underlying I/O error.
    #[error("io: {0}")]
    Io(String),

    /// Programmer error / unexpected invariant violation.
    #[error("internal: {0}")]
    Internal(String),
}

impl CollabError {
    /// Convenience constructor for [`CollabError::InvalidToken`].
    #[must_use]
    pub fn invalid_token(msg: impl Into<String>) -> Self {
        Self::InvalidToken(msg.into())
    }

    /// Convenience constructor for [`CollabError::Config`].
    #[must_use]
    pub fn config(msg: impl Into<String>) -> Self {
        Self::Config(msg.into())
    }

    /// Convenience constructor for [`CollabError::DnsServer`].
    #[must_use]
    pub fn dns_server(msg: impl Into<String>) -> Self {
        Self::DnsServer(msg.into())
    }

    /// Convenience constructor for [`CollabError::HttpServer`].
    #[must_use]
    pub fn http_server(msg: impl Into<String>) -> Self {
        Self::HttpServer(msg.into())
    }

    /// Convenience constructor for [`CollabError::SmtpServer`].
    #[must_use]
    pub fn smtp_server(msg: impl Into<String>) -> Self {
        Self::SmtpServer(msg.into())
    }

    /// Convenience constructor for [`CollabError::Sink`].
    #[must_use]
    pub fn sink(msg: impl Into<String>) -> Self {
        Self::Sink(msg.into())
    }

    /// Convenience constructor for [`CollabError::Encrypter`].
    #[must_use]
    pub fn encrypter(msg: impl Into<String>) -> Self {
        Self::Encrypter(msg.into())
    }

    /// Convenience constructor for [`CollabError::Io`].
    #[must_use]
    pub fn io(msg: impl Into<String>) -> Self {
        Self::Io(msg.into())
    }

    /// Convenience constructor for [`CollabError::Internal`].
    #[must_use]
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

impl From<std::io::Error> for CollabError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::CollabError;

    #[test]
    fn display_invalid_token() {
        let e = CollabError::invalid_token("too short");
        assert_eq!(e.to_string(), "invalid token: too short");
    }

    #[test]
    fn display_dns_server() {
        let e = CollabError::dns_server("bind failed");
        assert_eq!(e.to_string(), "dns server: bind failed");
    }

    #[test]
    fn display_http_server() {
        let e = CollabError::http_server("axum panic");
        assert_eq!(e.to_string(), "http server: axum panic");
    }

    #[test]
    fn display_smtp_server() {
        let e = CollabError::smtp_server("listener gone");
        assert_eq!(e.to_string(), "smtp server: listener gone");
    }

    #[test]
    fn from_io_error_is_io_variant() {
        let io = std::io::Error::new(std::io::ErrorKind::Other, "broken pipe");
        let e: CollabError = io.into();
        assert!(matches!(e, CollabError::Io(_)));
    }
}
