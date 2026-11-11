//! Error types for log ingestion.

use thiserror::Error;

/// Errors returned by parsers.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ParseError {
    /// Payload is not the expected shape (e.g. malformed JSON).
    #[error("malformed payload: {0}")]
    Malformed(String),
    /// Payload was parsed but a required field is missing.
    #[error("missing field: {0}")]
    MissingField(String),
    /// Payload exceeds the configured byte cap.
    #[error("payload too large: {0} bytes")]
    TooLarge(usize),
}

/// Errors surfaced by the ingestion service.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum LogIngestError {
    /// No parser is registered for the supplied `source` token.
    #[error("unknown source type: {0}")]
    UnknownSource(String),
    /// A parser rejected the payload.
    #[error("parser: {0}")]
    Parser(#[from] ParseError),
    /// Internal failure (e.g. clock).
    #[error("internal: {0}")]
    Internal(String),
}
