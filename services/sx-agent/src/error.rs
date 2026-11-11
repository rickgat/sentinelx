//! Error types for the `SentinelX` in-cluster scan agent.
//!
//! Every fallible operation in the binary surfaces as an [`AgentError`] —
//! `main` then folds that into `anyhow::Result` for a uniform process-exit
//! path. The error type is intentionally coarse-grained: granular causes are
//! captured via [`thiserror::Error`] source-chains rather than dozens of
//! variants.

use std::io;
use std::path::PathBuf;

/// All recoverable failures inside the agent binary.
#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    /// Configuration provided to the binary is invalid.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// The HMAC shared secret failed validation (missing, empty, too short).
    /// The error message NEVER reveals the secret value.
    #[error("invalid shared secret: {0}")]
    Secret(String),

    /// A required file could not be opened or read.
    #[error("io error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    /// A free-form I/O error not tied to a single path.
    #[error("io error: {0}")]
    GenericIo(#[from] io::Error),

    /// HTTP request to the collector failed at transport layer.
    #[error("collector transport error: {0}")]
    Transport(#[from] reqwest::Error),

    /// Collector returned a non-2xx response inside the configured policy.
    #[error("collector rejected report: status {status}")]
    CollectorRejected { status: u16 },

    /// JSON encoding / decoding error.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// URL parsing failure.
    #[error("invalid url: {0}")]
    Url(#[from] url::ParseError),

    /// The TLS / cert material could not be loaded.
    #[error("tls material error: {0}")]
    Tls(String),

    /// Agent exhausted its 4xx tolerance and is bailing out.
    #[error("collector returned 4xx for {count} consecutive runs (tolerance {tolerance})")]
    FailureToleranceExceeded { count: u32, tolerance: u32 },
}
