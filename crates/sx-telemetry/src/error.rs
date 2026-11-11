//! Error type returned by every fallible function in this crate.
//!
//! Errors are intentionally string-based at the boundary so the crate does
//! not leak `opentelemetry` / `metrics-exporter-prometheus` types in its
//! public signature. This keeps the `SemVer` surface small.

use std::net::SocketAddr;

/// Errors produced while initialising or shutting down telemetry.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    /// The supplied `EnvFilter` directive could not be parsed.
    #[error("invalid log filter directive: {0}")]
    InvalidFilter(String),

    /// Building or shutting down the OTLP/gRPC exporter failed.
    #[error("failed to build OTLP exporter: {0}")]
    Otlp(String),

    /// The Prometheus HTTP listener could not be started.
    #[error("failed to start prometheus listener at {addr}: {message}")]
    Prometheus {
        /// Address that was attempted.
        addr: SocketAddr,
        /// Underlying error rendered as a string. Named `message` rather
        /// than `source` because the underlying error type is not part of
        /// this crate's public API.
        message: String,
    },

    /// A global `tracing` subscriber has already been installed.
    #[error("subscriber already initialized")]
    AlreadyInitialized,

    /// A generic I/O error wrapper used for misc validation and runtime
    /// failures that don't fit elsewhere.
    #[error("io error: {0}")]
    Io(String),
}
