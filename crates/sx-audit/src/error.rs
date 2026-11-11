//! Audit error type.
//!
//! All fallible operations in this crate return [`AuditError`].

use thiserror::Error;

/// Errors produced by the audit subsystem.
#[derive(Debug, Error)]
pub enum AuditError {
    /// The underlying [`crate::service::sink::AuditSink`] reported a failure.
    #[error("sink error: {0}")]
    Sink(String),

    /// During chain verification, the recomputed hash for an entry did not
    /// match the stored hash — strong evidence of tampering.
    #[error("chain divergence at seq {at_seq}: expected hash {expected}, actual {actual}")]
    ChainDivergence {
        /// Sequence number of the diverging entry.
        at_seq: u64,
        /// Hex-encoded expected hash (recomputed).
        expected: String,
        /// Hex-encoded actual hash (as stored).
        actual: String,
    },

    /// A gap was detected in the sequence numbers of the chain — either
    /// the first entry was not seq `1` or two consecutive entries differ
    /// by more than one.
    #[error("sequence gap at {at_seq}: missing prior")]
    SequenceGap {
        /// Sequence number where the gap was detected.
        at_seq: u64,
    },

    /// Serialization of the audit entry to canonical bytes failed.
    #[error("serialization: {0}")]
    Serialization(String),

    /// Catch-all for unrecoverable internal errors.
    #[error("internal: {0}")]
    Internal(String),
}
