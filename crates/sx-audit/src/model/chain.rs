//! Chain-level helpers.
//!
//! Operating on a single entry is handled in [`crate::model::entry`]. This
//! module collects helpers that reason about a *sequence* of entries.

use crate::error::AuditError;
use crate::model::entry::{AuditEntry, Hash, HASH_LEN};

/// All-zero hash used as the `prev_hash` of the genesis entry.
pub const GENESIS_PREV_HASH: Hash = [0u8; HASH_LEN];

/// Outcome of a chain verification pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    /// Total number of entries inspected.
    pub entries_checked: u64,
    /// `None` if the chain verified end-to-end; otherwise the seq number
    /// of the first diverging entry.
    pub first_divergence_at: Option<u64>,
}

impl VerificationReport {
    /// Build a clean (no divergence) report.
    #[must_use]
    pub const fn clean(entries_checked: u64) -> Self {
        Self {
            entries_checked,
            first_divergence_at: None,
        }
    }
}

/// Verify the linkage between two consecutive entries.
///
/// Returns `Ok(())` when `current.prev_hash == previous.hash` AND the seqs
/// are consecutive (`current.seq == previous.seq + 1`).
pub fn verify_linkage(previous: &AuditEntry, current: &AuditEntry) -> Result<(), AuditError> {
    if current.seq != previous.seq.saturating_add(1) {
        return Err(AuditError::SequenceGap {
            at_seq: current.seq,
        });
    }
    if current.prev_hash != previous.hash {
        return Err(AuditError::ChainDivergence {
            at_seq: current.seq,
            expected: hex::encode(previous.hash),
            actual: hex::encode(current.prev_hash),
        });
    }
    Ok(())
}
