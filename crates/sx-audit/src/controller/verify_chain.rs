//! [`VerifyChainUseCase`] — replay-and-verify a tenant's chain.

use std::sync::Arc;

use tracing::instrument;

use sx_core::value_object::ids::TenantId;

use crate::error::AuditError;
use crate::model::chain::{verify_linkage, VerificationReport, GENESIS_PREV_HASH};
use crate::service::hasher::compute_hash;
use crate::service::sink::AuditSink;

/// Use-case that walks a tenant's chain end-to-end and reports the first
/// divergence, if any.
#[derive(Debug)]
pub struct VerifyChainUseCase {
    sink: Arc<dyn AuditSink>,
}

impl VerifyChainUseCase {
    /// Construct a new use-case bound to `sink`.
    #[must_use]
    pub fn new(sink: Arc<dyn AuditSink>) -> Self {
        Self { sink }
    }

    /// Verify the chain for `tenant_id` over the closed sequence range
    /// `[from_seq, to_seq]`. Pass `from_seq = 1` and a large `to_seq`
    /// (e.g. `u64::MAX`) to verify the full chain.
    ///
    /// Returns [`AuditError::SequenceGap`] when the seqs are non-monotonic
    /// or skip a value, and [`AuditError::ChainDivergence`] when a
    /// recomputed hash does not match the stored one.
    #[instrument(skip(self), fields(tenant = %tenant_id))]
    pub async fn verify(
        &self,
        tenant_id: TenantId,
        from_seq: u64,
        to_seq: u64,
    ) -> Result<VerificationReport, AuditError> {
        let entries = self.sink.read_range(tenant_id, from_seq, to_seq).await?;
        verify_entries(&entries, from_seq)
    }
}

/// Pure-function verifier — exposed for unit / property tests and for
/// callers that already hold the entries in memory.
pub fn verify_entries(
    entries: &[crate::model::entry::AuditEntry],
    expected_first_seq: u64,
) -> Result<VerificationReport, AuditError> {
    if entries.is_empty() {
        return Ok(VerificationReport::clean(0));
    }

    let mut expected_seq = expected_first_seq;
    let mut prev: Option<&crate::model::entry::AuditEntry> = None;
    let mut count: u64 = 0;

    for entry in entries {
        if entry.seq != expected_seq {
            return Err(AuditError::SequenceGap { at_seq: entry.seq });
        }

        // Linkage to predecessor.
        if let Some(p) = prev {
            verify_linkage(p, entry)?;
        } else if expected_first_seq == 1 && entry.prev_hash != GENESIS_PREV_HASH {
            // Only enforce genesis-zero when verifying from seq 1; partial
            // verifications (from_seq > 1) cannot check the very first prev.
            return Err(AuditError::ChainDivergence {
                at_seq: entry.seq,
                expected: hex::encode(GENESIS_PREV_HASH),
                actual: hex::encode(entry.prev_hash),
            });
        }

        // Recompute hash and compare.
        let canonical = entry.to_canonical_bytes()?;
        let recomputed = compute_hash(&entry.prev_hash, &canonical);
        if recomputed != entry.hash {
            return Err(AuditError::ChainDivergence {
                at_seq: entry.seq,
                expected: hex::encode(recomputed),
                actual: hex::encode(entry.hash),
            });
        }

        prev = Some(entry);
        expected_seq = expected_seq.saturating_add(1);
        count = count.saturating_add(1);
    }

    Ok(VerificationReport::clean(count))
}
