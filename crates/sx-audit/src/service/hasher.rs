//! SHA-256 hashing helpers for the audit chain.

use sha2::{Digest, Sha256};

use crate::model::entry::{Hash, HASH_LEN};

/// Compute `SHA-256(prev || canonical)` and return the 32-byte digest.
///
/// `prev` is the raw 32-byte previous-entry hash (or
/// [`crate::model::chain::GENESIS_PREV_HASH`] for the genesis entry).
#[must_use]
pub fn compute_hash(prev: &Hash, canonical: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(canonical);
    let out = h.finalize();
    let mut bytes = [0u8; HASH_LEN];
    bytes.copy_from_slice(&out);
    bytes
}
