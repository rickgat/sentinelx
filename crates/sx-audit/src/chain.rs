//! HMAC-SHA256 chain anchoring for audit events.
//!
//! This module sits **alongside** the SHA-256 [`crate::model::chain`] hash
//! chain. It anchors each event with an HMAC-SHA256 keyed by a per-tenant
//! signing key, so that an attacker who tampers with the on-disk audit
//! log without also possessing the signing key cannot forge a valid
//! chain.
//!
//! # Construction
//!
//! For each event with sequence number `seq` and previous chain hash
//! `prev` (hex-encoded, `None` for the genesis event):
//!
//! ```text
//! input = prev_bytes || canonical_event_bytes || seq.to_be_bytes()
//! chain_hash = hex(HMAC-SHA256(signing_key, input))
//! ```
//!
//! Where `prev_bytes` is the lowercase hex string of the previous
//! chain hash decoded back into raw bytes (32 bytes), or the empty
//! byte slice for the genesis event. The canonical event bytes are
//! produced by [`crate::model::entry::AuditEntry::to_canonical_bytes`]
//! **with the HMAC fields zeroed out** so the input is independent of
//! the field whose value we are computing.
//!
//! # Security notes
//!
//! - The signing key is held in a [`SecretString`] and is **never**
//!   logged through `tracing`.
//! - Production deployments should source the signing key from a
//!   KMS-managed secret with rotation; the MVP reuses
//!   `iam.attempt_email_pepper` because the workspace already plumbs
//!   it as a [`SecretString`].
//! - HMAC output is 32 bytes; the hex representation is 64 characters.

use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use thiserror::Error;
use tracing::{debug, instrument};

use crate::error::AuditError;
use crate::model::entry::AuditEntry;

/// Hex string length of an HMAC-SHA256 digest (32 bytes => 64 hex chars).
pub const CHAIN_HASH_HEX_LEN: usize = 64;

type HmacSha256 = Hmac<Sha256>;

/// Errors produced by the HMAC chain layer.
#[derive(Debug, Error)]
pub enum ChainError {
    /// The signing key was empty — refusing to compute an unsigned chain.
    #[error("signing key must be non-empty")]
    EmptySigningKey,

    /// HMAC initialisation rejected the key (extremely unlikely with
    /// `Hmac<Sha256>` which accepts arbitrary-length keys, but we model
    /// it for completeness).
    #[error("invalid signing key for HMAC-SHA256: {0}")]
    InvalidKey(String),

    /// Canonical-bytes derivation failed.
    #[error("canonical event bytes: {0}")]
    CanonicalBytes(String),

    /// A stored `chain_hash` (or `chain_prev_hash`) was not a valid
    /// lowercase 64-char hex string.
    #[error("malformed chain hash at seq {at_seq}: {reason}")]
    MalformedHash {
        /// Sequence number of the offending entry.
        at_seq: u64,
        /// Human-readable description of why parsing failed.
        reason: String,
    },

    /// The stored `chain_hash` did not match the recomputed HMAC.
    /// Strong evidence of tampering — either the event payload was
    /// modified or the stored hash itself was rewritten.
    #[error(
        "chain divergence at seq {at_seq} for tenant {tenant}: \
         expected hmac prefix {expected_prefix}, got {actual_prefix}"
    )]
    HashMismatch {
        /// Sequence number of the diverging entry.
        at_seq: u64,
        /// Tenant id (for operator triage; no secrets included).
        tenant: String,
        /// First 16 hex chars of the recomputed hash (full hash is in
        /// the verifier's structured output, not the error message).
        expected_prefix: String,
        /// First 16 hex chars of the stored hash.
        actual_prefix: String,
    },

    /// The current event's `chain_prev_hash` did not match the prior
    /// event's `chain_hash`.
    #[error(
        "prev_hash mismatch at seq {at_seq} for tenant {tenant}: \
         expected prefix {expected_prefix}, got {actual_prefix}"
    )]
    PrevHashMismatch {
        /// Sequence number of the offending entry.
        at_seq: u64,
        /// Tenant id.
        tenant: String,
        /// First 16 hex chars of the expected previous chain hash.
        expected_prefix: String,
        /// First 16 hex chars of the actual stored previous chain hash.
        actual_prefix: String,
    },

    /// Sequence numbers were not strictly monotonic per tenant.
    #[error(
        "sequence gap or duplicate at seq {at_seq} for tenant {tenant} (previous was {previous})"
    )]
    SequenceGap {
        /// Sequence number of the offending entry.
        at_seq: u64,
        /// Tenant id.
        tenant: String,
        /// The previous sequence number observed for this tenant.
        previous: u64,
    },

    /// The genesis event carried a non-`None` `chain_prev_hash`.
    #[error("genesis event for tenant {tenant} must have prev_hash=None, got {got_prefix}")]
    GenesisHasPrev {
        /// Tenant id.
        tenant: String,
        /// First 16 hex chars of the unexpected prev hash.
        got_prefix: String,
    },
}

impl From<ChainError> for AuditError {
    fn from(value: ChainError) -> Self {
        match value {
            ChainError::CanonicalBytes(msg) => Self::Serialization(msg),
            other => Self::Internal(other.to_string()),
        }
    }
}

/// HMAC-SHA256 chain anchor.
///
/// Holds a single per-tenant signing key. In a multi-tenant deployment
/// the caller is expected to construct one [`HashChain`] per tenant so
/// that signing keys are not mixed.
#[derive(Clone)]
pub struct HashChain {
    signing_key: SecretString,
}

impl std::fmt::Debug for HashChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose the signing key, even in debug formatters.
        f.debug_struct("HashChain")
            .field("signing_key", &"<redacted>")
            .finish()
    }
}

impl HashChain {
    /// Construct a chain anchored by `signing_key`.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError::EmptySigningKey`] if the key is empty.
    pub fn new(signing_key: SecretString) -> Result<Self, ChainError> {
        if signing_key.expose_secret().is_empty() {
            return Err(ChainError::EmptySigningKey);
        }
        Ok(Self { signing_key })
    }

    /// Compute the HMAC-SHA256 chain hash for a new event.
    ///
    /// `prev` is the **hex-encoded** chain hash of the immediately
    /// preceding event (or `None` for the genesis event), and `seq` is
    /// the new event's sequence number.
    ///
    /// The HMAC input is `prev_bytes || canonical_event_bytes ||
    /// seq.to_be_bytes()` where `prev_bytes` is the raw 32 bytes of the
    /// decoded `prev` hex string (or an empty byte slice for the
    /// genesis event), and `canonical_event_bytes` is produced by
    /// [`AuditEntry::to_canonical_bytes`] **with the HMAC chain fields
    /// zeroed out**.
    ///
    /// # Errors
    ///
    /// - [`ChainError::MalformedHash`] if `prev` is not a valid 64-char
    ///   lowercase hex string.
    /// - [`ChainError::CanonicalBytes`] if the event cannot be
    ///   canonicalised.
    /// - [`ChainError::InvalidKey`] if HMAC initialisation rejects the
    ///   key (should not happen in practice).
    #[instrument(skip(self, event), fields(tenant = %event.tenant_id, seq))]
    pub fn step(
        &self,
        prev: Option<&str>,
        event: &AuditEntry,
        seq: u64,
    ) -> Result<String, ChainError> {
        let prev_bytes = match prev {
            None => Vec::new(),
            Some(hex_str) => decode_chain_hash(hex_str, seq)?,
        };

        let canonical = clone_for_chain(event)
            .to_canonical_bytes()
            .map_err(|e| ChainError::CanonicalBytes(e.to_string()))?;

        let mut mac = HmacSha256::new_from_slice(self.signing_key.expose_secret().as_bytes())
            .map_err(|e| ChainError::InvalidKey(e.to_string()))?;
        mac.update(&prev_bytes);
        mac.update(&canonical);
        mac.update(&seq.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let hex_digest = hex::encode(digest);
        debug!(
            tenant = %event.tenant_id,
            seq,
            hash_prefix = %&hex_digest[..16.min(hex_digest.len())],
            "computed hmac chain hash",
        );
        Ok(hex_digest)
    }

    /// Verify a slice of events against the expected HMAC chain.
    ///
    /// Events MUST be sorted ascending by `seq` and all belong to the
    /// same tenant. Returns `Ok(())` only when:
    ///
    /// - The first event has `chain_prev_hash == None` (genesis).
    /// - For all later events, `chain_prev_hash == Some(previous.chain_hash)`.
    /// - Each event's `chain_hash` matches the recomputed HMAC of
    ///   `prev_bytes || canonical_event_bytes || seq.to_be_bytes()`.
    /// - Sequence numbers are strictly monotonic per tenant.
    ///
    /// # Errors
    ///
    /// Returns the most specific [`ChainError`] variant for the first
    /// problem encountered.
    pub fn verify(&self, events: &[AuditEntry]) -> Result<(), ChainError> {
        if events.is_empty() {
            return Ok(());
        }

        let mut prev_hash: Option<String> = None;
        let mut prev_seq: u64 = 0;
        let mut prev_tenant: Option<sx_core::value_object::ids::TenantId> = None;

        for event in events {
            let tenant_str = event.tenant_id.to_string();

            // Sequence monotonicity (per-tenant). If the tenant changed
            // we reset the running counter; otherwise expect prev + 1.
            if let Some(t) = prev_tenant {
                if event.tenant_id != t {
                    prev_hash = None;
                    prev_seq = 0;
                }
            }
            if event.seq != prev_seq.saturating_add(1) {
                return Err(ChainError::SequenceGap {
                    at_seq: event.seq,
                    tenant: tenant_str,
                    previous: prev_seq,
                });
            }

            // prev_hash linkage.
            check_prev_linkage(prev_hash.as_deref(), event, &tenant_str)?;

            // Recompute and compare.
            let recomputed = self.step(prev_hash.as_deref(), event, event.seq)?;
            if recomputed != event.chain_hash {
                return Err(ChainError::HashMismatch {
                    at_seq: event.seq,
                    tenant: tenant_str,
                    expected_prefix: prefix(&recomputed),
                    actual_prefix: prefix(&event.chain_hash),
                });
            }

            prev_hash = Some(event.chain_hash.clone());
            prev_seq = event.seq;
            prev_tenant = Some(event.tenant_id);
        }
        Ok(())
    }
}

/// Check that `event.chain_prev_hash` matches the expected prev hash
/// from the verifier's running state.
fn check_prev_linkage(
    expected_prev: Option<&str>,
    event: &AuditEntry,
    tenant_str: &str,
) -> Result<(), ChainError> {
    match (expected_prev, event.chain_prev_hash.as_deref()) {
        (None, None) => Ok(()),
        (None, Some(got)) => Err(ChainError::GenesisHasPrev {
            tenant: tenant_str.to_owned(),
            got_prefix: prefix(got),
        }),
        (Some(expected), None) => Err(ChainError::PrevHashMismatch {
            at_seq: event.seq,
            tenant: tenant_str.to_owned(),
            expected_prefix: prefix(expected),
            actual_prefix: "<none>".to_owned(),
        }),
        (Some(expected), Some(got)) => {
            if expected == got {
                Ok(())
            } else {
                Err(ChainError::PrevHashMismatch {
                    at_seq: event.seq,
                    tenant: tenant_str.to_owned(),
                    expected_prefix: prefix(expected),
                    actual_prefix: prefix(got),
                })
            }
        }
    }
}

/// Decode a stored chain hash from its lowercase hex form into raw bytes.
fn decode_chain_hash(s: &str, at_seq: u64) -> Result<Vec<u8>, ChainError> {
    if s.len() != CHAIN_HASH_HEX_LEN {
        return Err(ChainError::MalformedHash {
            at_seq,
            reason: format!("expected {CHAIN_HASH_HEX_LEN} hex chars, got {}", s.len()),
        });
    }
    hex::decode(s).map_err(|e| ChainError::MalformedHash {
        at_seq,
        reason: e.to_string(),
    })
}

/// Produce a clone of `event` with the HMAC chain fields zeroed out so
/// the HMAC input is independent of the field whose value we compute.
/// The underlying SHA-256 chain fields (`prev_hash` / `hash`) are
/// preserved; those participate in the canonical bytes deliberately.
fn clone_for_chain(event: &AuditEntry) -> AuditEntry {
    let mut clone = event.clone();
    clone.chain_hash = String::new();
    clone.chain_prev_hash = None;
    clone
}

/// 16-char hex prefix used in error messages; never the full digest so
/// that log inspection cannot accidentally recover an HMAC sample
/// large enough to mount a key-recovery attack.
fn prefix(s: &str) -> String {
    let n = 16.min(s.len());
    s.get(..n).unwrap_or("").to_owned()
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::similar_names
)]
mod tests {
    use super::*;

    use secrecy::SecretString;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use sx_core::value_object::ids::{TenantId, UserId};

    use crate::model::action::AuditAction;
    use crate::model::actor::Actor;
    use crate::model::chain::GENESIS_PREV_HASH;
    use crate::service::chain_builder::{build_entry, build_genesis, NewAuditEvent};

    fn key() -> SecretString {
        SecretString::from("test-pepper-must-be-at-least-16b".to_owned())
    }

    fn fixed_tenant() -> TenantId {
        Uuid::parse_str("00000000-0000-7000-8000-000000000001")
            .unwrap()
            .into()
    }

    fn fixed_user() -> UserId {
        Uuid::parse_str("00000000-0000-7000-8000-000000000002")
            .unwrap()
            .into()
    }

    fn payload(seq_hint: u64) -> NewAuditEvent {
        NewAuditEvent {
            tenant_id: fixed_tenant(),
            actor: Actor::user(fixed_user()),
            action: AuditAction::Login,
            resource_kind: "session".into(),
            resource_id: format!("s-{seq_hint}"),
            before: None,
            after: None,
            request_id: format!("req-{seq_hint}"),
            ts: Some(OffsetDateTime::from_unix_timestamp(1_700_000_000 + seq_hint as i64).unwrap()),
        }
    }

    fn build_chain(n: usize) -> (HashChain, Vec<AuditEntry>) {
        let chain = HashChain::new(key()).unwrap();
        let mut entries = Vec::with_capacity(n);
        let mut prev_hmac: Option<String> = None;
        let g = build_genesis(payload(1)).unwrap();
        let mut e = g;
        let h = chain.step(prev_hmac.as_deref(), &e, e.seq).unwrap();
        e.chain_prev_hash = None;
        e.chain_hash = h.clone();
        prev_hmac = Some(h);
        entries.push(e);
        for i in 2..=(n as u64) {
            let last = entries.last().unwrap();
            let mut entry = build_entry(i, last.hash, payload(i)).unwrap();
            let h = chain.step(prev_hmac.as_deref(), &entry, entry.seq).unwrap();
            entry.chain_prev_hash = prev_hmac.clone();
            entry.chain_hash = h.clone();
            prev_hmac = Some(h);
            entries.push(entry);
        }
        (chain, entries)
    }

    #[test]
    fn step_genesis() {
        let chain = HashChain::new(key()).unwrap();
        let mut entry = build_genesis(payload(1)).unwrap();
        let h1 = chain.step(None, &entry, 1).unwrap();
        // Computing again must yield the same value.
        let h2 = chain.step(None, &entry, 1).unwrap();
        assert_eq!(h1, h2, "deterministic genesis HMAC");
        assert_eq!(h1.len(), CHAIN_HASH_HEX_LEN);
        // And stamping the fields does not change the recomputation
        // (because the canonical-bytes derivation zeroes them).
        entry.chain_hash = h1.clone();
        entry.chain_prev_hash = None;
        let h3 = chain.step(None, &entry, 1).unwrap();
        assert_eq!(h1, h3, "stamping must not change the hash");
    }

    #[test]
    fn step_chain() {
        let (_chain, entries) = build_chain(3);
        assert_eq!(entries.len(), 3);
        assert!(entries[0].chain_prev_hash.is_none());
        assert_eq!(
            entries[1].chain_prev_hash.as_deref(),
            Some(entries[0].chain_hash.as_str())
        );
        assert_eq!(
            entries[2].chain_prev_hash.as_deref(),
            Some(entries[1].chain_hash.as_str())
        );
        // All three hashes are distinct.
        assert_ne!(entries[0].chain_hash, entries[1].chain_hash);
        assert_ne!(entries[1].chain_hash, entries[2].chain_hash);
        assert_ne!(entries[0].chain_hash, entries[2].chain_hash);
    }

    #[test]
    fn verify_accepts_well_formed_chain() {
        let (chain, entries) = build_chain(5);
        chain.verify(&entries).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_event_payload() {
        let (chain, mut entries) = build_chain(3);
        // Flip a byte in the second event's request_id — this changes
        // the canonical bytes, so the stored chain_hash no longer matches
        // the recomputation.
        entries[1].request_id = "TAMPERED".to_owned();
        let err = chain.verify(&entries).expect_err("must fail");
        match err {
            ChainError::HashMismatch { at_seq, .. } => assert_eq!(at_seq, 2),
            other => panic!("expected HashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_modified_chain_hash() {
        let (chain, mut entries) = build_chain(3);
        // Replace the stored hash with garbage. We mutate just one
        // character so the length stays 64.
        let h = &mut entries[1].chain_hash;
        let mut chars: Vec<char> = h.chars().collect();
        chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
        *h = chars.into_iter().collect();
        let err = chain.verify(&entries).expect_err("must fail");
        match err {
            ChainError::HashMismatch { at_seq, .. } => assert_eq!(at_seq, 2),
            // The mutation also breaks the next event's prev_hash
            // linkage; the verifier is permitted to surface either.
            ChainError::PrevHashMismatch { at_seq, .. } => assert_eq!(at_seq, 3),
            other => panic!("expected HashMismatch or PrevHashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_skipped_seq() {
        let (chain, mut entries) = build_chain(3);
        entries.remove(1);
        let err = chain.verify(&entries).expect_err("must fail");
        match err {
            ChainError::SequenceGap { at_seq, .. } => assert_eq!(at_seq, 3),
            other => panic!("expected SequenceGap, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_swapped_events() {
        let (chain, mut entries) = build_chain(3);
        entries.swap(0, 2);
        let err = chain.verify(&entries).expect_err("must fail");
        // Swapping shifts seqs out of monotonic order — the verifier
        // notices either the seq gap (seq=3 before seq=1) or a chain
        // divergence depending on the swap.
        match err {
            ChainError::SequenceGap { .. }
            | ChainError::HashMismatch { .. }
            | ChainError::PrevHashMismatch { .. } => {}
            other => panic!("expected ordering error, got {other:?}"),
        }
    }

    #[test]
    fn new_rejects_empty_key() {
        let err = HashChain::new(SecretString::from(String::new())).expect_err("must fail");
        assert!(matches!(err, ChainError::EmptySigningKey));
    }

    #[test]
    fn step_uses_genesis_prev_hash_sha_zeroes_for_compat() {
        // Construct a genesis entry the normal way; the SHA-256
        // `prev_hash` field is the all-zero array.
        let entry = build_genesis(payload(1)).unwrap();
        assert_eq!(entry.prev_hash, GENESIS_PREV_HASH);
        // The HMAC chain is independent of the SHA chain's all-zero
        // prev_hash; what matters is that `prev` (the HMAC prev) is None.
        let chain = HashChain::new(key()).unwrap();
        let h = chain.step(None, &entry, 1).unwrap();
        assert_eq!(h.len(), CHAIN_HASH_HEX_LEN);
    }
}
