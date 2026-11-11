//! Property-based tests for the low-level HMAC `HashChain::step` / `verify`
//! invariants — complementary to the use-case-level properties in
//! `proptest_chain.rs`.
//!
//! Covers:
//!
//! 1. For any N in `1..=16`, a `step()`-produced chain verifies cleanly.
//! 2. Tampering with any entry's `request_id` mid-chain causes `verify` to
//!    reject.
//! 3. Swapping any two adjacent entries causes `verify` to reject.
//! 4. An empty chain verifies as `Ok`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::items_after_statements,
    clippy::assigning_clones
)]

use proptest::prelude::*;
use secrecy::SecretString;
use time::OffsetDateTime;
use uuid::Uuid;

use sx_audit::chain::{ChainError, HashChain};
use sx_audit::prelude::{
    build_entry, build_genesis, Actor, AuditAction, AuditEntry, NewAuditEvent,
};
use sx_core::value_object::ids::{TenantId, UserId};

fn key() -> SecretString {
    SecretString::from("proptest-pepper-must-be-at-least-16b".to_owned())
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
        ts: Some(OffsetDateTime::from_unix_timestamp(1_700_000_000_i64 + seq_hint as i64).unwrap()),
    }
}

/// Build a fully-stamped chain of `n` entries against `chain`.
fn build_chain(chain: &HashChain, n: usize) -> Vec<AuditEntry> {
    let mut entries: Vec<AuditEntry> = Vec::with_capacity(n);
    let mut prev_hmac: Option<String> = None;
    if n == 0 {
        return entries;
    }
    // Genesis.
    let mut g = build_genesis(payload(1)).unwrap();
    let h = chain.step(prev_hmac.as_deref(), &g, g.seq).unwrap();
    g.chain_prev_hash = None;
    g.chain_hash = h.clone();
    prev_hmac = Some(h);
    entries.push(g);
    for i in 2..=(n as u64) {
        let last = entries.last().unwrap();
        let mut e = build_entry(i, last.hash, payload(i)).unwrap();
        let h = chain.step(prev_hmac.as_deref(), &e, e.seq).unwrap();
        e.chain_prev_hash = prev_hmac.clone();
        e.chain_hash = h.clone();
        prev_hmac = Some(h);
        entries.push(e);
    }
    entries
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Any N-entry chain produced by `step()` is accepted by `verify()`.
    #[test]
    fn step_produced_chain_verifies(n in 1usize..=16) {
        let chain = HashChain::new(key()).unwrap();
        let entries = build_chain(&chain, n);
        chain.verify(&entries).expect("step-produced chain must verify");
    }

    /// Tampering with *any* entry's `request_id` flips `verify` to a
    /// `HashMismatch` (or `PrevHashMismatch` for the immediately following
    /// entry) at the tampered seq.
    #[test]
    fn tampering_with_any_entry_rejects(
        n in 2usize..=8,
        target_offset in 0usize..8,
    ) {
        let chain = HashChain::new(key()).unwrap();
        let mut entries = build_chain(&chain, n);
        let idx = target_offset % n;
        let target_seq = entries[idx].seq;
        entries[idx].request_id = "TAMPERED-BY-PROPTEST".to_owned();
        match chain.verify(&entries).expect_err("tampered chain must reject") {
            ChainError::HashMismatch { at_seq, .. } => {
                prop_assert_eq!(at_seq, target_seq);
            }
            // If the tampered entry is not the last, the linkage check on
            // the *next* entry can also surface first depending on the
            // verifier's order. Both error variants are acceptable.
            ChainError::PrevHashMismatch { at_seq, .. } => {
                prop_assert!(at_seq >= target_seq);
            }
            other => {
                prop_assert!(false, "expected HashMismatch / PrevHashMismatch, got {other:?}");
            }
        }
    }

    /// Swapping two adjacent entries breaks verification.
    ///
    /// A swap of two adjacent entries violates either the strict
    /// monotonic seq invariant (the verifier sees the higher seq first)
    /// or the prev-hash linkage; the verifier may surface any of
    /// `SequenceGap`, `HashMismatch`, or `PrevHashMismatch`.
    #[test]
    fn swapping_adjacent_entries_rejects(
        n in 2usize..=8,
        swap_at in 0usize..8,
    ) {
        let chain = HashChain::new(key()).unwrap();
        let mut entries = build_chain(&chain, n);
        // Pick a valid swap index in [0, n-2].
        let i = swap_at % (n - 1);
        entries.swap(i, i + 1);
        let err = chain.verify(&entries).expect_err("swapped chain must reject");
        match err {
            ChainError::SequenceGap { .. }
            | ChainError::HashMismatch { .. }
            | ChainError::PrevHashMismatch { .. } => {}
            other => prop_assert!(false, "expected ordering error, got {other:?}"),
        }
    }
}

/// Bonus: not a proptest case but covers the spec's "empty chain verify
/// Ok" requirement. `#[test]` is enough for this property.
#[test]
fn empty_chain_verifies_ok() {
    let chain = HashChain::new(key()).unwrap();
    chain.verify(&[]).expect("empty chain must verify");
}
