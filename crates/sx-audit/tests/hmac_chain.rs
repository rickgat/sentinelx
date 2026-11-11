//! Integration tests for the HMAC chain anchor + sink stamping.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::significant_drop_tightening,
    clippy::items_after_statements
)]

mod common;

use std::sync::Arc;

use common::{sample_event, InMemorySink};
use secrecy::SecretString;

use sx_audit::prelude::{
    AuditAction, ChainError, HashChain, RecordAuditEventUseCase, CHAIN_HASH_HEX_LEN,
};
use sx_core::value_object::ids::TenantId;

fn signing_key() -> SecretString {
    SecretString::from("test-pepper-must-be-at-least-16b".to_owned())
}

#[tokio::test]
async fn sink_stamps_chain_metadata() {
    let tenant = TenantId::new();
    let sink = Arc::new(InMemorySink::new());
    let chain = HashChain::new(signing_key()).unwrap();
    let uc = RecordAuditEventUseCase::with_chain(sink.clone(), chain.clone());

    let e1 = uc
        .record(sample_event(tenant, AuditAction::Login, 1))
        .await
        .unwrap();
    let e2 = uc
        .record(sample_event(tenant, AuditAction::EngagementCreated, 2))
        .await
        .unwrap();
    let e3 = uc
        .record(sample_event(tenant, AuditAction::ScanStarted, 3))
        .await
        .unwrap();

    // seq monotonic & starts at 1
    assert_eq!(e1.seq, 1);
    assert_eq!(e2.seq, 2);
    assert_eq!(e3.seq, 3);
    // chain_hash hex-shaped
    assert_eq!(e1.chain_hash.len(), CHAIN_HASH_HEX_LEN);
    assert_eq!(e2.chain_hash.len(), CHAIN_HASH_HEX_LEN);
    assert_eq!(e3.chain_hash.len(), CHAIN_HASH_HEX_LEN);
    // prev_hash linkage
    assert!(e1.chain_prev_hash.is_none(), "genesis prev must be None");
    assert_eq!(e2.chain_prev_hash.as_deref(), Some(e1.chain_hash.as_str()));
    assert_eq!(e3.chain_prev_hash.as_deref(), Some(e2.chain_hash.as_str()));
    // hashes are distinct
    assert_ne!(e1.chain_hash, e2.chain_hash);
    assert_ne!(e2.chain_hash, e3.chain_hash);

    // And the on-disk snapshot agrees with the returned entries.
    let snapshot = sink.snapshot(tenant).await;
    assert_eq!(snapshot.len(), 3);
    assert_eq!(snapshot[0].chain_hash, e1.chain_hash);
    assert_eq!(snapshot[1].chain_hash, e2.chain_hash);
    assert_eq!(snapshot[2].chain_hash, e3.chain_hash);

    // End-to-end verification through the HMAC chain.
    chain.verify(&snapshot).unwrap();
}

#[tokio::test]
async fn tampering_breaks_chain_verification() {
    let tenant = TenantId::new();
    let sink = Arc::new(InMemorySink::new());
    let chain = HashChain::new(signing_key()).unwrap();
    let uc = RecordAuditEventUseCase::with_chain(sink.clone(), chain.clone());

    for i in 1..=3 {
        uc.record(sample_event(tenant, AuditAction::Login, i))
            .await
            .unwrap();
    }

    sink.tamper(tenant, |v| {
        v[1].request_id = "TAMPERED".into();
    })
    .await;

    let entries = sink.snapshot(tenant).await;
    let err = chain.verify(&entries).expect_err("must fail");
    match err {
        ChainError::HashMismatch { at_seq, .. } => assert_eq!(at_seq, 2),
        other => panic!("expected HashMismatch, got {other:?}"),
    }
}

#[tokio::test]
async fn empty_chain_verifies_clean() {
    let chain = HashChain::new(signing_key()).unwrap();
    chain.verify(&[]).unwrap();
}

#[tokio::test]
async fn wrong_signing_key_fails_verification() {
    let tenant = TenantId::new();
    let sink = Arc::new(InMemorySink::new());
    let writer_chain = HashChain::new(signing_key()).unwrap();
    let uc = RecordAuditEventUseCase::with_chain(sink.clone(), writer_chain);

    for i in 1..=2 {
        uc.record(sample_event(tenant, AuditAction::Login, i))
            .await
            .unwrap();
    }
    let entries = sink.snapshot(tenant).await;

    let attacker_chain = HashChain::new(SecretString::from(
        "a-different-key-of-equal-length".to_owned(),
    ))
    .unwrap();
    let err = attacker_chain.verify(&entries).expect_err("must fail");
    match err {
        ChainError::HashMismatch { at_seq, .. } => assert_eq!(at_seq, 1),
        other => panic!("expected HashMismatch on seq 1, got {other:?}"),
    }
}
