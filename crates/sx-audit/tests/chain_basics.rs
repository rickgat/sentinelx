//! Black-box tests of chain construction & verification.

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
use rstest::rstest;
use time::OffsetDateTime;

use sx_audit::prelude::{
    build_entry, build_genesis, compute_hash, verify_entries, Actor, AuditAction, AuditError,
    NewAuditEvent, RecordAuditEventUseCase, VerifyChainUseCase, GENESIS_PREV_HASH,
};
use sx_core::value_object::ids::{TenantId, UserId};

#[tokio::test]
async fn genesis_entry_links_to_zero_prev() {
    let tenant = TenantId::new();
    let payload = sample_event(tenant, AuditAction::Login, 1);
    let entry = build_genesis(payload).unwrap();
    assert_eq!(entry.seq, 1);
    assert_eq!(entry.prev_hash, GENESIS_PREV_HASH);
    // Recompute & confirm.
    let canonical = entry.to_canonical_bytes().unwrap();
    let expected = compute_hash(&GENESIS_PREV_HASH, &canonical);
    assert_eq!(entry.hash, expected);
}

#[tokio::test]
async fn two_entry_chain_verifies() {
    let tenant = TenantId::new();
    let sink = Arc::new(InMemorySink::new());
    let uc = RecordAuditEventUseCase::new(sink.clone());

    let e1 = uc
        .record(sample_event(tenant, AuditAction::Login, 1))
        .await
        .unwrap();
    let e2 = uc
        .record(sample_event(tenant, AuditAction::EngagementCreated, 2))
        .await
        .unwrap();

    assert_eq!(e1.seq, 1);
    assert_eq!(e2.seq, 2);
    assert_eq!(e2.prev_hash, e1.hash);

    let verifier = VerifyChainUseCase::new(sink.clone());
    let report = verifier.verify(tenant, 1, u64::MAX).await.unwrap();
    assert_eq!(report.entries_checked, 2);
    assert!(report.first_divergence_at.is_none());
}

#[tokio::test]
async fn mutating_action_breaks_verification() {
    let tenant = TenantId::new();
    let sink = Arc::new(InMemorySink::new());
    let uc = RecordAuditEventUseCase::new(sink.clone());

    let _ = uc
        .record(sample_event(tenant, AuditAction::Login, 1))
        .await
        .unwrap();
    let _ = uc
        .record(sample_event(tenant, AuditAction::EngagementCreated, 2))
        .await
        .unwrap();
    let _ = uc
        .record(sample_event(tenant, AuditAction::ScanStarted, 3))
        .await
        .unwrap();

    // Tamper with entry seq=2: flip the action.
    sink.tamper(tenant, |v| {
        v[1].action = AuditAction::ScanAborted;
    })
    .await;

    let verifier = VerifyChainUseCase::new(sink.clone());
    let err = verifier
        .verify(tenant, 1, u64::MAX)
        .await
        .expect_err("must fail");
    match err {
        AuditError::ChainDivergence { at_seq, .. } => assert_eq!(at_seq, 2),
        other => panic!("expected ChainDivergence, got {other:?}"),
    }
}

#[tokio::test]
async fn reordered_entries_fail() {
    let tenant = TenantId::new();
    let sink = Arc::new(InMemorySink::new());
    let uc = RecordAuditEventUseCase::new(sink.clone());

    for i in 1..=3 {
        uc.record(sample_event(tenant, AuditAction::Login, i))
            .await
            .unwrap();
    }
    sink.tamper(tenant, |v| {
        v.swap(0, 2);
    })
    .await;
    let entries = sink.snapshot(tenant).await;
    let err = verify_entries(&entries, 1).expect_err("must fail");
    // Reordering changes prev_hash mismatch OR sequence gap.
    matches!(
        err,
        AuditError::SequenceGap { .. } | AuditError::ChainDivergence { .. }
    );
}

#[tokio::test]
async fn canonical_bytes_are_deterministic() {
    let tenant = TenantId::new();
    let payload = sample_event(tenant, AuditAction::Login, 7);
    let e = build_genesis(payload).unwrap();
    let a = e.to_canonical_bytes().unwrap();
    let b = e.to_canonical_bytes().unwrap();
    assert_eq!(a, b);
}

#[tokio::test]
async fn empty_chain_verifies_clean() {
    let tenant = TenantId::new();
    let sink = Arc::new(InMemorySink::new());
    let verifier = VerifyChainUseCase::new(sink);
    let report = verifier.verify(tenant, 1, u64::MAX).await.unwrap();
    assert_eq!(report.entries_checked, 0);
    assert!(report.first_divergence_at.is_none());
}

#[tokio::test]
async fn known_fixture_hash_is_stable() {
    // A deterministic fixture: fixed tenant, fixed UserId, fixed ts, no
    // before/after — verifies that the hash of this entry is reproducible
    // across runs. The exact bytes are computed by the implementation,
    // but they MUST be invariant between runs of this test.
    use uuid::Uuid;
    let tenant: TenantId = Uuid::parse_str("00000000-0000-7000-8000-000000000001")
        .unwrap()
        .into();
    let user: UserId = Uuid::parse_str("00000000-0000-7000-8000-000000000002")
        .unwrap()
        .into();
    let payload = NewAuditEvent {
        tenant_id: tenant,
        actor: Actor::user(user),
        action: AuditAction::Login,
        resource_kind: "session".into(),
        resource_id: "s-1".into(),
        before: None,
        after: None,
        request_id: "req-1".into(),
        ts: Some(OffsetDateTime::from_unix_timestamp(0).unwrap()),
    };
    let e1 = build_entry(1, GENESIS_PREV_HASH, payload.clone()).unwrap();
    let e2 = build_entry(1, GENESIS_PREV_HASH, payload).unwrap();
    assert_eq!(e1.hash, e2.hash, "fixture hash must be reproducible");

    // Verify a single-entry chain.
    let report = verify_entries(&[e1], 1).unwrap();
    assert_eq!(report.entries_checked, 1);
}

#[rstest]
#[case(AuditAction::Login, "login")]
#[case(AuditAction::Logout, "logout")]
#[case(AuditAction::KillSwitchTriggered, "kill_switch_triggered")]
fn action_codes(#[case] a: AuditAction, #[case] expected: &str) {
    assert_eq!(a.code(), expected);
}
