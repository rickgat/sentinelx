//! Property-based tests for chain invariants.

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

use common::{sample_event, InMemorySink};
use proptest::prelude::*;
use std::sync::Arc;
use tokio::runtime::Runtime;

use sx_audit::prelude::{
    verify_entries, AuditAction, AuditError, RecordAuditEventUseCase, VerifyChainUseCase,
};
use sx_core::value_object::ids::TenantId;

fn arb_action() -> impl Strategy<Value = AuditAction> {
    prop_oneof![
        Just(AuditAction::Login),
        Just(AuditAction::Logout),
        Just(AuditAction::LoginFailed),
        Just(AuditAction::EngagementCreated),
        Just(AuditAction::EngagementUpdated),
        Just(AuditAction::ScanStarted),
        Just(AuditAction::ScanCompleted),
        Just(AuditAction::FindingCreated),
        Just(AuditAction::FindingConfirmed),
        Just(AuditAction::KillSwitchTriggered),
        Just(AuditAction::ScopeMutated),
        Just(AuditAction::SecretAccessed),
        ".{1,16}".prop_map(|code| AuditAction::Custom { code }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Any sequence of valid actions appended in order produces a chain
    /// that verifies end-to-end.
    #[test]
    fn appended_chain_verifies(actions in proptest::collection::vec(arb_action(), 1..16)) {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let tenant = TenantId::new();
            let sink = Arc::new(InMemorySink::new());
            let uc = RecordAuditEventUseCase::new(sink.clone());
            for (i, action) in actions.iter().enumerate() {
                let ev = sample_event(tenant, action.clone(), (i + 1) as u64);
                uc.record(ev).await.unwrap();
            }
            let verifier = VerifyChainUseCase::new(sink);
            let report = verifier.verify(tenant, 1, u64::MAX).await.unwrap();
            prop_assert_eq!(report.entries_checked, actions.len() as u64);
            prop_assert!(report.first_divergence_at.is_none());
            Ok(())
        })?;
    }

    /// Tampering with any single mid-chain entry's `request_id` produces
    /// a [`AuditError::ChainDivergence`] at exactly that seq.
    #[test]
    fn middle_tamper_diverges_at_that_seq(
        n in 3usize..10,
        target_offset in 0usize..3,
    ) {
        let rt = Runtime::new().unwrap();
        rt.block_on(async move {
            let tenant = TenantId::new();
            let sink = Arc::new(InMemorySink::new());
            let uc = RecordAuditEventUseCase::new(sink.clone());
            for i in 1..=n {
                let ev = sample_event(tenant, AuditAction::Login, i as u64);
                uc.record(ev).await.unwrap();
            }
            // Pick a middle index in [1, n-2].
            let target_idx = 1 + (target_offset % (n - 2));
            let target_seq = (target_idx + 1) as u64;
            sink.tamper(tenant, |v| {
                v[target_idx].request_id = "TAMPERED".into();
            })
            .await;

            let entries = sink.snapshot(tenant).await;
            let err = verify_entries(&entries, 1).expect_err("must fail");
            match err {
                AuditError::ChainDivergence { at_seq, .. } => {
                    prop_assert_eq!(at_seq, target_seq);
                }
                other => prop_assert!(false, "expected ChainDivergence, got {other:?}"),
            }
            Ok(())
        })?;
    }
}
