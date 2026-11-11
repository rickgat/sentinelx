//! Concurrency: parallel `record` calls must produce monotonic seqs.

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

use sx_audit::prelude::{AuditAction, RecordAuditEventUseCase, VerifyChainUseCase};
use sx_core::value_object::ids::TenantId;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_record_produces_monotonic_seqs() {
    let tenant = TenantId::new();
    let sink = Arc::new(InMemorySink::new());
    let uc = Arc::new(RecordAuditEventUseCase::new(sink.clone()));

    const N: u64 = 50;
    let mut handles = Vec::with_capacity(N as usize);
    for i in 1..=N {
        let uc = uc.clone();
        let payload = sample_event(tenant, AuditAction::Login, i);
        handles.push(tokio::spawn(async move { uc.record(payload).await }));
    }
    for h in handles {
        h.await.unwrap().unwrap();
    }

    let entries = sink.snapshot(tenant).await;
    assert_eq!(entries.len() as u64, N);
    for (i, e) in entries.iter().enumerate() {
        assert_eq!(e.seq, (i + 1) as u64, "seq must be monotonic & start at 1");
    }

    // And the whole chain verifies.
    let verifier = VerifyChainUseCase::new(sink.clone());
    let report = verifier.verify(tenant, 1, u64::MAX).await.unwrap();
    assert_eq!(report.entries_checked, N);
}
