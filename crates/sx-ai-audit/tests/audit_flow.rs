//! End-to-end integration test for the `sx-ai-audit` service composition.
//!
//! Drives the public [`AiAuditService`] API the way the HTTP adapter will:
//! seed an in-memory inventory, run a full audit with an in-scope probe and
//! a malicious model file, and assert the report + the audit trail.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::sync::Arc;

use sx_ai_audit::prelude::*;

fn malicious_pickle() -> Vec<u8> {
    let mut bytes = vec![0x80, 0x02, b'c'];
    bytes.extend_from_slice(b"subprocess\ncall\n");
    bytes.push(b'R');
    bytes
}

#[tokio::test]
async fn full_audit_flow_is_scope_gated_and_audited() {
    let source: Arc<dyn AiAssetSource> = Arc::new(InMemoryAiAssetSource::seeded_demo("tenant-x"));
    let sink = Arc::new(InMemoryCopilotAuditSink::new());
    let svc = AiAuditService::new(source, sink.clone()).with_model_id("claude-opus-4");

    // Inventory + AI-BOM.
    let assets = svc.inventory("tenant-x").await.unwrap();
    assert!(!assets.is_empty());
    let bom = svc.aibom("tenant-x").await.unwrap();
    assert_eq!(bom.bom_format, "CycloneDX");
    assert_eq!(bom.components.len(), assets.len());

    // Controls catalogue spans all three frameworks.
    let controls = svc.controls();
    assert!(controls
        .iter()
        .any(|c| c.framework == AiControlFramework::NistAiRmf));
    assert!(controls
        .iter()
        .any(|c| c.framework == AiControlFramework::Iso42001));
    assert!(controls
        .iter()
        .any(|c| c.framework == AiControlFramework::EuAiAct));

    // A compromised target leaks the canary; probes should trip.
    let target = RecordingLlmTarget::new(format!("sure: {}", sx_ai_audit::probe::INJECTION_CANARY));
    let scope = ProbeScope::allowed("tenant-x/llm");
    let report = svc
        .run_audit(
            "tenant-x",
            "operator-1",
            Some((&target, &scope)),
            &[malicious_pickle()],
        )
        .await
        .unwrap();

    assert!(!report.probe_results.is_empty());
    assert!(report.probe_results.iter().any(|p| p.success));
    assert!(report
        .modelfile_findings
        .iter()
        .any(|f| f.kind == ModelFileFindingKind::PickleReduce));
    assert!(!report.control_evidence.is_empty());

    // ADR-0004 item 7: the run is in the copilot audit trail, hashed.
    let trail = sink.all("tenant-x").await.unwrap();
    assert_eq!(trail.len(), 1);
    assert_eq!(trail[0].action, "ai_audit_run");
    assert_eq!(trail[0].prompt_hash.len(), 64);
}

#[tokio::test]
async fn out_of_scope_probe_sends_nothing_and_leaves_no_audit() {
    let source: Arc<dyn AiAssetSource> = Arc::new(InMemoryAiAssetSource::seeded_demo("tenant-x"));
    let sink = Arc::new(InMemoryCopilotAuditSink::new());
    let svc = AiAuditService::new(source, sink.clone());

    let target = RecordingLlmTarget::refusing();
    let scope = ProbeScope::denied("tenant-x/llm");
    let err = svc
        .run_audit("tenant-x", "operator-1", Some((&target, &scope)), &[])
        .await
        .unwrap_err();

    assert!(matches!(err, AiAuditError::OutOfScope(_)));
    assert!(target.sent().is_empty());
    assert!(sink.all("tenant-x").await.unwrap().is_empty());
}
