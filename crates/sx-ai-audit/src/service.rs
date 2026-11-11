//! The [`AiAuditService`] — composition of every `sx-ai-audit` capability.
//!
//! The service owns an [`AiAssetSource`] and a [`CopilotAuditSink`] and
//! produces an [`AiAuditReport`]. It is transport-agnostic: the HTTP adapter
//! in `services/sx-monolith` wraps it and projects the report onto wire
//! DTOs.

use std::sync::Arc;

use crate::aibom::{build_aibom, AiBomDocument};
use crate::copilot_audit::{CopilotAuditSink, CopilotDecisionAudit};
use crate::error::AiAuditError;
use crate::governance::{builtin_ai_controls, AiControl, AiControlEvidence, EvidenceStatus};
use crate::inventory::{AiAsset, AiAssetSource};
use crate::modelfile::{scan_model_file, ModelFileFinding};
use crate::probe::{run_probes, LlmTarget, ProbeOutcome, ProbeScope};

/// The default model-of-record label used in copilot-decision audit records
/// when the composition root does not override it.
pub const DEFAULT_MODEL_ID: &str = "sx-ai-audit";

/// The full output of an AI-audit run.
#[derive(Debug, Clone, PartialEq)]
pub struct AiAuditReport {
    /// AI assets in scope for the tenant.
    pub assets: Vec<AiAsset>,
    /// CycloneDX-ML-style AI-BOM built from `assets`.
    pub aibom: AiBomDocument,
    /// Probe outcomes (empty when no in-scope probe target was supplied).
    pub probe_results: Vec<ProbeOutcome>,
    /// Model-file supply-chain findings (empty when no files were supplied).
    pub modelfile_findings: Vec<ModelFileFinding>,
    /// Governance control evidence derived from the run.
    pub control_evidence: Vec<AiControlEvidence>,
}

/// Composes AI asset inventory, AI-BOM, probing, model-file scanning, and
/// governance evidence behind one service object.
#[derive(Clone)]
pub struct AiAuditService {
    source: Arc<dyn AiAssetSource>,
    copilot_sink: Arc<dyn CopilotAuditSink>,
    model_id: String,
}

impl std::fmt::Debug for AiAuditService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiAuditService")
            .field("model_id", &self.model_id)
            .finish_non_exhaustive()
    }
}

impl AiAuditService {
    /// Build a service from an asset source and a copilot audit sink.
    #[must_use]
    pub fn new(source: Arc<dyn AiAssetSource>, copilot_sink: Arc<dyn CopilotAuditSink>) -> Self {
        Self {
            source,
            copilot_sink,
            model_id: DEFAULT_MODEL_ID.to_owned(),
        }
    }

    /// Builder: set the model-of-record label used in audit records.
    #[must_use]
    pub fn with_model_id(mut self, model_id: impl Into<String>) -> Self {
        self.model_id = model_id.into();
        self
    }

    /// Enumerate the tenant's AI assets.
    ///
    /// # Errors
    ///
    /// Propagates any error from the underlying [`AiAssetSource`].
    pub async fn inventory(&self, tenant_id: &str) -> Result<Vec<AiAsset>, AiAuditError> {
        self.source.enumerate(tenant_id).await
    }

    /// Build the tenant's AI-BOM.
    ///
    /// # Errors
    ///
    /// Propagates any error from the underlying [`AiAssetSource`].
    pub async fn aibom(&self, tenant_id: &str) -> Result<AiBomDocument, AiAuditError> {
        let assets = self.inventory(tenant_id).await?;
        Ok(build_aibom(&assets))
    }

    /// The built-in AI governance control catalogue.
    #[must_use]
    #[allow(clippy::unused_self)] // method form kept for API symmetry
    pub fn controls(&self) -> Vec<AiControl> {
        builtin_ai_controls()
    }

    /// Run a full AI audit for `tenant_id` on behalf of `actor`.
    ///
    /// When `probe` is `Some`, the harness runs the probe corpus against the
    /// supplied target **only if** its [`ProbeScope`] authorizes it; an
    /// out-of-scope scope causes the whole run to fail with
    /// [`AiAuditError::OutOfScope`] before anything is sent. Each entry in
    /// `model_files` is scanned for supply-chain issues.
    ///
    /// Every run appends a [`CopilotDecisionAudit`] record (action
    /// `"ai_audit_run"`) to the sink.
    ///
    /// # Errors
    ///
    /// * Any inventory error.
    /// * [`AiAuditError::OutOfScope`] when the probe target is out of scope.
    /// * Any probe transport error.
    /// * Any sink error.
    pub async fn run_audit(
        &self,
        tenant_id: &str,
        actor: &str,
        probe: Option<(&dyn LlmTarget, &ProbeScope)>,
        model_files: &[Vec<u8>],
    ) -> Result<AiAuditReport, AiAuditError> {
        if tenant_id.is_empty() {
            return Err(AiAuditError::Invalid("tenant_id is empty".to_owned()));
        }

        let assets = self.inventory(tenant_id).await?;
        let aibom = build_aibom(&assets);

        let probe_results = match probe {
            Some((target, scope)) => run_probes(target, scope).await?,
            None => Vec::new(),
        };

        let mut modelfile_findings = Vec::new();
        for bytes in model_files {
            modelfile_findings.extend(scan_model_file(bytes));
        }

        let control_evidence =
            derive_control_evidence(&assets, &probe_results, &modelfile_findings);

        // ADR-0004 item 7 — record the run as a copilot decision. The
        // "prompt" and "response" are summaries; the sink hashes them.
        let prompt_summary = format!(
            "ai_audit_run tenant={tenant_id} assets={} model_files={}",
            assets.len(),
            model_files.len()
        );
        let probe_fails = probe_results.iter().filter(|p| p.success).count();
        let response_summary = format!(
            "assets={} probes={} probe_fails={} modelfile_findings={} controls={}",
            assets.len(),
            probe_results.len(),
            probe_fails,
            modelfile_findings.len(),
            control_evidence.len()
        );
        let record = CopilotDecisionAudit::new(
            tenant_id,
            actor,
            &self.model_id,
            "ai_audit_run",
            &prompt_summary,
            &response_summary,
        );
        self.copilot_sink.record(record).await?;

        Ok(AiAuditReport {
            assets,
            aibom,
            probe_results,
            modelfile_findings,
            control_evidence,
        })
    }

    /// Borrow the copilot audit sink (composition root read-side access).
    #[must_use]
    pub fn copilot_sink(&self) -> &Arc<dyn CopilotAuditSink> {
        &self.copilot_sink
    }
}

/// Derive governance control evidence from a run's observations.
fn derive_control_evidence(
    assets: &[AiAsset],
    probe_results: &[ProbeOutcome],
    modelfile_findings: &[ModelFileFinding],
) -> Vec<AiControlEvidence> {
    use crate::governance::ids;

    let have_assets = !assets.is_empty();
    let probed = !probe_results.is_empty();
    let scanned = !modelfile_findings.is_empty();

    let mapped_status = if have_assets {
        EvidenceStatus::Pass
    } else {
        EvidenceStatus::Manual
    };
    let measure_status = if probed || scanned {
        EvidenceStatus::Pass
    } else {
        EvidenceStatus::Manual
    };

    vec![
        AiControlEvidence::now(
            ids::NIST_GOVERN,
            EvidenceStatus::Manual,
            "Governance structure requires manual attestation.",
        ),
        AiControlEvidence::now(
            ids::NIST_MAP,
            mapped_status,
            format!("{} AI asset(s) inventoried and AI-BOM built.", assets.len()),
        ),
        AiControlEvidence::now(
            ids::NIST_MEASURE,
            measure_status,
            format!(
                "{} probe(s) and {} model-file finding(s) measured.",
                probe_results.len(),
                modelfile_findings.len()
            ),
        ),
        AiControlEvidence::now(
            ids::NIST_MANAGE,
            EvidenceStatus::Manual,
            "Risk response / remediation is tracked out of band.",
        ),
        AiControlEvidence::now(
            ids::EU_AI_ACT_LOGGING,
            EvidenceStatus::Pass,
            "Audit run recorded to the copilot-decision sink.",
        ),
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::copilot_audit::InMemoryCopilotAuditSink;
    use crate::inventory::InMemoryAiAssetSource;
    use crate::probe::RecordingLlmTarget;

    fn service() -> (AiAuditService, Arc<InMemoryCopilotAuditSink>) {
        let source: Arc<dyn AiAssetSource> = Arc::new(InMemoryAiAssetSource::seeded_demo("t-demo"));
        let sink = Arc::new(InMemoryCopilotAuditSink::new());
        let svc = AiAuditService::new(source, sink.clone()).with_model_id("test-model");
        (svc, sink)
    }

    #[tokio::test]
    async fn inventory_and_aibom_are_consistent() {
        let (svc, _) = service();
        let assets = svc.inventory("t-demo").await.unwrap();
        let bom = svc.aibom("t-demo").await.unwrap();
        assert_eq!(assets.len(), bom.components.len());
        assert!(!assets.is_empty());
    }

    #[tokio::test]
    async fn run_audit_records_a_copilot_decision() {
        let (svc, sink) = service();
        let report = svc.run_audit("t-demo", "alice", None, &[]).await.unwrap();
        assert!(!report.assets.is_empty());
        assert!(report.probe_results.is_empty());
        assert!(!report.control_evidence.is_empty());
        let audit = sink.all("t-demo").await.unwrap();
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].action, "ai_audit_run");
        assert_eq!(audit[0].model_id, "test-model");
    }

    #[tokio::test]
    async fn run_audit_with_in_scope_probe_runs_corpus() {
        let (svc, _) = service();
        let target = RecordingLlmTarget::refusing();
        let scope = ProbeScope::allowed("t-demo/llm");
        let report = svc
            .run_audit("t-demo", "alice", Some((&target, &scope)), &[])
            .await
            .unwrap();
        assert!(!report.probe_results.is_empty());
    }

    #[tokio::test]
    async fn run_audit_with_out_of_scope_probe_fails_and_sends_nothing() {
        let (svc, sink) = service();
        let target = RecordingLlmTarget::refusing();
        let scope = ProbeScope::denied("t-demo/llm");
        let err = svc
            .run_audit("t-demo", "alice", Some((&target, &scope)), &[])
            .await
            .unwrap_err();
        assert!(matches!(err, AiAuditError::OutOfScope(_)));
        assert!(target.sent().is_empty());
        // No partial audit record should be written on an out-of-scope run.
        assert!(sink.all("t-demo").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn run_audit_scans_model_files() {
        let (svc, _) = service();
        let mut malicious = vec![0x80, 0x02, b'c'];
        malicious.extend_from_slice(b"os\nsystem\n");
        malicious.push(b'R');
        let report = svc
            .run_audit("t-demo", "alice", None, &[malicious])
            .await
            .unwrap();
        assert!(!report.modelfile_findings.is_empty());
    }

    #[tokio::test]
    async fn empty_tenant_is_rejected() {
        let (svc, _) = service();
        let err = svc.run_audit("", "alice", None, &[]).await.unwrap_err();
        assert!(matches!(err, AiAuditError::Invalid(_)));
    }
}
