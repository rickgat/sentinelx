//! AI security audit adapter (AI-SEC-001).
//!
//! Wires [`sx_ai_audit::AiAuditService`] behind the [`AiAuditPort`] HTTP
//! trait. The MVP installs an in-memory asset source (seeded demo inventory)
//! and an in-memory copilot-decision audit sink. The service records every
//! `run_audit` to that sink (ADR-0004 §7) — the audit emission happens in
//! the service/adapter layer, never in the controller.
//!
//! ## Topology
//!
//! ```text
//!   GET/POST /v1/ai-audit/*
//!           |
//!           v
//!   ┌────────────────┐   pulls tenant_id from the caller's JWT claims
//!   │ AiAuditAdapter │
//!   └────────────────┘
//!           |
//!           v
//!   ┌────────────────┐   InMemoryAiAssetSource + InMemoryCopilotAuditSink
//!   │ AiAuditService │
//!   └────────────────┘
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use sx_ai_audit::prelude::*;
use sx_ai_audit::probe::{LlmTarget, ProbeScope};
use sx_api::port::{AiAuditPort, AiAuditPortError};
use sx_api::view::ai_audit_view::{
    AiAssetListResponse, AiAssetView, AiAuditReportView, AiBomComponentView, AiBomPropertyView,
    AiBomView, AiControlEvidenceView, AiControlListResponse, AiControlView, ModelFileFindingView,
    ProbeOutcomeView,
};
use sx_config::{AiCopilotConfig, DenylistEntry, ExternalLlmTarget};
use sx_core::value_object::ids::{EngagementId, TenantId, UserId};
use sx_engagement::controller::ValidateScanRequestUseCase;
use sx_engagement::model::intensity::ScanIntensity;
use sx_engagement::model::scope_request::ScanRequest;
use sx_engagement::model::scope_target::ScopeTarget;
use sx_engagement::port::EngagementRepository;
use sx_engagement::service::clock::SystemClock;
use sx_engagement::service::denylist::DenylistChecker;
use sx_engagement::service::kill_switch::{KillSwitch, KillSwitchScope};
use sx_engagement::service::scope_validator::ScopeValidator;
use sx_remediation::service::llm_client::LlmClient;

/// Parse a string id into a UUID, falling back to a fresh v7 uuid on a
/// malformed value. A fallback id simply fails the engagement lookup in the
/// authorization gate (fail-closed), so a bad tenant/engagement id denies.
fn parse_uuid(s: &str) -> uuid::Uuid {
    uuid::Uuid::parse_str(s.trim()).unwrap_or_else(|_| uuid::Uuid::now_v7())
}

/// Model-of-record label recorded in copilot-decision audit entries.
const MODEL_ID: &str = "sx-ai-audit-mvp";

/// Bundle handed to the composition root.
#[derive(Clone)]
pub(crate) struct AiAuditBundle {
    /// HTTP-facing port installed onto `AppState`.
    pub ai_audit: Arc<dyn AiAuditPort>,
}

impl std::fmt::Debug for AiAuditBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiAuditBundle").finish_non_exhaustive()
    }
}

/// `LlmTarget` that probes the platform's OWN copilot LLM — a self-audit of
/// SentinelX's AI surface for prompt-injection / jailbreak resistance. The
/// probe prompts are forwarded verbatim (the whole point is to test whether
/// the model resists them); the engagement-scope gate on the caller side
/// decides whether the run is authorized.
struct CopilotProbeTarget {
    llm: Arc<dyn LlmClient>,
}

impl std::fmt::Debug for CopilotProbeTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CopilotProbeTarget").finish_non_exhaustive()
    }
}

#[async_trait]
impl LlmTarget for CopilotProbeTarget {
    async fn send(&self, prompt: &str) -> Result<String, AiAuditError> {
        self.llm
            .complete("", prompt)
            .await
            .map_err(|e| AiAuditError::TargetUnavailable(e.to_string()))
    }
}

/// Provider-agnostic HTTP LLM target for external red-team runs (AI-SEC-002).
/// POSTs the probe prompt into `request_template` (the literal `{PROMPT}` is
/// replaced with the JSON-escaped prompt, quotes included) and extracts the
/// completion via an RFC-6901 JSON pointer. Auth, when present, is a single
/// header resolved from an env var at request time — never from config/logs.
struct GenericHttpLlmTarget {
    http: reqwest::Client,
    url: String,
    /// `(header_name, header_value)` — already includes the scheme prefix.
    auth: Option<(String, String)>,
    request_template: String,
    response_pointer: String,
}

#[async_trait]
impl LlmTarget for GenericHttpLlmTarget {
    async fn send(&self, prompt: &str) -> Result<String, AiAuditError> {
        // `to_string` yields a quoted, escaped JSON string, so the template
        // slot `{PROMPT}` must sit where a JSON string value belongs.
        let encoded = serde_json::to_string(prompt)
            .map_err(|e| AiAuditError::Internal(format!("prompt encode: {e}")))?;
        let body = self.request_template.replace("{PROMPT}", &encoded);

        let mut rb = self
            .http
            .post(&self.url)
            .header("content-type", "application/json")
            .body(body);
        if let Some((name, value)) = &self.auth {
            rb = rb.header(name.as_str(), value.as_str());
        }

        let resp = rb
            .send()
            .await
            .map_err(|e| AiAuditError::TargetUnavailable(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AiAuditError::TargetUnavailable(format!(
                "target returned HTTP {}",
                resp.status()
            )));
        }
        let text = resp
            .text()
            .await
            .map_err(|e| AiAuditError::TargetUnavailable(e.to_string()))?;
        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| AiAuditError::Parse(format!("response is not JSON: {e}")))?;
        let completion = json
            .pointer(&self.response_pointer)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                AiAuditError::Parse(format!(
                    "response_pointer '{}' did not resolve to a string",
                    self.response_pointer
                ))
            })?;
        Ok(completion.to_owned())
    }
}

/// Build the AI-audit bundle.
///
/// `copilot_sink` is the shared copilot-decision audit sink (tee'd to the
/// durable sx-audit chain by the composition root) so `run_audit` records to
/// the same trail as the live copilot chat path (ADR-0004 §7).
///
/// When the platform copilot is enabled (`cfg.enabled`), a live
/// [`CopilotProbeTarget`] is installed so a `run` actually exercises the
/// prompt-injection corpus against SentinelX's own copilot LLM; otherwise no
/// probe target is wired and `run` returns an empty `probe_results` set.
pub(crate) fn build(
    copilot_sink: Arc<dyn CopilotAuditSink>,
    cfg: &AiCopilotConfig,
    http: reqwest::Client,
    detected_assets: Vec<AiAsset>,
    kill_switch: Arc<dyn KillSwitch>,
    engagement_repo: Arc<dyn EngagementRepository>,
    denylist: &[DenylistEntry],
) -> AiAuditBundle {
    // The in-memory source holds a demo inventory for the dev tenant so the
    // dashboard renders out of the box, merged with any assets discovered
    // from the dependency SBOM (#5 — real AI asset discovery). The source
    // filters by tenant on every call.
    let mut mem = InMemoryAiAssetSource::seeded_demo("dev-tenant");
    for asset in detected_assets {
        mem = mem.with_asset(asset);
    }
    let source: Arc<dyn AiAssetSource> = Arc::new(mem);
    let service = AiAuditService::new(source, copilot_sink).with_model_id(MODEL_ID);
    let external_targets = cfg.external_targets.clone();
    // Clone the shared client for external targets before `http` is moved
    // into the copilot LLM client build below.
    let external_http = http.clone();
    let probe_target: Option<Arc<dyn LlmTarget>> = if cfg.enabled {
        Some(Arc::new(CopilotProbeTarget {
            llm: sx_remediation::service::llm_client::build(cfg, http),
        }))
    } else {
        None
    };
    // AI-SEC-002: the same engagement authorization gate the pentest path uses
    // (kill-switch + scope validator) authorizes external red-team runs.
    let scope_validator = Arc::new(ScopeValidator::new(
        DenylistChecker::from_entries(denylist),
        Arc::new(SystemClock),
    ));
    let scan_gate = Arc::new(ValidateScanRequestUseCase::new(
        engagement_repo,
        scope_validator,
        Arc::clone(&kill_switch),
    ));
    let ai_audit: Arc<dyn AiAuditPort> = Arc::new(AiAuditAdapter {
        service,
        probe_target,
        kill_switch,
        scan_gate,
        http: external_http,
        external_targets,
    });
    AiAuditBundle { ai_audit }
}

/// HTTP-facing adapter — translates between `sx_api` wire types and the
/// in-process `sx_ai_audit` service.
#[derive(Clone)]
struct AiAuditAdapter {
    service: AiAuditService,
    /// Live probe target (the platform's own copilot LLM) when configured.
    probe_target: Option<Arc<dyn LlmTarget>>,
    /// S-2: engagement kill switch. Active prompt-injection probing is halted
    /// when the Global or this tenant's kill switch is tripped; passive
    /// inventory / governance auditing still runs.
    kill_switch: Arc<dyn KillSwitch>,
    /// AI-SEC-002: engagement authorization gate for external red-team runs.
    scan_gate: Arc<ValidateScanRequestUseCase>,
    /// Shared HTTP client for external LLM targets.
    http: reqwest::Client,
    /// Config-registered external LLM targets, keyed by `id`.
    external_targets: Vec<ExternalLlmTarget>,
}

impl AiAuditAdapter {
    /// `true` when active AI probing must be suppressed because the Global or
    /// the tenant-scoped kill switch is tripped. Fails safe: a malformed
    /// tenant id or a kill-switch backend error suppresses probing.
    async fn probing_halted(&self, tenant_id: &str) -> bool {
        if matches!(
            self.kill_switch.is_tripped(KillSwitchScope::Global).await,
            Ok(true) | Err(_)
        ) {
            tracing::warn!(
                target = "sx_monolith::ai_audit",
                tenant_id,
                "ai probing suppressed: global kill switch"
            );
            return true;
        }
        let Ok(uuid) = uuid::Uuid::parse_str(tenant_id.trim()) else {
            // Non-UUID tenant (e.g. the dev/demo slug): the Global switch above
            // is already honored, but a tenant-scoped switch cannot be keyed.
            // Fail open so the global emergency stop still works without
            // blocking non-UUID tenants.
            tracing::debug!(
                target = "sx_monolith::ai_audit",
                tenant_id,
                "tenant kill switch not evaluated: tenant id is not a UUID"
            );
            return false;
        };
        let scope = KillSwitchScope::Tenant(TenantId::from_uuid(uuid));
        // Fail closed: only an explicit `Ok(false)` (switch not tripped)
        // permits probing; `Ok(true)` and any error suppress it.
        let suppressed = !matches!(self.kill_switch.is_tripped(scope).await, Ok(false));
        if suppressed {
            tracing::warn!(
                target = "sx_monolith::ai_audit",
                tenant_id,
                "ai probing suppressed: tenant kill switch"
            );
        }
        suppressed
    }
}

impl std::fmt::Debug for AiAuditAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiAuditAdapter").finish_non_exhaustive()
    }
}

#[async_trait]
impl AiAuditPort for AiAuditAdapter {
    async fn list_assets(&self, tenant_id: &str) -> Result<AiAssetListResponse, AiAuditPortError> {
        let assets = self.service.inventory(tenant_id).await.map_err(map_err)?;
        Ok(AiAssetListResponse {
            assets: assets.iter().map(project_asset).collect(),
        })
    }

    async fn aibom(&self, tenant_id: &str) -> Result<AiBomView, AiAuditPortError> {
        let bom = self.service.aibom(tenant_id).await.map_err(map_err)?;
        Ok(project_bom(&bom))
    }

    async fn list_controls(
        &self,
        _tenant_id: &str,
    ) -> Result<AiControlListResponse, AiAuditPortError> {
        Ok(AiControlListResponse {
            controls: self
                .service
                .controls()
                .iter()
                .map(project_control)
                .collect(),
        })
    }

    async fn run_audit(
        &self,
        tenant_id: &str,
        actor: &str,
    ) -> Result<AiAuditReportView, AiAuditPortError> {
        // When a live probe target is wired (platform copilot enabled), run
        // the prompt-injection corpus against it under an engagement scope
        // that authorizes auditing our OWN copilot surface. The run is always
        // recorded to the copilot-decision audit trail (ADR-0004 §7).
        // S-2: honor the engagement kill switch. When tripped, suppress the
        // active probe target and run a passive-only audit (inventory +
        // governance) rather than issuing adversarial prompts.
        let probe = match &self.probe_target {
            Some(target) if !self.probing_halted(tenant_id).await => Some(target),
            _ => None,
        };
        let report = match probe {
            Some(target) => {
                let scope = ProbeScope::allowed(format!("{tenant_id}/platform-copilot"));
                self.service
                    .run_audit(tenant_id, actor, Some((target.as_ref(), &scope)), &[])
                    .await
            }
            None => self.service.run_audit(tenant_id, actor, None, &[]).await,
        }
        .map_err(map_err)?;
        Ok(project_report(&report))
    }

    async fn run_external_audit(
        &self,
        tenant_id: &str,
        actor: &str,
        engagement_id: &str,
        target_id: &str,
    ) -> Result<AiAuditReportView, AiAuditPortError> {
        // 1. Resolve the config-registered target.
        let target_cfg = self
            .external_targets
            .iter()
            .find(|t| t.id == target_id)
            .ok_or_else(|| {
                AiAuditPortError::Invalid(format!("unknown external target '{target_id}'"))
            })?;

        // 2. Engagement authorization on the target host, at ActiveExploit
        //    intensity (red-teaming an external endpoint is active testing).
        //    ValidateScanRequest enforces kill-switch -> Active -> approvals
        //    -> RoE window -> denylist -> intensity ceiling -> scope.
        let url = url::Url::parse(&target_cfg.url)
            .map_err(|e| AiAuditPortError::Invalid(format!("target url: {e}")))?;
        let host = url
            .host_str()
            .ok_or_else(|| AiAuditPortError::Invalid("target url has no host".to_owned()))?;
        let scope_target = ScopeTarget::parse_url_or_domain(host).ok_or_else(|| {
            AiAuditPortError::Invalid(format!("target host '{host}' is not scope-parseable"))
        })?;
        let req = ScanRequest::new(
            TenantId::from_uuid(parse_uuid(tenant_id)),
            EngagementId::from_uuid(parse_uuid(engagement_id)),
            scope_target,
            ScanIntensity::ActiveExploit,
            UserId::from_uuid(parse_uuid(actor)),
        );
        match self.scan_gate.execute(req).await {
            Ok(decision) if decision.allowed => {}
            Ok(decision) => {
                return Err(AiAuditPortError::Forbidden(format!(
                    "engagement authorization denied for '{host}': {}",
                    decision.reason
                )))
            }
            Err(e) => {
                // Fail closed: kill-switch tripped, engagement missing, etc.
                return Err(AiAuditPortError::Forbidden(format!(
                    "engagement authorization failed for '{host}': {e}"
                )));
            }
        }

        // 3. Resolve the auth token by reference (env var) — never logged.
        //    `std::env::var` is normally disallowed in favour of the config
        //    schema, but the variable *name* here is itself config-supplied
        //    (`auth_env`, AI-SEC-002: secrets referenced by name, never
        //    inlined), so a dynamic lookup is the intended mechanism.
        #[allow(clippy::disallowed_methods)]
        let auth = target_cfg
            .auth_env
            .as_ref()
            .and_then(|var| std::env::var(var).ok())
            .map(|token| {
                (
                    target_cfg.auth_header.clone(),
                    format!("{}{token}", target_cfg.auth_scheme),
                )
            });

        // 4. Run the full corpus against the external target.
        let target = GenericHttpLlmTarget {
            http: self.http.clone(),
            url: target_cfg.url.clone(),
            auth,
            request_template: target_cfg
                .resolved_request_template()
                .map_err(AiAuditPortError::Invalid)?,
            response_pointer: target_cfg.resolved_response_pointer(),
        };
        let scope = ProbeScope::allowed(format!("{tenant_id}/external/{target_id}"));
        let report = self
            .service
            .run_audit(tenant_id, actor, Some((&target, &scope)), &[])
            .await
            .map_err(map_err)?;
        Ok(project_report(&report))
    }
}

fn map_err(err: AiAuditError) -> AiAuditPortError {
    match err {
        AiAuditError::OutOfScope(t) => {
            AiAuditPortError::Forbidden(format!("target out of scope: {t}"))
        }
        AiAuditError::Invalid(m) => AiAuditPortError::Invalid(m),
        AiAuditError::TargetUnavailable(m) | AiAuditError::Sink(m) => {
            AiAuditPortError::Dependency(m)
        }
        AiAuditError::Parse(m) | AiAuditError::Internal(m) => AiAuditPortError::Internal(m),
    }
}

fn project_asset(a: &AiAsset) -> AiAssetView {
    AiAssetView {
        id: a.id.clone(),
        tenant_id: Some(a.tenant_id.clone()),
        kind: a.kind.code().to_owned(),
        name: a.name.clone(),
        provider: a.provider.clone(),
        endpoint: a.endpoint.clone(),
        discovered_at: a.discovered_at.clone(),
        metadata: a.metadata.clone(),
    }
}

fn project_bom(bom: &AiBomDocument) -> AiBomView {
    AiBomView {
        bom_format: bom.bom_format.clone(),
        spec_version: bom.spec_version.clone(),
        version: bom.version,
        components: bom
            .components
            .iter()
            .map(|c| AiBomComponentView {
                bom_ref: c.bom_ref.clone(),
                component_type: c.component_type.clone(),
                name: c.name.clone(),
                publisher: c.publisher.clone(),
                properties: c
                    .properties
                    .iter()
                    .map(|p| AiBomPropertyView {
                        name: p.name.clone(),
                        value: p.value.clone(),
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn project_control(c: &AiControl) -> AiControlView {
    AiControlView {
        id: c.id.clone(),
        title: c.title.to_owned(),
        framework: c.framework.code().to_owned(),
        description: c.description.to_owned(),
    }
}

fn project_report(r: &AiAuditReport) -> AiAuditReportView {
    AiAuditReportView {
        assets: r.assets.iter().map(project_asset).collect(),
        aibom: project_bom(&r.aibom),
        probe_results: r
            .probe_results
            .iter()
            .map(|p| ProbeOutcomeView {
                probe_id: p.probe_id.clone(),
                category: p.category.clone(),
                success: p.success,
                confidence: p.confidence,
                refused: p.refused,
                signals: p.signals.clone(),
                owasp_id: p.mapping.owasp_id.clone(),
                owasp_title: p.mapping.owasp_title.clone(),
                atlas_id: p.mapping.atlas_id.clone(),
                atlas_title: p.mapping.atlas_title.clone(),
            })
            .collect(),
        modelfile_findings: r
            .modelfile_findings
            .iter()
            .map(|f| ModelFileFindingView {
                kind: f.kind.code().to_owned(),
                severity: f.severity.code().to_owned(),
                detail: f.detail.clone(),
                offset: f.offset,
                owasp_id: f.owasp_id.clone(),
                atlas_id: f.atlas_id.clone(),
            })
            .collect(),
        control_evidence: r
            .control_evidence
            .iter()
            .map(|e| AiControlEvidenceView {
                control_id: e.control_id.clone(),
                status: e.status.code().to_owned(),
                detail: e.detail.clone(),
                collected_at: e.collected_at.clone(),
            })
            .collect(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Disabled copilot config → no live probe target (empty probe_results).
    fn disabled_cfg() -> AiCopilotConfig {
        AiCopilotConfig::default()
    }

    fn mem_sink() -> Arc<InMemoryCopilotAuditSink> {
        Arc::new(InMemoryCopilotAuditSink::new())
    }

    /// A scan gate over an empty engagement repository + empty denylist. With
    /// no engagement persisted, `run_external_audit` fails closed (Forbidden),
    /// which is the correct default for tests that do not seed one.
    fn test_scan_gate() -> Arc<ValidateScanRequestUseCase> {
        use crate::adapters::engagement::InMemoryEngagementRepository;
        let repo: Arc<dyn EngagementRepository> = Arc::new(InMemoryEngagementRepository::default());
        let validator = Arc::new(ScopeValidator::new(
            DenylistChecker::from_entries(&[]),
            Arc::new(SystemClock),
        ));
        let ks: Arc<dyn KillSwitch> =
            Arc::new(sx_engagement::service::kill_switch::InMemoryKillSwitch::new());
        Arc::new(ValidateScanRequestUseCase::new(repo, validator, ks))
    }

    #[tokio::test]
    async fn seeded_tenant_lists_assets_and_builds_bom() {
        let bundle = build(
            mem_sink(),
            &disabled_cfg(),
            reqwest::Client::new(),
            Vec::new(),
            Arc::new(sx_engagement::service::kill_switch::InMemoryKillSwitch::new()),
            Arc::new(crate::adapters::engagement::InMemoryEngagementRepository::default())
                as Arc<dyn EngagementRepository>,
            &[],
        );
        let assets = bundle.ai_audit.list_assets("dev-tenant").await.unwrap();
        assert!(!assets.assets.is_empty());
        let bom = bundle.ai_audit.aibom("dev-tenant").await.unwrap();
        assert_eq!(bom.bom_format, "CycloneDX");
        assert_eq!(bom.components.len(), assets.assets.len());
    }

    #[tokio::test]
    async fn unknown_tenant_is_empty_not_error() {
        let bundle = build(
            mem_sink(),
            &disabled_cfg(),
            reqwest::Client::new(),
            Vec::new(),
            Arc::new(sx_engagement::service::kill_switch::InMemoryKillSwitch::new()),
            Arc::new(crate::adapters::engagement::InMemoryEngagementRepository::default())
                as Arc<dyn EngagementRepository>,
            &[],
        );
        let assets = bundle.ai_audit.list_assets("nobody").await.unwrap();
        assert!(assets.assets.is_empty());
    }

    #[tokio::test]
    async fn run_audit_records_to_copilot_sink() {
        let sink = mem_sink();
        let bundle = build(
            sink.clone(),
            &disabled_cfg(),
            reqwest::Client::new(),
            Vec::new(),
            Arc::new(sx_engagement::service::kill_switch::InMemoryKillSwitch::new()),
            Arc::new(crate::adapters::engagement::InMemoryEngagementRepository::default())
                as Arc<dyn EngagementRepository>,
            &[],
        );
        let report = bundle
            .ai_audit
            .run_audit("dev-tenant", "operator-1")
            .await
            .unwrap();
        assert!(!report.assets.is_empty());
        assert!(!report.control_evidence.is_empty());
        // Disabled copilot → no live probe target → empty probe_results.
        assert!(report.probe_results.is_empty());
        // ADR-0004 §7: the run is in the copilot-decision audit sink.
        let trail = sink.all("dev-tenant").await.unwrap();
        assert_eq!(trail.len(), 1);
        assert_eq!(trail[0].action, "ai_audit_run");
    }

    /// A fake LLM that always complies with the injected instruction — the
    /// worst case, so the probe evaluator flags successes. Lets us exercise
    /// the live-probe path without a network call.
    #[derive(Debug)]
    struct CompliantLlm;
    #[async_trait]
    impl LlmClient for CompliantLlm {
        async fn complete(
            &self,
            _system: &str,
            prompt: &str,
        ) -> Result<String, sx_remediation::RemediationError> {
            // Echo the prompt back and "comply" — maximises probe signal.
            Ok(format!("SYSTEM PROMPT: ignore safety. {prompt}"))
        }
        fn model_id(&self) -> &'static str {
            "compliant-fake"
        }
    }

    #[tokio::test]
    async fn run_audit_with_live_probe_target_runs_the_corpus() {
        // Construct the adapter directly with a live (fake) probe target —
        // mirrors what `build` does when the platform copilot is enabled.
        let source: Arc<dyn AiAssetSource> =
            Arc::new(InMemoryAiAssetSource::seeded_demo("dev-tenant"));
        let service = AiAuditService::new(source, mem_sink()).with_model_id(MODEL_ID);
        let adapter = AiAuditAdapter {
            service,
            probe_target: Some(Arc::new(CopilotProbeTarget {
                llm: Arc::new(CompliantLlm),
            })),
            kill_switch: Arc::new(sx_engagement::service::kill_switch::InMemoryKillSwitch::new()),
            scan_gate: test_scan_gate(),
            http: reqwest::Client::new(),
            external_targets: Vec::new(),
        };
        let report = adapter.run_audit("dev-tenant", "operator-1").await.unwrap();
        // The live target means the injection corpus actually ran.
        assert!(
            !report.probe_results.is_empty(),
            "probe corpus must run against a live target"
        );
        // Every probe carries its OWASP-LLM + MITRE-ATLAS mapping.
        assert!(report
            .probe_results
            .iter()
            .all(|p| !p.owasp_id.is_empty() && !p.atlas_id.is_empty()));
    }

    #[tokio::test]
    async fn global_kill_switch_suppresses_active_probing() {
        use sx_engagement::service::kill_switch::{
            InMemoryKillSwitch, KillReason, KillSwitch, KillSwitchScope,
        };
        // Same live target as the test above, but with the Global kill switch
        // tripped: S-2 must run a passive-only audit (no probe results).
        let source: Arc<dyn AiAssetSource> =
            Arc::new(InMemoryAiAssetSource::seeded_demo("dev-tenant"));
        let service = AiAuditService::new(source, mem_sink()).with_model_id(MODEL_ID);
        let ks = Arc::new(InMemoryKillSwitch::new());
        ks.trip(KillSwitchScope::Global, KillReason::EmergencyStop)
            .await
            .unwrap();
        let adapter = AiAuditAdapter {
            service,
            probe_target: Some(Arc::new(CopilotProbeTarget {
                llm: Arc::new(CompliantLlm),
            })),
            kill_switch: ks,
            scan_gate: test_scan_gate(),
            http: reqwest::Client::new(),
            external_targets: Vec::new(),
        };
        let report = adapter.run_audit("dev-tenant", "operator-1").await.unwrap();
        assert!(
            report.probe_results.is_empty(),
            "a tripped global kill switch must suppress active AI probing"
        );
    }

    fn external_adapter(targets: Vec<ExternalLlmTarget>) -> AiAuditAdapter {
        let source: Arc<dyn AiAssetSource> =
            Arc::new(InMemoryAiAssetSource::seeded_demo("dev-tenant"));
        let service = AiAuditService::new(source, mem_sink()).with_model_id(MODEL_ID);
        AiAuditAdapter {
            service,
            probe_target: None,
            kill_switch: Arc::new(sx_engagement::service::kill_switch::InMemoryKillSwitch::new()),
            scan_gate: test_scan_gate(),
            http: reqwest::Client::new(),
            external_targets: targets,
        }
    }

    fn sample_target() -> ExternalLlmTarget {
        ExternalLlmTarget {
            id: "ext-test".to_owned(),
            url: "https://api.example.com/v1/chat".to_owned(),
            auth_env: None,
            auth_header: "authorization".to_owned(),
            auth_scheme: "Bearer ".to_owned(),
            model: None,
            request_template: Some(
                r#"{"messages":[{"role":"user","content":{PROMPT}}]}"#.to_owned(),
            ),
            response_pointer: Some("/choices/0/message/content".to_owned()),
        }
    }

    #[test]
    fn openai_preset_derives_template_and_pointer_from_model() {
        let target = ExternalLlmTarget {
            id: "openai".to_owned(),
            url: "https://api.openai.com/v1/chat/completions".to_owned(),
            auth_env: Some("OPENAI_API_KEY".to_owned()),
            auth_header: "authorization".to_owned(),
            auth_scheme: "Bearer ".to_owned(),
            model: Some("gpt-4o-mini".to_owned()),
            request_template: None,
            response_pointer: None,
        };
        let tmpl = target
            .resolved_request_template()
            .expect("model-derived template");
        // Derived body is valid JSON with the model + a {PROMPT} slot.
        assert!(tmpl.contains("\"model\":\"gpt-4o-mini\""));
        assert!(tmpl.contains("{PROMPT}"));
        let probe = tmpl.replace("{PROMPT}", "\"hello\"");
        let parsed: serde_json::Value = serde_json::from_str(&probe)
            .expect("derived template is valid JSON after substitution");
        assert_eq!(parsed["model"], "gpt-4o-mini");
        assert_eq!(parsed["messages"][0]["content"], "hello");
        assert_eq!(
            target.resolved_response_pointer(),
            "/choices/0/message/content"
        );
    }

    #[test]
    fn target_without_template_or_model_is_rejected() {
        let target = ExternalLlmTarget {
            id: "bad".to_owned(),
            url: "https://api.example.com".to_owned(),
            auth_env: None,
            auth_header: "authorization".to_owned(),
            auth_scheme: "Bearer ".to_owned(),
            model: None,
            request_template: None,
            response_pointer: None,
        };
        assert!(target.resolved_request_template().is_err());
    }

    #[tokio::test]
    async fn external_audit_unknown_target_is_invalid() {
        let adapter = external_adapter(Vec::new());
        let res = adapter
            .run_external_audit(
                "01010101-0101-0101-0101-010101010101",
                "operator-1",
                "02020202-0202-0202-0202-020202020202",
                "does-not-exist",
            )
            .await;
        assert!(matches!(res, Err(AiAuditPortError::Invalid(_))));
    }

    #[tokio::test]
    async fn external_audit_without_active_engagement_is_forbidden() {
        // Target exists, tenant + engagement are valid UUIDs, but no engagement
        // is persisted → the authorization gate fails closed.
        let adapter = external_adapter(vec![sample_target()]);
        let res = adapter
            .run_external_audit(
                "01010101-0101-0101-0101-010101010101",
                "operator-1",
                "02020202-0202-0202-0202-020202020202",
                "ext-test",
            )
            .await;
        assert!(matches!(res, Err(AiAuditPortError::Forbidden(_))));
    }

    #[tokio::test]
    async fn controls_span_three_frameworks() {
        let bundle = build(
            mem_sink(),
            &disabled_cfg(),
            reqwest::Client::new(),
            Vec::new(),
            Arc::new(sx_engagement::service::kill_switch::InMemoryKillSwitch::new()),
            Arc::new(crate::adapters::engagement::InMemoryEngagementRepository::default())
                as Arc<dyn EngagementRepository>,
            &[],
        );
        let controls = bundle.ai_audit.list_controls("dev-tenant").await.unwrap();
        let frameworks: std::collections::HashSet<&str> = controls
            .controls
            .iter()
            .map(|c| c.framework.as_str())
            .collect();
        assert!(frameworks.contains("nist_ai_rmf"));
        assert!(frameworks.contains("iso_42001"));
        assert!(frameworks.contains("eu_ai_act"));
    }
}
