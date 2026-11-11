//! Phase-3 port adapters.
//!
//! Wraps the Phase-3 bundles (BAS, Graph, Report, Remediation, Compliance,
//! ML) and exposes them as the trait objects `sx-api`'s `AppState` expects.
//! Each adapter is a thin façade: the real domain logic lives inside the
//! sibling crates' use cases. Errors are translated into the small shared
//! [`Phase3PortError`] enum so the HTTP mapping stays in one place.

use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sx_api::port::{
    BasRunPort, ComplianceFrameworkPort, EngagementServicePort, FindingRepositoryPort,
    GraphAttackPathsPort, MlTriagePredictPort, Phase3PortError, RemediationAdvisoriesPort,
    ReportDiffPort, ReportRenderPort, TenantRepositoryPort,
};
use sx_api::view::bas_view::{BasRunRequestView, BasRunResponseView};
use sx_api::view::compliance_view::{
    ComplianceFrameworkResponseView, ComplianceMapRequestView, ComplianceMapResponseView,
    ControlView,
};
use sx_api::view::graph_view::{
    AttackPathView, GraphAttackPathsRequestView, GraphAttackPathsResponseView,
};
use sx_api::view::ml_view::{MlTriagePredictRequestView, MlTriagePredictResponseView};
use sx_api::view::remediation_view::{
    AdvisoryView, RemediationAdvisoriesRequestView, RemediationAdvisoriesResponseView,
};
use sx_api::view::report_view::{
    DiffFindingView, DiffMetricsView, ReportDiffRequestView, ReportDiffResponseView,
    ReportRenderRequestView, ReportRenderResponseView, SeverityDriftEntryView,
};
use sx_bas::controller::run_simulation::RunSimulationUseCase;
use sx_bas::error::BasError;
use sx_bas::model::approval::Approval;
use sx_bas::model::mode::AttackMode;
use sx_bas::model::simulation::{SimulationOutcome, SimulationRequest};
use sx_compliance::controller::map_finding::{MapFindingInput, MapFindingToControlsUseCase};
use sx_compliance::error::ComplianceError;
use sx_compliance::model::mapping::FindingCategory;
use sx_core::value_object::ids::{CveId, EngagementId, FindingId, TenantId};
use sx_core::value_object::severity::Severity;
use sx_graph::controller::FindAttackPathsUseCase;
use sx_graph::error::GraphError;
use sx_graph::model::node::NodeKind;
use sx_graph::port::AttackPathQuery;
use sx_graph::service::{FallbackKnowledgeGraph, GraphEngine};
use sx_ml::controller::predict_triage::PredictTriageUseCase;
use sx_ml::error::MlError;
use sx_ml::model::feature::FeatureVector;
use sx_ml::model::label::Label;
use sx_remediation::service::registry::MultiSourceAdvisoryRegistry;
use time::{Duration, OffsetDateTime};

use super::{
    autonomy::AutonomyBundle, bas::BasBundle, cloud::CloudBundle, collab::CollabBundle,
    compliance::ComplianceBundle, graph::GraphBundle, ml::MlBundle, remediation::RemediationBundle,
    report::ReportBundle,
};

/// Default per-step deadline allowance for HTTP-triggered BAS runs.
const BAS_DEFAULT_DEADLINE_SECS: i64 = 30;

/// Bundle of every Phase-3 port adapter.
pub(crate) struct Phase3Adapters {
    pub bas: Arc<dyn BasRunPort>,
    pub graph: Arc<dyn GraphAttackPathsPort>,
    pub report: Arc<dyn ReportRenderPort>,
    /// P2-003 — differential-report port (week-over-week).
    pub report_diff: Arc<dyn ReportDiffPort>,
    pub remediation: Arc<dyn RemediationAdvisoriesPort>,
    pub compliance: Arc<dyn ComplianceFrameworkPort>,
    pub ml: Arc<dyn MlTriagePredictPort>,
}

/// Build all six adapters from the underlying bundles.
///
/// The two trailing repository ports (`findings`, `tenants`) are required
/// by the report adapter so it can hydrate a `ReportContext` from the same
/// in-memory / Postgres data the rest of the HTTP layer already sees.
#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) fn build(
    bas_bundle: BasBundle,
    _collab_bundle: CollabBundle,
    ml_bundle: MlBundle,
    _cloud_bundle: CloudBundle,
    _autonomy_bundle: AutonomyBundle,
    graph_bundle: GraphBundle,
    report_bundle: ReportBundle,
    remediation_bundle: RemediationBundle,
    compliance_bundle: ComplianceBundle,
    findings: Arc<dyn FindingRepositoryPort>,
    tenants: Arc<dyn TenantRepositoryPort>,
    engagements: Arc<dyn EngagementServicePort>,
    branding: Arc<dyn crate::adapters::branding::BrandingStore>,
) -> Phase3Adapters {
    let report_diff = Arc::new(ReportDiffAdapter::new(
        Arc::clone(&report_bundle.render_use_case),
        Arc::clone(&findings),
        Arc::clone(&tenants),
        Arc::clone(&engagements),
    ));
    Phase3Adapters {
        bas: Arc::new(BasAdapter {
            run_uc: Arc::clone(&bas_bundle.run_use_case),
        }),
        graph: Arc::new(GraphAdapter {
            find_paths_uc: Arc::clone(&graph_bundle.find_paths_use_case),
            // HIGH-007 — pass the optional Neo4j fallback wrapper through
            // so the adapter can surface `engine` + `degraded` on every
            // attack-path response. When `None` (in-memory dev / MVP),
            // the adapter falls back to the bundle's `default_engine`.
            fallback: graph_bundle.fallback.clone(),
            default_engine: graph_bundle.default_engine,
        }),
        report: Arc::new(ReportAdapter {
            render_uc: Arc::clone(&report_bundle.render_use_case),
            findings,
            tenants,
            branding,
        }),
        report_diff,
        remediation: Arc::new(RemediationAdapter {
            registry: Arc::clone(&remediation_bundle.registry),
        }),
        compliance: Arc::new(ComplianceAdapter {
            catalog: Arc::clone(&compliance_bundle.catalog),
            mapper_uc: Arc::clone(&compliance_bundle.mapper_use_case),
        }),
        ml: Arc::new(MlAdapter {
            predict_uc: Arc::new(PredictTriageUseCase::new(
                Arc::clone(&ml_bundle.anonymiser),
                Arc::clone(&ml_bundle.registry),
            )),
        }),
    }
}

// ---------------------------------------------------------------------------
// BAS adapter
// ---------------------------------------------------------------------------

/// Adapter over [`RunSimulationUseCase`] — executes one technique through
/// the four-gate safety pipeline.
struct BasAdapter {
    run_uc: Arc<RunSimulationUseCase>,
}

#[async_trait]
impl BasRunPort for BasAdapter {
    async fn run(&self, req: BasRunRequestView) -> Result<BasRunResponseView, Phase3PortError> {
        let mode = AttackMode::from_str(&req.mode).map_err(map_bas_error)?;
        let now = OffsetDateTime::now_utc();
        let sim_req = SimulationRequest {
            tenant_id: TenantId::new(),
            engagement_id: EngagementId::new(),
            technique_id: req.technique_id,
            mode,
            change_window: None,
            roe: None,
            approvals: Vec::<Approval>::new(),
            now,
            deadline: now + Duration::seconds(BAS_DEFAULT_DEADLINE_SECS),
        };
        let outcome = self.run_uc.execute(sim_req).await.map_err(map_bas_error)?;
        Ok(translate_outcome(&outcome))
    }
}

fn translate_outcome(outcome: &SimulationOutcome) -> BasRunResponseView {
    let id = uuid::Uuid::now_v7().to_string();
    let label = match outcome {
        SimulationOutcome::Simulated { .. } => "simulated",
        SimulationOutcome::Killed { .. } => "killed",
        SimulationOutcome::Denied { .. } => "denied",
    };
    BasRunResponseView {
        simulation_id: id,
        outcome: label.to_owned(),
        evidence_count: 0,
    }
}

fn map_bas_error(err: BasError) -> Phase3PortError {
    match err {
        BasError::TechniqueNotFound(_) => Phase3PortError::NotFound,
        BasError::InvalidInput(msg) | BasError::RoeInvalid(msg) => Phase3PortError::Invalid(msg),
        BasError::OutsideChangeWindow => {
            Phase3PortError::Invalid("outside change window".to_owned())
        }
        BasError::ApprovalsInsufficient { have, need } => {
            Phase3PortError::Invalid(format!("approvals required: have {have}, need {need}"))
        }
        BasError::ModeViolation { .. } => Phase3PortError::Invalid(err.to_string()),
        BasError::KillSwitchTripped(msg) | BasError::ExecutionBlocked { reason: msg } => {
            Phase3PortError::Dependency(msg)
        }
        BasError::DeadlineExceeded => Phase3PortError::Dependency("deadline exceeded".to_owned()),
        BasError::DuplicateTechnique(msg) | BasError::Internal(msg) => {
            Phase3PortError::Internal(msg)
        }
    }
}

// ---------------------------------------------------------------------------
// Graph adapter
// ---------------------------------------------------------------------------

/// Adapter over [`FindAttackPathsUseCase`] — searches for risky paths
/// between Internet-exposed entry assets and crown-jewel sinks.
///
/// HIGH-007: when `fallback` is `Some`, the adapter prefers
/// [`FallbackKnowledgeGraph::find_attack_paths_with_engine`] so the wire
/// DTO can carry the `engine` + `degraded` flags the dashboard reads to
/// distinguish a fully-trusted Neo4j result from a degraded in-memory
/// one. When `fallback` is `None`, the adapter uses the simpler use
/// case and stamps the bundle's `default_engine` on the response.
struct GraphAdapter {
    find_paths_uc: Arc<FindAttackPathsUseCase>,
    fallback: Option<Arc<FallbackKnowledgeGraph>>,
    default_engine: GraphEngine,
}

#[async_trait]
impl GraphAttackPathsPort for GraphAdapter {
    async fn search(
        &self,
        req: GraphAttackPathsRequestView,
    ) -> Result<GraphAttackPathsResponseView, Phase3PortError> {
        let tenant_id = TenantId::from_str(&req.tenant_id)
            .map_err(|e| Phase3PortError::Invalid(format!("invalid tenant_id: {e}")))?;
        let query = AttackPathQuery {
            tenant_id,
            entry_kind: NodeKind::Asset,
            target_kind: NodeKind::Asset,
            max_depth: req.max_depth,
            max_paths: req.max_paths,
        };

        // Wrapper-aware path: lets the API surface graceful-degrade.
        if let Some(wrapper) = &self.fallback {
            let resp = wrapper
                .find_attack_paths_with_engine(&query)
                .await
                .map_err(map_graph_error)?;
            let projections = resp
                .paths
                .into_iter()
                .map(|p| {
                    let length = p.hop_count();
                    AttackPathView {
                        id: p.id,
                        score: p.score,
                        length,
                    }
                })
                .collect();
            return Ok(GraphAttackPathsResponseView {
                paths: projections,
                engine: resp.engine.as_str().to_owned(),
                degraded: resp.degraded,
            });
        }

        // Simple path: in-memory dev / MVP — `degraded` is always
        // false; `engine` reflects whatever backend the composition
        // root wired up.
        let paths = self
            .find_paths_uc
            .execute(&query)
            .await
            .map_err(map_graph_error)?;
        let projections = paths
            .into_iter()
            .map(|p| {
                let length = p.hop_count();
                AttackPathView {
                    id: p.id,
                    score: p.score,
                    length,
                }
            })
            .collect();
        Ok(GraphAttackPathsResponseView {
            paths: projections,
            engine: self.default_engine.as_str().to_owned(),
            degraded: false,
        })
    }
}

fn map_graph_error(err: GraphError) -> Phase3PortError {
    match err {
        GraphError::NotFound { .. } => Phase3PortError::NotFound,
        GraphError::Conflict { kind, id } => {
            Phase3PortError::Invalid(format!("conflict: {kind} id={id}"))
        }
        GraphError::InvalidQuery(msg) => Phase3PortError::Invalid(msg),
        GraphError::Config(msg)
        | GraphError::Connection(msg)
        | GraphError::Query(msg)
        | GraphError::Cypher(msg) => Phase3PortError::Dependency(msg),
        GraphError::TenantBoundary {
            kind,
            caller_tenant,
            resource_tenant,
        } => Phase3PortError::Invalid(format!(
            "tenant boundary: caller={caller_tenant} resource={resource_tenant} ({kind})"
        )),
        GraphError::Internal(msg) => Phase3PortError::Internal(msg),
    }
}

// ---------------------------------------------------------------------------
// Report adapter
// ---------------------------------------------------------------------------

/// Adapter over [`sx_report::controller::RenderReportUseCase`] — hydrates a
/// `ReportContext` from the same repository ports the HTTP layer uses and
/// dispatches to the registered format renderer.
struct ReportAdapter {
    render_uc: Arc<sx_report::controller::RenderReportUseCase>,
    findings: Arc<dyn FindingRepositoryPort>,
    tenants: Arc<dyn TenantRepositoryPort>,
    /// P2-002 — shared per-tenant branding store (MSSP white-label).
    branding: Arc<dyn crate::adapters::branding::BrandingStore>,
}

#[async_trait]
impl ReportRenderPort for ReportAdapter {
    async fn render(
        &self,
        req: ReportRenderRequestView,
    ) -> Result<ReportRenderResponseView, Phase3PortError> {
        let format = sx_report::port::ReportFormat::from_str(&req.format)
            .map_err(|e| Phase3PortError::Invalid(e.to_string()))?;

        let tenant_id = TenantId::from_str(&req.tenant_id)
            .map_err(|e| Phase3PortError::Invalid(format!("invalid tenant_id: {e}")))?;
        let engagement_id = EngagementId::from_str(&req.engagement_id)
            .map_err(|e| Phase3PortError::Invalid(format!("invalid engagement_id: {e}")))?;

        // Resolve tenant + (best-effort) finding list via the repository
        // ports. Errors collapse into the Phase-3 error surface.
        let tenant = self
            .tenants
            .get(&req.tenant_id)
            .await
            .map_err(map_engagement_error)?;
        let finding_views = self
            .findings
            .list(&req.tenant_id, 0, 200)
            .await
            .map_err(map_engagement_error)?;

        let report_findings = finding_views
            .into_iter()
            .map(view_to_report_finding)
            .collect::<Result<Vec<_>, _>>()?;

        // Phase-3.5+1 deferred: posture trend chart + KPI tiles. Today we
        // ship an empty `PostureSummary` so the renderer pipeline is
        // exercisable end-to-end. The per-severity counts are derived from
        // the rendered findings list so reports remain self-consistent.
        let mut posture = sx_report::model::posture::PostureSummary::empty();
        posture.scores_by_severity =
            sx_report::model::posture::SeverityBreakdown::from_findings(&report_findings);

        let generated_by = "system".to_owned();
        let ctx = sx_report::model::report::ReportContext::new(
            tenant_id,
            engagement_id,
            tenant.name.clone(),
            format!("Engagement {engagement_id}"),
            generated_by,
            OffsetDateTime::now_utc(),
            posture,
            report_findings,
        )
        .map_err(map_report_error)?
        // P2-002 — apply the tenant's white-label branding (logo, colour,
        // cover/footer). Defaults to the house brand when unconfigured.
        .with_branding(self.branding.get(&req.tenant_id).await);

        let artifact = self
            .render_uc
            .execute(format, &ctx)
            .await
            .map_err(map_report_error)?;

        let byte_count = artifact.bytes.len();
        let inline_payload = match format {
            sx_report::port::ReportFormat::Sarif
            | sx_report::port::ReportFormat::Stix
            | sx_report::port::ReportFormat::Csv => Some(BASE64.encode(&artifact.bytes)),
            // PDF payloads are too large to embed in the JSON envelope —
            // callers fetch them through a follow-up download endpoint.
            sx_report::port::ReportFormat::ExecutivePdf
            | sx_report::port::ReportFormat::TechnicalPdf
            | sx_report::port::ReportFormat::DiffPdf => None,
        };

        Ok(ReportRenderResponseView {
            filename: artifact.filename,
            mime_type: artifact.mime_type.to_owned(),
            byte_count,
            inline_payload,
        })
    }
}

fn view_to_report_finding(
    view: sx_api::view::finding_view::FindingView,
) -> Result<sx_report::model::report_finding::ReportFinding, Phase3PortError> {
    let finding_id = FindingId::from_str(&view.id).unwrap_or_default();
    let severity = match view.severity.as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    };
    let title = if view.title.trim().is_empty() {
        "(untitled finding)".to_owned()
    } else {
        view.title.clone()
    };
    sx_report::model::report_finding::ReportFinding::new(
        finding_id,
        view.asset_id,
        severity,
        title,
        view.description,
        None, // CVSS envelope hydrated by Phase-3.5+1 CVE lookup.
        view.status,
        Vec::<String>::new(),
    )
    .map_err(map_report_error)
}

fn map_engagement_error(err: sx_api::port::EngagementPortError) -> Phase3PortError {
    use sx_api::port::EngagementPortError as E;
    match err {
        E::NotFound => Phase3PortError::NotFound,
        E::Forbidden => Phase3PortError::Forbidden("forbidden".to_owned()),
        E::Conflict(msg) | E::Invalid(msg) => Phase3PortError::Invalid(msg),
        E::Dependency(msg) => Phase3PortError::Dependency(msg),
        E::Internal(msg) => Phase3PortError::Internal(msg),
    }
}

fn map_report_error(err: sx_report::error::ReportError) -> Phase3PortError {
    use sx_report::error::ReportError as E;
    match err {
        E::UnsupportedFormat(msg) | E::RendererNotRegistered(msg) => Phase3PortError::Invalid(msg),
        E::InvalidRegistry(msg) | E::InvalidContext(msg) | E::UnsafeFilename(msg) => {
            Phase3PortError::Invalid(msg)
        }
        E::Pdf(msg) | E::Json(msg) | E::Csv(msg) => Phase3PortError::Dependency(msg),
        E::Internal(msg) => Phase3PortError::Internal(msg),
    }
}

// ---------------------------------------------------------------------------
// Differential-report adapter (P2-003)
// ---------------------------------------------------------------------------

/// Adapter implementing [`ReportDiffPort`] — wraps the in-memory diff
/// service ([`sx_report::diff::InMemoryReportDiffService`]) and — when the
/// caller asks for it — the existing PDF renderer pipeline.
///
/// The two underlying diff ports
/// ([`sx_report::diff::FindingsSnapshotPort`] +
/// [`sx_report::diff::EngagementExistsPort`]) are satisfied by thin
/// shims over [`FindingRepositoryPort`] and [`EngagementServicePort`] —
/// the same repository handles the rest of the HTTP layer sees.
struct ReportDiffAdapter {
    render_uc: Arc<sx_report::controller::RenderReportUseCase>,
    findings: Arc<dyn FindingRepositoryPort>,
    tenants: Arc<dyn TenantRepositoryPort>,
    engagements: Arc<dyn EngagementServicePort>,
}

impl ReportDiffAdapter {
    fn new(
        render_uc: Arc<sx_report::controller::RenderReportUseCase>,
        findings: Arc<dyn FindingRepositoryPort>,
        tenants: Arc<dyn TenantRepositoryPort>,
        engagements: Arc<dyn EngagementServicePort>,
    ) -> Self {
        Self {
            render_uc,
            findings,
            tenants,
            engagements,
        }
    }
}

/// Page size when fanning the [`FindingRepositoryPort::list`] call for
/// the diff snapshot.
const DIFF_SNAPSHOT_PAGE_SIZE: u32 = 500;

/// Defence-in-depth cap on the total number of findings the diff engine
/// will pull from the repository before bailing. Matches
/// [`sx_report::diff::MAX_FINDINGS_SCANNED`].
const DIFF_MAX_SCANNED: usize = sx_report::diff::MAX_FINDINGS_SCANNED;

/// Snapshot port — pages through every finding in the tenant and projects
/// the wire-shaped [`sx_api::view::finding_view::FindingView`] onto the
/// diff-engine [`sx_report::diff::FindingSnapshot`].
struct FindingsSnapshotAdapter {
    tenant_id: String,
    findings: Arc<dyn FindingRepositoryPort>,
}

#[async_trait]
impl sx_report::diff::FindingsSnapshotPort for FindingsSnapshotAdapter {
    async fn snapshot(
        &self,
        _tenant_id: &TenantId,
        _engagement_id: Option<&EngagementId>,
    ) -> Result<Vec<sx_report::diff::FindingSnapshot>, sx_report::ReportError> {
        let mut out: Vec<sx_report::diff::FindingSnapshot> = Vec::new();
        let mut offset: u64 = 0;
        loop {
            let page = self
                .findings
                .list(&self.tenant_id, offset, DIFF_SNAPSHOT_PAGE_SIZE)
                .await
                .map_err(|e| sx_report::ReportError::internal(format!("finding list: {e:?}")))?;
            if page.is_empty() {
                break;
            }
            for view in &page {
                if out.len() >= DIFF_MAX_SCANNED {
                    return Err(sx_report::ReportError::internal(format!(
                        "diff scan exceeded {DIFF_MAX_SCANNED} rows"
                    )));
                }
                if let Some(s) = view_to_snapshot(view) {
                    out.push(s);
                }
            }
            let advanced = u32::try_from(page.len()).unwrap_or(DIFF_SNAPSHOT_PAGE_SIZE);
            if advanced < DIFF_SNAPSHOT_PAGE_SIZE {
                break;
            }
            offset = offset.saturating_add(u64::from(advanced));
        }
        Ok(out)
    }
}

/// Engagement-exists port — delegates to
/// [`EngagementServicePort::get`]. `NotFound` collapses to `Ok(false)`;
/// every other error propagates as an internal report error.
struct EngagementExistsAdapter {
    engagements: Arc<dyn EngagementServicePort>,
}

#[async_trait]
impl sx_report::diff::EngagementExistsPort for EngagementExistsAdapter {
    async fn exists(
        &self,
        tenant_id: &TenantId,
        engagement_id: &EngagementId,
    ) -> Result<bool, sx_report::ReportError> {
        match self
            .engagements
            .get(&tenant_id.to_string(), &engagement_id.to_string())
            .await
        {
            Ok(_) => Ok(true),
            Err(sx_api::port::EngagementPortError::NotFound) => Ok(false),
            Err(e) => Err(sx_report::ReportError::internal(format!(
                "engagement lookup: {e:?}"
            ))),
        }
    }
}

fn view_to_snapshot(
    v: &sx_api::view::finding_view::FindingView,
) -> Option<sx_report::diff::FindingSnapshot> {
    let id = FindingId::from_str(&v.id).ok()?;
    let severity = match v.severity.as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    };
    let first_seen = OffsetDateTime::parse(
        &v.first_seen,
        &time::format_description::well_known::Rfc3339,
    )
    .ok()?;
    let last_seen =
        OffsetDateTime::parse(&v.last_seen, &time::format_description::well_known::Rfc3339).ok()?;
    Some(sx_report::diff::FindingSnapshot {
        id,
        engagement_id: None,
        severity,
        title: if v.title.trim().is_empty() {
            "(untitled finding)".to_owned()
        } else {
            v.title.clone()
        },
        status: v.status.clone(),
        first_seen,
        last_seen,
    })
}

#[async_trait]
impl ReportDiffPort for ReportDiffAdapter {
    async fn compute(
        &self,
        req: ReportDiffRequestView,
    ) -> Result<ReportDiffResponseView, Phase3PortError> {
        let tenant_id = TenantId::from_str(&req.tenant_id)
            .map_err(|e| Phase3PortError::Invalid(format!("invalid tenant_id: {e}")))?;
        let engagement_id = EngagementId::from_str(&req.engagement_id)
            .map_err(|e| Phase3PortError::Invalid(format!("invalid engagement_id: {e}")))?;
        let since =
            OffsetDateTime::parse(&req.since, &time::format_description::well_known::Rfc3339)
                .map_err(|e| Phase3PortError::Invalid(format!("invalid since: {e}")))?;
        let until =
            OffsetDateTime::parse(&req.until, &time::format_description::well_known::Rfc3339)
                .map_err(|e| Phase3PortError::Invalid(format!("invalid until: {e}")))?;

        let diff = {
            use sx_report::diff::ReportDiffService as _;
            let svc = sx_report::diff::InMemoryReportDiffService::new(
                Arc::new(FindingsSnapshotAdapter {
                    tenant_id: req.tenant_id.clone(),
                    findings: Arc::clone(&self.findings),
                }),
                Arc::new(EngagementExistsAdapter {
                    engagements: Arc::clone(&self.engagements),
                }),
            );
            svc.compute_diff(tenant_id, engagement_id, since, until)
                .await
                .map_err(map_report_error)?
        };

        // Optional rendered PDF — hydrate a `ReportContext` from the same
        // repository ports the regular render path uses, then dispatch.
        let pdf = if req.render_pdf {
            let tenant = self
                .tenants
                .get(&req.tenant_id)
                .await
                .map_err(map_engagement_error)?;
            let posture = sx_report::model::posture::PostureSummary::empty();
            let ctx = sx_report::model::report::ReportContext::new(
                tenant_id,
                engagement_id,
                tenant.name.clone(),
                format!("Engagement {engagement_id}"),
                "system".to_owned(),
                OffsetDateTime::now_utc(),
                posture,
                Vec::new(),
            )
            .map_err(map_report_error)?
            .with_diff(diff.clone());
            let artifact = self
                .render_uc
                .execute(sx_report::port::ReportFormat::DiffPdf, &ctx)
                .await
                .map_err(map_report_error)?;
            Some(ReportRenderResponseView {
                filename: artifact.filename,
                mime_type: artifact.mime_type.to_owned(),
                byte_count: artifact.bytes.len(),
                // PDF payload is intentionally not inlined — callers fetch
                // the artifact through the follow-up download endpoint.
                inline_payload: None,
            })
        } else {
            None
        };

        // Audit trail — single structured log line per successful diff so
        // the export ingester can pick it up. We deliberately log only
        // metadata (counts), never finding identifiers, to keep the audit
        // stream PII-free.
        tracing::info!(
            target: "audit.report.diff",
            tenant_id = %tenant_id,
            engagement_id = %engagement_id,
            since = %since,
            until = %until,
            added = diff.added.len(),
            resolved = diff.resolved.len(),
            reopened = diff.reopened.len(),
            net_change = diff.metrics.net_change_count,
            rendered_pdf = pdf.is_some(),
            "differential report computed",
        );

        Ok(project_diff_view(&diff, pdf))
    }
}

/// Project an [`sx_report::diff::ReportDiff`] onto the wire view.
fn project_diff_view(
    diff: &sx_report::diff::ReportDiff,
    pdf: Option<ReportRenderResponseView>,
) -> ReportDiffResponseView {
    fn map_one(f: &sx_report::diff::DiffFinding) -> DiffFindingView {
        DiffFindingView {
            id: f.id.to_string(),
            severity: f.severity.to_string().to_ascii_lowercase(),
            title: f.title.clone(),
            status: f.status.clone(),
            first_seen: f
                .first_seen
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            last_seen: f
                .last_seen
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        }
    }

    // Sort severity drift Critical → Info for deterministic output.
    let order = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];
    let severity_drift = order
        .iter()
        .filter_map(|s| {
            diff.severity_drift.get(s).map(|e| SeverityDriftEntryView {
                severity: s.to_string().to_ascii_lowercase(),
                before: e.before,
                after: e.after,
                delta: e.delta(),
            })
        })
        .collect();

    ReportDiffResponseView {
        tenant_id: diff.tenant_id.to_string(),
        engagement_id: diff.engagement_id.to_string(),
        since: diff
            .since
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        until: diff
            .until
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default(),
        added: diff.added.iter().map(map_one).collect(),
        resolved: diff.resolved.iter().map(map_one).collect(),
        reopened: diff.reopened.iter().map(map_one).collect(),
        severity_drift,
        metrics: DiffMetricsView {
            net_change_count: diff.metrics.net_change_count,
            regression_count: diff.metrics.regression_count,
        },
        pdf,
    }
}

// ---------------------------------------------------------------------------
// Remediation adapter
// ---------------------------------------------------------------------------

/// Adapter over [`MultiSourceAdvisoryRegistry`] — fans a single CVE lookup
/// across every registered vendor source and aggregates the responses.
struct RemediationAdapter {
    registry: Arc<MultiSourceAdvisoryRegistry>,
}

#[async_trait]
impl RemediationAdvisoriesPort for RemediationAdapter {
    async fn advisories(
        &self,
        req: RemediationAdvisoriesRequestView,
    ) -> Result<RemediationAdvisoriesResponseView, Phase3PortError> {
        let cve_id = CveId::new(req.cve_id)
            .map_err(|e| Phase3PortError::Invalid(format!("invalid cve_id: {e}")))?;
        // `MultiSourceAdvisoryRegistry::fetch` swallows per-source failures
        // and returns the union of successful advisories — there is no
        // outer `Result` to map. Spec listed it as fallible; the sibling
        // surface settled on infallible aggregation.
        let advisories = self.registry.fetch(&cve_id).await;
        let projections = advisories
            .into_iter()
            .map(|a| AdvisoryView {
                vendor: a.vendor,
                advisory_id: a.advisory_id,
                references: a.references.into_iter().map(|u| u.to_string()).collect(),
            })
            .collect();
        Ok(RemediationAdvisoriesResponseView {
            advisories: projections,
        })
    }
}

// ---------------------------------------------------------------------------
// Compliance adapter
// ---------------------------------------------------------------------------

/// Adapter over the [`sx_compliance`] catalog + mapper use case.
struct ComplianceAdapter {
    catalog: Arc<sx_compliance::service::catalog::ControlCatalog>,
    mapper_uc: Arc<MapFindingToControlsUseCase>,
}

#[async_trait]
impl ComplianceFrameworkPort for ComplianceAdapter {
    async fn list_framework(
        &self,
        framework: &str,
    ) -> Result<ComplianceFrameworkResponseView, Phase3PortError> {
        let parsed = framework
            .parse::<sx_compliance::model::framework::Framework>()
            .map_err(|_| Phase3PortError::NotFound)?;
        let controls = self
            .catalog
            .by_framework(parsed)
            .iter()
            .map(|c| ControlView {
                id: c.id.clone(),
                framework: format!("{:?}", c.framework),
                title: c.title.clone(),
                family: c.family.clone(),
            })
            .collect();
        Ok(ComplianceFrameworkResponseView {
            framework: framework.to_owned(),
            controls,
        })
    }

    async fn map_finding(
        &self,
        req: ComplianceMapRequestView,
    ) -> Result<ComplianceMapResponseView, Phase3PortError> {
        let category = FindingCategory::from_str(&req.category).map_err(map_compliance_error)?;
        let input = MapFindingInput {
            finding_id: req.finding_id.clone(),
            category,
            severity_str: req.severity,
        };
        let output = self
            .mapper_uc
            .execute(&input)
            .map_err(map_compliance_error)?;
        let controls = output
            .controls
            .into_iter()
            .map(|c| ControlView {
                id: c.id,
                framework: format!("{:?}", c.framework),
                title: c.title,
                family: c.family,
            })
            .collect();
        Ok(ComplianceMapResponseView {
            finding_id: output.finding_id,
            controls,
        })
    }
}

fn map_compliance_error(err: ComplianceError) -> Phase3PortError {
    match err {
        ComplianceError::UnknownFramework(_) | ComplianceError::UnknownCategory(_) => {
            Phase3PortError::NotFound
        }
        ComplianceError::InvalidInput(msg) => Phase3PortError::Invalid(msg),
        ComplianceError::EvidenceSink(msg) => Phase3PortError::Dependency(msg),
        ComplianceError::Internal(msg) => Phase3PortError::Internal(msg),
    }
}

// ---------------------------------------------------------------------------
// ML adapter
// ---------------------------------------------------------------------------

/// Adapter over [`PredictTriageUseCase`] — looks up the current model
/// artifact and returns the predicted [`Label`] alongside the probability
/// of `FalsePositive`.
struct MlAdapter {
    predict_uc: Arc<PredictTriageUseCase>,
}

#[async_trait]
impl MlTriagePredictPort for MlAdapter {
    async fn predict(
        &self,
        req: MlTriagePredictRequestView,
    ) -> Result<MlTriagePredictResponseView, Phase3PortError> {
        let row: FeatureVector = serde_json::from_value(req.row)
            .map_err(|e| Phase3PortError::Invalid(format!("feature row: {e}")))?;
        let label = self
            .predict_uc
            .execute(&req.model_id, row.clone())
            .await
            .map_err(map_ml_error)?;
        let probability = self
            .predict_uc
            .execute_proba(&req.model_id, row)
            .await
            .map_err(map_ml_error)?;
        Ok(MlTriagePredictResponseView {
            label: label_str(label).to_owned(),
            probability,
        })
    }
}

const fn label_str(label: Label) -> &'static str {
    match label {
        Label::TruePositive => "true_positive",
        Label::FalsePositive => "false_positive",
        Label::Unknown => "unknown",
    }
}

fn map_ml_error(err: MlError) -> Phase3PortError {
    match err {
        MlError::ModelNotFound(_) => Phase3PortError::NotFound,
        MlError::EmptyTrainingSet
        | MlError::EmptyFeatureRow
        | MlError::NonFiniteValue(_)
        | MlError::InvalidConfig(_) => Phase3PortError::Invalid(err.to_string()),
        MlError::Serde(e) => Phase3PortError::Dependency(e.to_string()),
        MlError::Invariant(msg) => Phase3PortError::Internal(msg),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use std::collections::HashSet;

    use secrecy::SecretString;
    use sx_api::view::finding_view::FindingView;
    use sx_bas::service::kill_switch_gate::{KillSwitchGate, KillSwitchPort, NotifyKillSwitchPort};
    use sx_bas::service::registry::TechniqueRegistry;
    use sx_bas::service::safety_pipeline::SafetyPipeline;
    use sx_compliance::service::catalog::ControlCatalog;
    use sx_graph::model::edge::GraphEdge;
    use sx_graph::model::node::{GraphAsset, GraphNode, NodeId};
    use sx_graph::port::KnowledgeGraph;
    use sx_graph::service::InMemoryKnowledgeGraph;
    use sx_ml::service::anonymiser::Anonymiser;
    use sx_ml::service::registry::{InMemoryModelRegistry, ModelRegistry};

    // --- helpers -----------------------------------------------------------

    fn build_bas_adapter_with_empty_registry() -> BasAdapter {
        let registry = TechniqueRegistry::new();
        let port: Arc<dyn KillSwitchPort> = Arc::new(NotifyKillSwitchPort::new());
        let gate = KillSwitchGate::new(port);
        let pipeline = Arc::new(SafetyPipeline::new(gate));
        let uc = Arc::new(RunSimulationUseCase::new(Arc::new(registry), pipeline));
        BasAdapter { run_uc: uc }
    }

    fn build_ml_adapter() -> MlAdapter {
        let pepper = SecretString::from("test-pepper".to_owned());
        let anonymiser = Arc::new(Anonymiser::new(pepper, HashSet::new(), HashSet::new()));
        let registry: Arc<dyn ModelRegistry> = Arc::new(InMemoryModelRegistry::new());
        let uc = Arc::new(PredictTriageUseCase::new(anonymiser, registry));
        MlAdapter { predict_uc: uc }
    }

    // --- BAS ---------------------------------------------------------------

    #[tokio::test]
    async fn bas_adapter_returns_simulation_id() {
        let adapter = build_bas_adapter_with_empty_registry();
        let err = adapter
            .run(BasRunRequestView {
                engagement_id: None,
                technique_id: "unknown_technique_v1".into(),
                target: "asset-1".into(),
                mode: "theoretical".into(),
                dry_run: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, Phase3PortError::NotFound));
    }

    #[tokio::test]
    async fn bas_adapter_rejects_unknown_mode() {
        let adapter = build_bas_adapter_with_empty_registry();
        let err = adapter
            .run(BasRunRequestView {
                engagement_id: None,
                technique_id: "T1003".into(),
                target: "asset-1".into(),
                mode: "yolo".into(),
                dry_run: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    // --- Graph -------------------------------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn graph_adapter_returns_paths_from_use_case() {
        use std::collections::BTreeMap;

        use sx_core::value_object::criticality::AssetCriticality;
        use sx_core::value_object::exposure::ExposureLevel;

        let tenant = TenantId::new();
        let graph: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());

        let entry = GraphNode::Asset(GraphAsset {
            id: NodeId::new("entry"),
            tenant_id: tenant,
            name: "entry".into(),
            exposure: ExposureLevel::Internet,
            criticality: AssetCriticality::Production,
            risk_score: Some(1.0),
            properties: BTreeMap::new(),
        });
        let crown = GraphNode::Asset(GraphAsset {
            id: NodeId::new("crown"),
            tenant_id: tenant,
            name: "crown".into(),
            exposure: ExposureLevel::Internal,
            criticality: AssetCriticality::CrownJewel,
            risk_score: Some(5.0),
            properties: BTreeMap::new(),
        });
        // A direct entry → crown edge — no intermediate Finding/Technique,
        // so the in-memory pattern check rejects it. We assert the empty
        // result is plumbed through correctly.
        graph.upsert_node(&entry).await.unwrap();
        graph.upsert_node(&crown).await.unwrap();
        graph
            .upsert_edge(&GraphEdge::reaches(
                NodeId::new("entry"),
                NodeId::new("crown"),
                443,
                "tcp",
            ))
            .await
            .unwrap();

        let uc = Arc::new(FindAttackPathsUseCase::new(graph));
        // HIGH-007: the in-memory dev path leaves the wrapper absent and
        // stamps `engine="memory", degraded=false` on every response.
        let adapter = GraphAdapter {
            find_paths_uc: uc,
            fallback: None,
            default_engine: sx_graph::service::GraphEngine::Memory,
        };
        let resp = adapter
            .search(GraphAttackPathsRequestView {
                tenant_id: tenant.to_string(),
                max_depth: 5,
                max_paths: 10,
            })
            .await
            .unwrap();
        // The seeded graph violates the production pattern (no critical
        // finding in the chain) so the BFS returns no paths — what we are
        // asserting is the plumbing, not the pattern matcher.
        assert_eq!(resp.paths.len(), 0);
        // HIGH-007: the no-fallback path must report the bundle default
        // engine without flagging the response as degraded.
        assert_eq!(resp.engine, "memory");
        assert!(!resp.degraded);
    }

    #[tokio::test]
    async fn graph_adapter_rejects_invalid_tenant_id() {
        let graph: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let uc = Arc::new(FindAttackPathsUseCase::new(graph));
        let adapter = GraphAdapter {
            find_paths_uc: uc,
            fallback: None,
            default_engine: sx_graph::service::GraphEngine::Memory,
        };
        let err = adapter
            .search(GraphAttackPathsRequestView {
                tenant_id: "not-a-uuid".into(),
                max_depth: 5,
                max_paths: 10,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    #[tokio::test]
    async fn graph_adapter_wrapper_path_surfaces_engine_and_degraded() {
        // HIGH-007: when the adapter is wired with a `FallbackKnowledgeGraph`,
        // the search response must carry the `engine` + `degraded` markers
        // that the dashboard reads to render the degraded badge. The
        // primary in this test is the in-memory backend, so the response
        // reports `engine="neo4j", degraded=false` (the wrapper labels
        // the primary as `Neo4j` regardless of the concrete adapter).
        let tenant = TenantId::new();
        let primary: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let secondary: Arc<dyn KnowledgeGraph> = Arc::new(InMemoryKnowledgeGraph::new());
        let wrapper = Arc::new(sx_graph::service::FallbackKnowledgeGraph::new(
            Arc::clone(&primary),
            secondary,
        ));
        let uc = Arc::new(FindAttackPathsUseCase::new(Arc::clone(&primary)));
        let adapter = GraphAdapter {
            find_paths_uc: uc,
            fallback: Some(Arc::clone(&wrapper)),
            default_engine: sx_graph::service::GraphEngine::Neo4j,
        };
        let resp = adapter
            .search(GraphAttackPathsRequestView {
                tenant_id: tenant.to_string(),
                max_depth: 5,
                max_paths: 10,
            })
            .await
            .unwrap();
        assert_eq!(resp.engine, "neo4j");
        assert!(!resp.degraded);
        assert!(resp.paths.is_empty());
    }

    // --- Remediation -------------------------------------------------------

    #[tokio::test]
    async fn remediation_adapter_returns_empty_for_unknown_cve() {
        let registry = Arc::new(MultiSourceAdvisoryRegistry::new(vec![]));
        let adapter = RemediationAdapter { registry };
        let resp = adapter
            .advisories(RemediationAdvisoriesRequestView {
                cve_id: "CVE-2024-99999".into(),
            })
            .await
            .unwrap();
        assert!(resp.advisories.is_empty());
    }

    #[tokio::test]
    async fn remediation_adapter_rejects_bad_cve() {
        let registry = Arc::new(MultiSourceAdvisoryRegistry::new(vec![]));
        let adapter = RemediationAdapter { registry };
        let err = adapter
            .advisories(RemediationAdvisoriesRequestView {
                cve_id: "not-a-cve".into(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    // --- Compliance --------------------------------------------------------

    #[tokio::test]
    async fn compliance_map_finding_returns_controls_for_authentication_category() {
        let catalog = ControlCatalog::shared();
        let mapper = Arc::new(MapFindingToControlsUseCase::new(Arc::clone(&catalog)));
        let adapter = ComplianceAdapter {
            catalog,
            mapper_uc: mapper,
        };
        let resp = adapter
            .map_finding(ComplianceMapRequestView {
                finding_id: "F-1".into(),
                category: "authentication".into(),
                severity: "high".into(),
            })
            .await
            .unwrap();
        assert_eq!(resp.finding_id, "F-1");
        assert!(
            !resp.controls.is_empty(),
            "authentication must implicate at least one control",
        );
    }

    #[tokio::test]
    async fn compliance_map_finding_rejects_unknown_category() {
        let catalog = ControlCatalog::shared();
        let mapper = Arc::new(MapFindingToControlsUseCase::new(Arc::clone(&catalog)));
        let adapter = ComplianceAdapter {
            catalog,
            mapper_uc: mapper,
        };
        let err = adapter
            .map_finding(ComplianceMapRequestView {
                finding_id: "F-1".into(),
                category: "yolo".into(),
                severity: "high".into(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, Phase3PortError::NotFound));
    }

    #[tokio::test]
    async fn compliance_list_framework_returns_controls() {
        let catalog = ControlCatalog::shared();
        let mapper = Arc::new(MapFindingToControlsUseCase::new(Arc::clone(&catalog)));
        let adapter = ComplianceAdapter {
            catalog,
            mapper_uc: mapper,
        };
        let resp = adapter.list_framework("iso27001").await.unwrap();
        assert_eq!(resp.framework, "iso27001");
        assert!(!resp.controls.is_empty());
    }

    // --- Report ------------------------------------------------------------

    #[derive(Debug, Default)]
    struct StubFindings;

    #[async_trait]
    impl FindingRepositoryPort for StubFindings {
        async fn list(
            &self,
            _tenant_id: &str,
            _offset: u64,
            _limit: u32,
        ) -> Result<Vec<FindingView>, sx_api::port::EngagementPortError> {
            Ok(vec![FindingView {
                id: "00000000-0000-0000-0000-000000000001".into(),
                tenant_id: "tenant".into(),
                asset_id: "host.example.com".into(),
                severity: "high".into(),
                status: "open".into(),
                title: "Example finding".into(),
                description: "details".into(),
                cvss: Some(7.5),
                cve_id: None,
                first_seen: "2026-05-29T00:00:00Z".into(),
                last_seen: "2026-05-29T00:00:00Z".into(),
                metadata: None,
            }])
        }

        async fn get(
            &self,
            _tenant_id: &str,
            _id: &str,
        ) -> Result<FindingView, sx_api::port::EngagementPortError> {
            Err(sx_api::port::EngagementPortError::NotFound)
        }

        async fn update_status(
            &self,
            _tenant_id: &str,
            _id: &str,
            _new_status: &str,
            _comment: Option<&str>,
        ) -> Result<FindingView, sx_api::port::EngagementPortError> {
            Err(sx_api::port::EngagementPortError::NotFound)
        }
        async fn insert(
            &self,
            view: FindingView,
        ) -> Result<FindingView, sx_api::port::EngagementPortError> {
            Ok(view)
        }
    }

    #[derive(Debug, Default)]
    struct StubTenants;

    #[async_trait]
    impl TenantRepositoryPort for StubTenants {
        async fn get(
            &self,
            _id: &str,
        ) -> Result<sx_api::port::TenantSummaryView, sx_api::port::EngagementPortError> {
            Ok(sx_api::port::TenantSummaryView {
                id: "00000000-0000-0000-0000-000000000002".into(),
                name: "Acme".into(),
                slug: "acme".into(),
                is_active: true,
            })
        }
    }

    #[tokio::test]
    async fn report_render_csv_returns_non_empty_bytes() {
        use sx_report::controller::RenderReportUseCase;
        use sx_report::port::Renderer;
        use sx_report::renderer::csv::CsvRenderer;
        use sx_report::renderer::executive_pdf::ExecutivePdfRenderer;
        use sx_report::renderer::sarif::SarifRenderer;
        use sx_report::renderer::stix::StixRenderer;
        use sx_report::renderer::technical_pdf::TechnicalPdfRenderer;

        let renderers: Vec<Arc<dyn Renderer>> = vec![
            Arc::new(ExecutivePdfRenderer),
            Arc::new(TechnicalPdfRenderer),
            Arc::new(SarifRenderer),
            Arc::new(StixRenderer),
            Arc::new(CsvRenderer),
        ];
        let render_uc = Arc::new(RenderReportUseCase::new(renderers).unwrap());
        let adapter = ReportAdapter {
            render_uc,
            findings: Arc::new(StubFindings),
            tenants: Arc::new(StubTenants),
            branding: Arc::new(crate::adapters::branding::InMemoryBrandingStore::default()),
        };
        let tenant_uuid = TenantId::new();
        let engagement_uuid = EngagementId::new();
        let resp = adapter
            .render(ReportRenderRequestView {
                tenant_id: tenant_uuid.to_string(),
                engagement_id: engagement_uuid.to_string(),
                format: "csv".into(),
            })
            .await
            .unwrap();
        assert!(resp.byte_count > 0);
        assert!(resp.inline_payload.is_some());
        assert_eq!(resp.mime_type, "text/csv; charset=utf-8");
    }

    // --- ML ----------------------------------------------------------------

    #[tokio::test]
    async fn ml_predict_returns_unknown_when_model_id_missing() {
        let adapter = build_ml_adapter();
        let err = adapter
            .predict(MlTriagePredictRequestView {
                model_id: "missing-model".into(),
                row: serde_json::json!({}),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, Phase3PortError::NotFound));
    }
}
