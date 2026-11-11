//! Autonomy port adapters.
//!
//! Exposes the three autonomy capabilities — auto-remediation PR generation,
//! anonymised threat-network submission, and continuous-validation engine
//! scheduling — as trait objects matching the new ports defined in
//! [`sx_api::port`]. Each adapter is a thin façade around the relevant
//! `sx_autonomy::prelude` types.
//!
//! ## Wiring choices
//!
//! - The PR-generator adapter is generic over [`GithubClient`] so tests can
//!   inject a recording `FakeGithubClient` without standing up an HTTP
//!   server.
//! - The threat-network adapter takes the endpoint URL as a parameter. When
//!   no configuration field carries it, [`DEFAULT_THREAT_NETWORK_ENDPOINT`]
//!   is used as a documented placeholder.
//! - The schedule adapter keeps a `HashMap<String, EngineHandle>` keyed by
//!   the engine id it returns to the caller. `cancel` joins
//!   `EngineHandle::shutdown` synchronously and returns
//!   [`Phase3PortError::NotFound`] when the id is unknown (which makes a
//!   second cancel idempotent rather than silent).
//!
//! ## Safety
//!
//! - `#![forbid(unsafe_code)]` is inherited from the workspace.
//! - No `unwrap`/`expect`/`panic!` on production paths; every fallible
//!   call is mapped into [`Phase3PortError`] or its parent
//!   [`anyhow::Error`].
//! - The PR-generator adapter does NOT bypass the autonomy safety pipeline.
//!   `AutoRemediationPrGenerator::propose` enforces the protected-branch
//!   list, diff-size guard, and signed-off-by footer before any HTTP call.
//! - The threat-network adapter rejects non-HTTPS endpoints at construction
//!   time (`ThreatNetworkClient::new`).

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use secrecy::SecretString;
use sx_api::port::{
    AutonomyEngineId, Phase3PortError, ProposePrInput, ProposePrOutcome, ProposePrPort,
    ScheduleValidationInput, ScheduleValidationPort, SubmitThreatInput, SubmitThreatObservation,
    SubmitThreatObservationPort, SubmitThreatOutcome,
};
use sx_autonomy::error::AutonomyError;
use sx_autonomy::prelude::{
    AutoRemediationPrGenerator, ContinuousValidationEngine, EngineHandle, FileChange, GithubClient,
    PrGeneratorConfig, PrProposal, RepoTarget, Schedule, SharingScope, SimulationPort,
    TenantConsent, ThreatNetworkClient, ThreatObservation, ValidationReport, ValidationReportSink,
};
use sx_bas::controller::run_simulation::RunSimulationUseCase;
use sx_config::GithubConfig;
use sx_core::value_object::ids::{CveId, EngagementId, TenantId};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{info, warn};
use url::Url;
use uuid::Uuid;

/// Placeholder threat-network endpoint used when the runtime configuration
/// does not carry an explicit override.
///
/// Documented constant so operators see exactly where the default points;
/// `.invalid` is reserved by IANA and never resolves, so a misconfigured
/// deployment surfaces as a clear DNS error instead of silently leaking
/// observations.
pub(crate) const DEFAULT_THREAT_NETWORK_ENDPOINT: &str =
    "https://threat-network.sentinelx.invalid/v1/observations";

/// Bundle of every autonomy port adapter.
///
/// The composition root pulls `propose_pr`, `submit_threat`, and
/// `schedule_validation` out of this struct and stores them in
/// `AppState`. `engine_techniques` is retained for diagnostics and reuse
/// by downstream agents wiring richer schedule defaults.
pub(crate) struct AutonomyBundle {
    /// Default technique ids the validation engine targets when the
    /// request omits an explicit override.
    #[allow(dead_code)] // retained for diagnostics + future scheduler defaults.
    pub engine_techniques: Vec<String>,
    /// Auto-remediation PR proposal port.
    pub propose_pr: Arc<dyn ProposePrPort>,
    /// Threat-network observation-submission port.
    pub submit_threat: Arc<dyn SubmitThreatObservationPort>,
    /// Continuous-validation engine scheduling port.
    pub schedule_validation: Arc<dyn ScheduleValidationPort>,
}

// ---------------------------------------------------------------------------
// Shared shims for the validation engine
// ---------------------------------------------------------------------------

/// In-memory report sink.
#[derive(Debug, Default)]
struct InMemoryValidationReportSink {
    reports: Mutex<Vec<ValidationReport>>,
}

#[async_trait]
impl ValidationReportSink for InMemoryValidationReportSink {
    async fn append(&self, report: ValidationReport) -> Result<(), AutonomyError> {
        let mut guard = self
            .reports
            .lock()
            .map_err(|e| AutonomyError::internal(format!("sink poisoned: {e}")))?;
        guard.push(report);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Propose-PR adapter
// ---------------------------------------------------------------------------

/// Adapter exposing [`AutoRemediationPrGenerator`] as a
/// [`ProposePrPort`].
///
/// Generic over [`GithubClient`] so tests can substitute a recording fake
/// for the real HTTP-backed client.
struct ProposePrAdapter<G: GithubClient + 'static> {
    generator: AutoRemediationPrGenerator<G>,
}

impl<G: GithubClient + 'static> ProposePrAdapter<G> {
    fn new(client: Arc<G>, cfg: PrGeneratorConfig) -> Result<Self, AutonomyError> {
        Ok(Self {
            generator: AutoRemediationPrGenerator::new(client, cfg)?,
        })
    }
}

#[async_trait]
impl<G: GithubClient + 'static> ProposePrPort for ProposePrAdapter<G> {
    async fn propose(&self, req: ProposePrInput) -> Result<ProposePrOutcome, Phase3PortError> {
        let repo = RepoTarget::new(req.repo_owner, req.repo_name).map_err(map_autonomy)?;
        let changes_result: Result<Vec<FileChange>, AutonomyError> = req
            .changes
            .into_iter()
            .map(|c| FileChange::new(c.path, c.new_content))
            .collect();
        let changes = changes_result.map_err(map_autonomy)?;
        let proposal = PrProposal::new(
            repo,
            req.target_branch,
            req.title,
            req.description,
            changes,
            req.finding_id,
            Vec::new(),
        )
        .map_err(map_autonomy)?;
        let outcome = self
            .generator
            .propose(proposal)
            .await
            .map_err(map_autonomy)?;
        Ok(ProposePrOutcome {
            pull_request_number: outcome.pull_request_number,
            url: outcome.url.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Submit-threat adapter
// ---------------------------------------------------------------------------

/// Adapter exposing [`ThreatNetworkClient`] as a
/// [`SubmitThreatObservationPort`].
#[derive(Debug)]
struct SubmitThreatAdapter {
    client: ThreatNetworkClient,
}

impl SubmitThreatAdapter {
    fn new(
        http: reqwest::Client,
        endpoint: Url,
        pepper: SecretString,
    ) -> Result<Self, AutonomyError> {
        let client = ThreatNetworkClient::new(http, endpoint, pepper)?;
        Ok(Self { client })
    }
}

#[async_trait]
impl SubmitThreatObservationPort for SubmitThreatAdapter {
    async fn submit(&self, req: SubmitThreatInput) -> Result<SubmitThreatOutcome, Phase3PortError> {
        let scope = parse_scope(&req.scope)?;
        let tenant_id = TenantId::from_str(&req.tenant_id)
            .map_err(|e| Phase3PortError::Invalid(format!("tenant_id: {e}")))?;
        let consented_at = OffsetDateTime::parse(&req.consented_at, &Rfc3339)
            .map_err(|e| Phase3PortError::Invalid(format!("consented_at: {e}")))?;
        let consent = TenantConsent::new(tenant_id, consented_at, scope);

        let observations = req
            .observations
            .into_iter()
            .map(parse_observation)
            .collect::<Result<Vec<_>, _>>()?;
        let count = u32::try_from(observations.len()).unwrap_or(u32::MAX);
        self.client
            .submit(consent, observations)
            .await
            .map_err(map_autonomy)?;
        Ok(SubmitThreatOutcome {
            accepted: true,
            submitted_count: count,
        })
    }
}

/// Parse the on-the-wire scope string into [`SharingScope`].
fn parse_scope(value: &str) -> Result<SharingScope, Phase3PortError> {
    match value {
        "vulnerability_frequency" => Ok(SharingScope::VulnerabilityFrequency),
        "ioc_match" => Ok(SharingScope::VulnerabilityAndTechniqueFrequency),
        other => Err(Phase3PortError::Invalid(format!("unknown scope: {other}"))),
    }
}

/// Translate a single wire observation into [`ThreatObservation`].
fn parse_observation(o: SubmitThreatObservation) -> Result<ThreatObservation, Phase3PortError> {
    let cve = CveId::new(o.cve_id).map_err(|e| Phase3PortError::Invalid(format!("cve_id: {e}")))?;
    Ok(ThreatObservation::new(cve, o.asset_kind, o.count))
}

// ---------------------------------------------------------------------------
// Schedule-validation adapter
// ---------------------------------------------------------------------------

/// Adapter exposing [`ContinuousValidationEngine`] as a
/// [`ScheduleValidationPort`].
///
/// Owns a map of `engine_id -> EngineHandle` behind a `tokio::Mutex` so
/// the schedule + cancel handlers can run concurrently without poisoning
/// a `std::sync::Mutex` across an `.await` point.
struct ScheduleValidationAdapter {
    simulator: Arc<dyn SimulationPort>,
    sink: Arc<dyn ValidationReportSink>,
    handles: Arc<AsyncMutex<HashMap<String, EngineHandle>>>,
}

impl ScheduleValidationAdapter {
    fn new(simulator: Arc<dyn SimulationPort>, sink: Arc<dyn ValidationReportSink>) -> Self {
        Self {
            simulator,
            sink,
            handles: Arc::new(AsyncMutex::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl ScheduleValidationPort for ScheduleValidationAdapter {
    async fn schedule(
        &self,
        req: ScheduleValidationInput,
    ) -> Result<AutonomyEngineId, Phase3PortError> {
        let tenant_id = TenantId::from_str(&req.tenant_id)
            .map_err(|e| Phase3PortError::Invalid(format!("tenant_id: {e}")))?;
        let engagement_id = EngagementId::from_str(&req.engagement_id)
            .map_err(|e| Phase3PortError::Invalid(format!("engagement_id: {e}")))?;
        let schedule = Schedule::from_interval(Duration::from_secs(req.interval_secs))
            .map_err(map_autonomy)?;
        let engine = ContinuousValidationEngine::new(
            schedule,
            req.technique_ids,
            Arc::clone(&self.simulator),
            Arc::clone(&self.sink),
        )
        .map_err(map_autonomy)?;
        let handle = engine
            .execute(tenant_id, engagement_id)
            .await
            .map_err(map_autonomy)?;

        let id = Uuid::now_v7().to_string();
        {
            let mut guard = self.handles.lock().await;
            guard.insert(id.clone(), handle);
        }
        info!(engine_id = %id, "continuous-validation engine scheduled");
        Ok(AutonomyEngineId(id))
    }

    async fn cancel(&self, id: &AutonomyEngineId) -> Result<(), Phase3PortError> {
        let removed = {
            let mut guard = self.handles.lock().await;
            guard.remove(&id.0)
        };
        #[allow(clippy::single_match_else)]
        match removed {
            Some(handle) => {
                handle.shutdown().await.map_err(map_autonomy)?;
                info!(engine_id = %id, "continuous-validation engine cancelled");
                Ok(())
            }
            None => {
                warn!(engine_id = %id, "cancel: unknown engine id");
                Err(Phase3PortError::NotFound)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Translate every [`AutonomyError`] into a [`Phase3PortError`].
///
/// `Invalid` / `Forbidden` are surfaced explicitly so the HTTP layer can
/// emit the correct 4xx; everything else collapses to `Internal` /
/// `Dependency`.
fn map_autonomy(err: AutonomyError) -> Phase3PortError {
    match err {
        AutonomyError::InvalidInput(m) => Phase3PortError::Invalid(m),
        AutonomyError::ProtectedBranch(b) => {
            Phase3PortError::Forbidden(format!("protected branch: {b}"))
        }
        AutonomyError::DiffTooLarge { actual, max } => {
            Phase3PortError::Invalid(format!("diff too large: {actual} > {max}"))
        }
        AutonomyError::EmptyChangeSet => Phase3PortError::Invalid("empty change set".to_owned()),
        AutonomyError::InsecureEndpoint => {
            Phase3PortError::Invalid("threat-network endpoint must be https".to_owned())
        }
        AutonomyError::MissingConsent(m) => Phase3PortError::Forbidden(format!("consent: {m}")),
        AutonomyError::KillSwitchTripped => {
            Phase3PortError::Forbidden("kill switch tripped".to_owned())
        }
        AutonomyError::Config(m) => Phase3PortError::Internal(format!("config: {m}")),
        AutonomyError::SimulatorError(m) => Phase3PortError::Dependency(format!("simulator: {m}")),
        AutonomyError::SinkError(m) => Phase3PortError::Dependency(format!("sink: {m}")),
        AutonomyError::GithubClient(m) => Phase3PortError::Dependency(format!("github: {m}")),
        AutonomyError::NetworkSubmissionFailed { status } => {
            Phase3PortError::Dependency(format!("threat network status {status}"))
        }
        AutonomyError::NetworkTransport(m) => {
            Phase3PortError::Dependency(format!("threat network transport: {m}"))
        }
        AutonomyError::Serialization(m) => Phase3PortError::Internal(format!("serialization: {m}")),
        AutonomyError::Internal(m) => Phase3PortError::Internal(m),
    }
}

// ---------------------------------------------------------------------------
// Composition root
// ---------------------------------------------------------------------------

/// Build the autonomy bundle.
///
/// `http` is shared by the PR-generator's GitHub client and the threat-
/// network client; `pepper` is forwarded to the threat-network client;
/// `bas_run_use_case` is the BAS entry point that the validation engine
/// invokes per technique via the [`super::bas_simulator::BasSimulationAdapter`].
///
/// If a future `cfg.autonomy.threat_network_endpoint` field lands, replace
/// the [`DEFAULT_THREAT_NETWORK_ENDPOINT`] constant call below with the
/// configured URL.
pub(crate) fn build(
    http: reqwest::Client,
    pepper: SecretString,
    bas_run_use_case: Arc<RunSimulationUseCase>,
    github_cfg: &GithubConfig,
) -> anyhow::Result<AutonomyBundle> {
    // --- PR generator ----------------------------------------------------
    // Honour `github.enabled`: when set, wire the real octocrab-backed
    // client; otherwise fall back to the deterministic stub so the
    // monolith boots cleanly without GitHub credentials.
    let propose_pr: Arc<dyn ProposePrPort> = if let Some(octocrab_client) =
        super::github::build(github_cfg).map_err(|e| anyhow::anyhow!("github client init: {e}"))?
    {
        info!(
            target = "adapters.autonomy.github",
            mode = "octocrab",
            "autonomy PR generator wired to octocrab",
        );
        Arc::new(
            ProposePrAdapter::new(octocrab_client, PrGeneratorConfig::default())
                .map_err(|e| anyhow::anyhow!("pr generator init (octocrab): {e}"))?,
        )
    } else {
        info!(
            target = "adapters.autonomy.github",
            mode = "stub",
            "autonomy PR generator wired to stub (github disabled)",
        );
        let disabled = Arc::new(DisabledGithubClient);
        Arc::new(
            ProposePrAdapter::new(disabled, PrGeneratorConfig::default())
                .map_err(|e| anyhow::anyhow!("pr generator init (github disabled): {e}"))?,
        )
    };

    // --- Threat network --------------------------------------------------
    let endpoint = Url::parse(DEFAULT_THREAT_NETWORK_ENDPOINT)
        .map_err(|e| anyhow::anyhow!("threat-network endpoint url: {e}"))?;
    let submit_threat: Arc<dyn SubmitThreatObservationPort> = Arc::new(
        SubmitThreatAdapter::new(http, endpoint, pepper)
            .map_err(|e| anyhow::anyhow!("threat-network init: {e}"))?,
    );

    // --- Validation engine scheduling -----------------------------------
    // The autonomy continuous-validation engine now delegates every
    // technique through the BAS four-gate safety pipeline. Cf.
    // [`super::bas_simulator`] for the mapping table.
    let simulator: Arc<dyn SimulationPort> = Arc::new(
        super::bas_simulator::BasSimulationAdapter::new(bas_run_use_case),
    );
    let sink: Arc<dyn ValidationReportSink> = Arc::new(InMemoryValidationReportSink::default());
    let schedule_validation: Arc<dyn ScheduleValidationPort> = Arc::new(
        ScheduleValidationAdapter::new(Arc::clone(&simulator), Arc::clone(&sink)),
    );

    let engine_techniques = vec![
        "theoretical_reachability_v1".to_owned(),
        "passive_cve_match_v1".to_owned(),
    ];

    info!(
        target = "adapters.autonomy.built",
        endpoint = DEFAULT_THREAT_NETWORK_ENDPOINT,
        simulator = "bas_run_simulation",
        sink = "in-memory",
        "autonomy bundle constructed",
    );

    Ok(AutonomyBundle {
        engine_techniques,
        propose_pr,
        submit_threat,
        schedule_validation,
    })
}

// ---------------------------------------------------------------------------
// Disabled-GitHub fallback client
// ---------------------------------------------------------------------------

/// [`GithubClient`] used only when GitHub integration is **not enabled**
/// (`github.enabled = false`, so no credentials are configured). The real
/// octocrab-backed [`super::github::OctocrabGithubClient`] is wired whenever
/// GitHub *is* configured — see [`build`].
///
/// Opening a PR without configured credentials is impossible, so this client
/// fails closed with a clear, actionable error rather than attempting an
/// unauthenticated call. It keeps the production path testable without
/// standing up a mock server.
#[derive(Debug, Default)]
struct DisabledGithubClient;

#[async_trait]
impl GithubClient for DisabledGithubClient {
    async fn open_pull_request(
        &self,
        prop: &PrProposal,
        _body: &str,
    ) -> Result<sx_autonomy::prelude::PrOutcome, AutonomyError> {
        Err(AutonomyError::github(format!(
            "cannot open a pull request for finding {}: GitHub integration is not enabled \
             (set github.enabled and app-installation or PAT credentials)",
            prop.finding_id
        )))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use sx_autonomy::prelude::{PrOutcome, SimulationOutcomeKind, SimulationPortOutcome};
    use uuid::Uuid;

    /// In-test stub simulator. The `schedule_validation_adapter_*` test
    /// schedules an engine with a 60-second tick then immediately cancels
    /// it — the simulator never actually runs. This stub stands in for
    /// the production BAS-backed adapter so the test stays focused on the
    /// schedule/cancel handle bookkeeping.
    #[derive(Debug, Default)]
    struct TestStubSimulator;

    #[async_trait]
    impl SimulationPort for TestStubSimulator {
        async fn execute(
            &self,
            _tenant_id: TenantId,
            _engagement_id: EngagementId,
            technique_id: String,
        ) -> Result<SimulationPortOutcome, AutonomyError> {
            Ok(SimulationPortOutcome::new(
                SimulationOutcomeKind::Pass,
                format!("test stub: {technique_id}"),
            ))
        }
    }

    /// Recording fake [`GithubClient`].
    #[derive(Debug, Default)]
    struct FakeGithubClient {
        captured: StdMutex<Vec<PrProposal>>,
    }

    impl FakeGithubClient {
        fn snapshot(&self) -> Vec<PrProposal> {
            self.captured.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl GithubClient for FakeGithubClient {
        async fn open_pull_request(
            &self,
            prop: &PrProposal,
            _body: &str,
        ) -> Result<PrOutcome, AutonomyError> {
            self.captured.lock().unwrap().push(prop.clone());
            Ok(PrOutcome {
                pull_request_number: 42,
                url: Url::parse("https://github.com/owner/repo/pull/42").unwrap(),
            })
        }
    }

    fn baseline_pr_input() -> ProposePrInput {
        ProposePrInput {
            tenant_id: Uuid::now_v7().to_string(),
            finding_id: "FIND-42".to_owned(),
            repo_owner: "owner".to_owned(),
            repo_name: "repo".to_owned(),
            target_branch: "develop".to_owned(),
            title: "fix: patch CVE".to_owned(),
            description: "Patch description.".to_owned(),
            changes: vec![sx_api::port::ProposePrChange {
                path: "src/lib.rs".to_owned(),
                new_content: "ok\n".to_owned(),
            }],
        }
    }

    #[tokio::test]
    async fn propose_pr_adapter_passes_through_to_generator() {
        let fake = Arc::new(FakeGithubClient::default());
        let adapter = ProposePrAdapter::new(Arc::clone(&fake), PrGeneratorConfig::default())
            .expect("adapter init");
        let outcome = adapter.propose(baseline_pr_input()).await.expect("propose");
        assert_eq!(outcome.pull_request_number, 42);
        assert_eq!(outcome.url, "https://github.com/owner/repo/pull/42");
        let captured = fake.snapshot();
        assert_eq!(captured.len(), 1);
        let prop = captured.into_iter().next().expect("one proposal");
        assert_eq!(prop.repo.owner, "owner");
        assert_eq!(prop.repo.name, "repo");
        assert_eq!(prop.finding_id, "FIND-42");
        assert_eq!(prop.target_branch, "develop");
        assert_eq!(prop.changes.len(), 1);
    }

    #[test]
    fn submit_threat_adapter_rejects_non_https_endpoint() {
        let endpoint = Url::parse("http://example.invalid/ingest").unwrap();
        let pepper = SecretString::new("pepper".to_owned().into_boxed_str());
        let err = SubmitThreatAdapter::new(reqwest::Client::new(), endpoint, pepper).unwrap_err();
        assert!(matches!(err, AutonomyError::InsecureEndpoint));
    }

    #[tokio::test]
    async fn schedule_validation_adapter_round_trip_schedule_then_cancel() {
        let simulator: Arc<dyn SimulationPort> = Arc::new(TestStubSimulator);
        let sink: Arc<dyn ValidationReportSink> = Arc::new(InMemoryValidationReportSink::default());
        let adapter = ScheduleValidationAdapter::new(simulator, sink);

        let req = ScheduleValidationInput {
            tenant_id: Uuid::now_v7().to_string(),
            engagement_id: Uuid::now_v7().to_string(),
            interval_secs: 60,
            technique_ids: vec!["t1".to_owned()],
        };
        let id = adapter.schedule(req).await.expect("schedule");

        // First cancel succeeds.
        adapter.cancel(&id).await.expect("first cancel");
        // Second cancel of the same id reports NotFound.
        let err = adapter.cancel(&id).await.unwrap_err();
        assert!(matches!(err, Phase3PortError::NotFound));
    }

    #[test]
    fn map_autonomy_translates_categories() {
        assert!(matches!(
            map_autonomy(AutonomyError::InsecureEndpoint),
            Phase3PortError::Invalid(_)
        ));
        assert!(matches!(
            map_autonomy(AutonomyError::ProtectedBranch("main".into())),
            Phase3PortError::Forbidden(_)
        ));
        assert!(matches!(
            map_autonomy(AutonomyError::DiffTooLarge {
                actual: 300,
                max: 200,
            }),
            Phase3PortError::Invalid(_)
        ));
        assert!(matches!(
            map_autonomy(AutonomyError::NetworkSubmissionFailed { status: 503 }),
            Phase3PortError::Dependency(_)
        ));
        assert!(matches!(
            map_autonomy(AutonomyError::Internal("boom".into())),
            Phase3PortError::Internal(_)
        ));
    }

    #[test]
    fn parse_scope_table() {
        assert!(matches!(
            parse_scope("vulnerability_frequency").unwrap(),
            SharingScope::VulnerabilityFrequency,
        ));
        assert!(matches!(
            parse_scope("ioc_match").unwrap(),
            SharingScope::VulnerabilityAndTechniqueFrequency,
        ));
        assert!(parse_scope("other").is_err());
    }
}
