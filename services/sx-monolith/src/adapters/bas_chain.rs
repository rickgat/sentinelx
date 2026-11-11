//! `BasChainPort` adapter — P2-015 lateral-movement chain replay.
//!
//! This adapter is the composition-root glue between the HTTP
//! [`sx_api::port::BasChainPort`] trait and the in-crate
//! [`sx_bas::service::chain_executor::ChainExecutor`].
//!
//! ## Responsibilities
//!
//! - **Catalogue.** [`InMemoryBasChainAdapter::list_catalogue`] returns the
//!   three pre-canned chains shipped by [`sx_bas::prelude::canonical_chains`]
//!   projected into the wire-shape [`LateralChainView`].
//! - **Run start.** [`InMemoryBasChainAdapter::start_run`] resolves the
//!   chain id against the catalogue, builds a
//!   [`ChainExecutionContext`] from the request, dispatches the
//!   chain through the shared `RunSimulationUseCase`, persists the
//!   resulting [`ChainRun`] into the per-tenant `bas_chain_runs`
//!   in-memory table, and returns the view projection.
//! - **Run lookup.** [`InMemoryBasChainAdapter::get_run`] looks up a
//!   recorded run by `(tenant_id, run_id)`. Cross-tenant reads surface
//!   as [`Phase3PortError::NotFound`] — the row simply does not exist
//!   from the calling tenant's perspective.
//!
//! ## Storage model
//!
//! Runs live in a `Mutex<Vec<(tenant_id, ChainRun)>>`. This mirrors the
//! pattern used by [`crate::adapters::bas::InMemoryBasRunHistory`] — a
//! Postgres-backed `bas_chain_runs` table will replace it in a follow-up
//! commit. The cap of [`InMemoryBasChainAdapter::CAP`] entries keeps
//! memory bounded for long-running processes; oldest entries are
//! evicted first.
//!
//! ## Audit
//!
//! The HTTP controller already emits `bas.chain.started` /
//! `bas.chain.completed` / `bas.chain.denied` audit events; the adapter
//! itself stays quiet on the tracing channel and lets the BAS crate's
//! `chain_executor` emit its per-step telemetry.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sx_api::port::{BasChainPort, Phase3PortError};
use sx_api::view::bas_view::{
    ChainRunView, ChainStepRecordView, ChainStepView, LateralChainView, StartChainRunRequest,
};
use sx_bas::controller::run_simulation::RunSimulationUseCase;
use sx_bas::prelude::{
    canonical_chains, ChainExecutionContext, ChainExecutor, ChainRun, ChainRunStatus,
    ChainStepStatus, LateralChain,
};
use sx_core::value_object::ids::{EngagementId, TenantId};
use time::{Duration, OffsetDateTime};

use sx_bas::model::mode::AttackMode;

/// In-memory `BasChainPort`. Bounded `Mutex<Vec<_>>` store with newest-first
/// insertion ordering.
pub(crate) struct InMemoryBasChainAdapter {
    executor: ChainExecutor,
    catalogue: Vec<LateralChain>,
    rows: Mutex<Vec<StoredRun>>,
}

#[derive(Debug, Clone)]
struct StoredRun {
    tenant_id: String,
    run: ChainRun,
    engagement_id: String,
}

impl InMemoryBasChainAdapter {
    /// Maximum number of recorded runs retained in memory.
    pub(crate) const CAP: usize = 1000;

    /// Default per-step execution budget. Each chain step inherits this
    /// window so the safety pipeline's window-gate has a non-trivial
    /// `now + budget` to evaluate against.
    const STEP_BUDGET_SECS: i64 = 30;

    /// Construct a new adapter over a shared [`RunSimulationUseCase`].
    pub(crate) fn new(use_case: Arc<RunSimulationUseCase>) -> Self {
        Self {
            executor: ChainExecutor::new(use_case),
            catalogue: canonical_chains(),
            rows: Mutex::new(Vec::new()),
        }
    }

    fn lookup(&self, chain_id: &str) -> Option<LateralChain> {
        self.catalogue.iter().find(|c| c.id == chain_id).cloned()
    }

    fn insert(&self, tenant_id: String, engagement_id: String, run: ChainRun) {
        if let Ok(mut guard) = self.rows.lock() {
            guard.insert(
                0,
                StoredRun {
                    tenant_id,
                    run,
                    engagement_id,
                },
            );
            if guard.len() > Self::CAP {
                guard.truncate(Self::CAP);
            }
        }
    }
}

#[async_trait]
impl BasChainPort for InMemoryBasChainAdapter {
    async fn list_catalogue(&self) -> Result<Vec<LateralChainView>, Phase3PortError> {
        Ok(self.catalogue.iter().map(chain_to_view).collect())
    }

    async fn start_run(
        &self,
        tenant_id: String,
        chain_id: String,
        req: StartChainRunRequest,
    ) -> Result<ChainRunView, Phase3PortError> {
        let Some(chain) = self.lookup(&chain_id) else {
            return Err(Phase3PortError::NotFound);
        };

        let tenant = tenant_id
            .parse::<TenantId>()
            .map_err(|e| Phase3PortError::Invalid(format!("tenant_id: {e}")))?;
        let engagement = req
            .engagement_id
            .parse::<EngagementId>()
            .map_err(|e| Phase3PortError::Invalid(format!("engagement_id: {e}")))?;
        let mode: AttackMode = req
            .mode
            .parse()
            .map_err(|e| Phase3PortError::Invalid(format!("mode: {e}")))?;

        let now = OffsetDateTime::now_utc();
        let ctx = ChainExecutionContext {
            tenant_id: tenant,
            engagement_id: engagement,
            mode,
            now,
            deadline: now + Duration::seconds(Self::STEP_BUDGET_SECS),
            approvals: Vec::new(),
        };

        let run = self
            .executor
            .run(&chain, &ctx)
            .await
            .map_err(|e| Phase3PortError::Internal(format!("chain executor: {e}")))?;

        // Project to the wire shape first because we hand ownership of the
        // run to the in-memory store below.
        let view = run_to_view(&run, &req.engagement_id);
        self.insert(tenant_id, req.engagement_id, run);
        Ok(view)
    }

    async fn get_run(
        &self,
        tenant_id: &str,
        run_id: &str,
    ) -> Result<ChainRunView, Phase3PortError> {
        let guard = self
            .rows
            .lock()
            .map_err(|_| Phase3PortError::Internal("bas_chain rows poisoned".into()))?;
        let stored = guard
            .iter()
            .find(|r| r.tenant_id == tenant_id && r.run.run_id == run_id)
            .ok_or(Phase3PortError::NotFound)?;
        Ok(run_to_view(&stored.run, &stored.engagement_id))
    }
}

fn chain_to_view(chain: &LateralChain) -> LateralChainView {
    LateralChainView {
        id: chain.id.clone(),
        name: chain.name.clone(),
        description: chain.description.clone(),
        steps: chain
            .steps
            .iter()
            .map(|s| ChainStepView {
                technique_id: s.technique_id.clone(),
                mitre_id: s.mitre_id.clone(),
                display_name: s.display_name.clone(),
                kill_on_failure: s.kill_on_failure,
            })
            .collect(),
    }
}

fn status_str(s: ChainRunStatus) -> &'static str {
    match s {
        ChainRunStatus::Running => "running",
        ChainRunStatus::Completed => "completed",
        ChainRunStatus::Failed => "failed",
        ChainRunStatus::Aborted => "aborted",
    }
}

fn step_status_str(s: &ChainStepStatus) -> &'static str {
    match s {
        ChainStepStatus::Success => "success",
        ChainStepStatus::Failure => "failure",
        ChainStepStatus::Skipped => "skipped",
    }
}

fn run_to_view(run: &ChainRun, engagement_id: &str) -> ChainRunView {
    ChainRunView {
        run_id: run.run_id.clone(),
        tenant_id: run.tenant_id.clone(),
        engagement_id: engagement_id.to_owned(),
        chain_id: run.chain_id.clone(),
        status: status_str(run.status).to_owned(),
        steps: run
            .steps
            .iter()
            .map(|s| ChainStepRecordView {
                step_index: s.step_index,
                technique_id: s.technique_id.clone(),
                mitre_id: s.mitre_id.clone(),
                status: step_status_str(&s.status).to_owned(),
                evidence: s.evidence.clone(),
            })
            .collect(),
        started_at: run.started_at.clone(),
        finished_at: run.finished_at.clone(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::{run_to_view, status_str, step_status_str, InMemoryBasChainAdapter};
    use async_trait::async_trait;
    use std::sync::Arc;
    use sx_api::port::BasChainPort;
    use sx_api::view::bas_view::StartChainRunRequest;
    use sx_bas::controller::run_simulation::RunSimulationUseCase;
    use sx_bas::model::chain::{ChainRunStatus, ChainStepStatus};
    use sx_bas::model::mode::AttackMode;
    use sx_bas::model::simulation::{SimulationStepContext, StepResult};
    use sx_bas::model::technique::{AttackTechnique, Capabilities, MitreTag};
    use sx_bas::service::kill_switch_gate::{KillSwitchGate, KillSwitchPort, NotifyKillSwitchPort};
    use sx_bas::service::registry::TechniqueRegistry;
    use sx_bas::service::safety_pipeline::SafetyPipeline;

    /// Mock technique used by the synthetic-chain test. Always returns
    /// `Simulated` with a deterministic summary so we can assert on
    /// evidence text.
    #[derive(Debug)]
    struct MockTech {
        id: &'static str,
        mitre: &'static str,
    }

    #[async_trait]
    impl AttackTechnique for MockTech {
        fn id(&self) -> &'static str {
            self.id
        }
        fn mitre(&self) -> MitreTag {
            MitreTag::new("TA0008", self.mitre, None)
        }
        fn max_mode(&self) -> AttackMode {
            AttackMode::Theoretical
        }
        fn capabilities(&self) -> Capabilities {
            Capabilities::ANALYTICAL
        }
        async fn step(
            &self,
            _ctx: SimulationStepContext,
        ) -> Result<StepResult, sx_bas::error::BasError> {
            Ok(StepResult::Simulated {
                summary: format!("mocked-{}", self.id),
                details: std::collections::HashMap::new(),
            })
        }
    }

    /// Build a `RunSimulationUseCase` whose registry contains every
    /// technique id referenced by the three canonical chains, mocked to
    /// always succeed. The adapter test then exercises the full
    /// list-catalogue / start-run / get-run sequence end-to-end.
    fn build_use_case_with_mocked_chain_techniques() -> Arc<RunSimulationUseCase> {
        let mut registry = TechniqueRegistry::new();
        // Match the registry ids used by `canonical_chains()`.
        let mocks: &[(&str, &str)] = &[
            ("t1078_valid_accounts_v1", "T1078"),
            ("t1021_remote_services_v1", "T1021"),
            ("t1570_lateral_tool_transfer_v1", "T1570"),
            ("t1199_trusted_relationship_v1", "T1199"),
            ("t1078_004_cloud_accounts_v1", "T1078"),
            ("t1611_escape_to_host_v1", "T1611"),
            ("t1566_phishing_v1", "T1566"),
            ("t1548_abuse_elevation_control_v1", "T1548"),
        ];
        for (id, mitre) in mocks {
            registry.register(Arc::new(MockTech { id, mitre })).unwrap();
        }
        let port = Arc::new(NotifyKillSwitchPort::new());
        let gate = KillSwitchGate::new(port as Arc<dyn KillSwitchPort>);
        let pipeline = Arc::new(SafetyPipeline::new(gate));
        Arc::new(RunSimulationUseCase::new(Arc::new(registry), pipeline))
    }

    fn tenant_uuid() -> String {
        "11111111-2222-3333-4444-555555555555".to_owned()
    }
    fn engagement_uuid() -> String {
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_owned()
    }

    #[tokio::test]
    async fn list_catalogue_returns_three_chains() {
        let adapter = InMemoryBasChainAdapter::new(build_use_case_with_mocked_chain_techniques());
        let items = adapter.list_catalogue().await.unwrap();
        assert_eq!(items.len(), 3);
        let ids: Vec<&str> = items.iter().map(|c| c.id.as_str()).collect();
        assert!(ids.contains(&"ransomware_style_v1"));
        assert!(ids.contains(&"supply_chain_compromise_v1"));
        assert!(ids.contains(&"phishing_privesc_lateral_v1"));
    }

    #[tokio::test]
    async fn start_run_records_per_step_evidence_and_round_trips_via_get_run() {
        let adapter = InMemoryBasChainAdapter::new(build_use_case_with_mocked_chain_techniques());
        let req = StartChainRunRequest {
            engagement_id: engagement_uuid(),
            mode: "theoretical".to_owned(),
            note: None,
        };
        let run = adapter
            .start_run(tenant_uuid(), "ransomware_style_v1".to_owned(), req)
            .await
            .unwrap();
        assert_eq!(run.tenant_id, tenant_uuid());
        assert_eq!(run.chain_id, "ransomware_style_v1");
        assert_eq!(run.engagement_id, engagement_uuid());
        assert_eq!(run.steps.len(), 3);
        for s in &run.steps {
            assert!(!s.evidence.is_empty(), "every step must carry evidence");
            assert_eq!(s.status, "success");
        }
        assert_eq!(run.status, "completed");

        // Round-trip via get_run.
        let again = adapter.get_run(&tenant_uuid(), &run.run_id).await.unwrap();
        assert_eq!(again, run);
    }

    #[tokio::test]
    async fn unknown_chain_id_returns_not_found() {
        let adapter = InMemoryBasChainAdapter::new(build_use_case_with_mocked_chain_techniques());
        let req = StartChainRunRequest {
            engagement_id: engagement_uuid(),
            mode: "theoretical".to_owned(),
            note: None,
        };
        let err = adapter
            .start_run(tenant_uuid(), "no_such_chain".to_owned(), req)
            .await
            .unwrap_err();
        assert!(matches!(err, sx_api::port::Phase3PortError::NotFound));
    }

    #[tokio::test]
    async fn cross_tenant_get_run_is_not_found() {
        let adapter = InMemoryBasChainAdapter::new(build_use_case_with_mocked_chain_techniques());
        let req = StartChainRunRequest {
            engagement_id: engagement_uuid(),
            mode: "theoretical".to_owned(),
            note: None,
        };
        let run = adapter
            .start_run(tenant_uuid(), "ransomware_style_v1".to_owned(), req)
            .await
            .unwrap();
        // A different tenant must see NotFound, never the row.
        let other_tenant = "99999999-9999-9999-9999-999999999999";
        let err = adapter
            .get_run(other_tenant, &run.run_id)
            .await
            .unwrap_err();
        assert!(matches!(err, sx_api::port::Phase3PortError::NotFound));
    }

    #[tokio::test]
    async fn bad_engagement_id_is_invalid() {
        let adapter = InMemoryBasChainAdapter::new(build_use_case_with_mocked_chain_techniques());
        let req = StartChainRunRequest {
            engagement_id: "not-a-uuid".to_owned(),
            mode: "theoretical".to_owned(),
            note: None,
        };
        let err = adapter
            .start_run(tenant_uuid(), "ransomware_style_v1".to_owned(), req)
            .await
            .unwrap_err();
        assert!(matches!(err, sx_api::port::Phase3PortError::Invalid(_)));
    }

    #[test]
    fn status_strings_match_wire_contract() {
        assert_eq!(status_str(ChainRunStatus::Running), "running");
        assert_eq!(status_str(ChainRunStatus::Completed), "completed");
        assert_eq!(status_str(ChainRunStatus::Failed), "failed");
        assert_eq!(status_str(ChainRunStatus::Aborted), "aborted");
        assert_eq!(step_status_str(&ChainStepStatus::Success), "success");
        assert_eq!(step_status_str(&ChainStepStatus::Failure), "failure");
        assert_eq!(step_status_str(&ChainStepStatus::Skipped), "skipped");
    }

    #[test]
    fn run_to_view_preserves_engagement_id() {
        let run = sx_bas::model::chain::ChainRun {
            run_id: "00000000-0000-0000-0000-000000000000".into(),
            tenant_id: tenant_uuid(),
            chain_id: "x".into(),
            status: ChainRunStatus::Completed,
            steps: vec![],
            started_at: "1970-01-01T00:00:00Z".into(),
            finished_at: Some("1970-01-01T00:00:00Z".into()),
        };
        let view = run_to_view(&run, "ENG");
        assert_eq!(view.engagement_id, "ENG");
        assert_eq!(view.status, "completed");
    }
}
