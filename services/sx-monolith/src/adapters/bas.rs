#![allow(dead_code)] // Phase-3.5: many fields are reserved for the next-turn wire-up.
//! BAS (Breach & Attack Simulation) adapter.
//!
//! Builds the composition-root bundle for `sx-bas`:
//!
//! - A [`TechniqueRegistry`] populated with the four safe-only techniques
//!   that ship today.
//! - A [`SafetyPipeline`] fronting the four-gate sequence
//!   (mode → window → approval → kill_switch).
//! - An [`InMemoryKillSwitchPort`] used in dev mode. Production wires this
//!   to the shared `sx-engagement` kill switch via a Phase-3.5 adapter.
//!
//! The bundle exposes:
//!
//! - `run_use_case` — the public BAS entry point.
//! - `kill_switch`  — the `KillSwitchPort` trait object so the parent
//!   composition root can hand the same handle to other subsystems
//!   (autonomy, API admin routes, etc).
//!
//! The sibling gates ([`ModeGate`], [`WindowGate`], [`DualApprovalGate`])
//! are stateless and constructed in place by `SafetyPipeline::new`. The
//! spec's mode ceiling of `SafeInteractive` is enforced at request time by
//! the [`ModeGate`] (every technique declares its own `max_mode`); we do
//! not need to wire the ceiling into the registry itself — the registered
//! safe-only techniques all top out at `SafeInteractive` or below.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use sx_bas::controller::run_simulation::RunSimulationUseCase;
use sx_bas::error::BasError;
use sx_bas::service::kill_switch_gate::{KillSwitchGate, KillSwitchPort};
use sx_bas::service::registry::TechniqueRegistry;
use sx_bas::service::safety_pipeline::SafetyPipeline;
use sx_bas::technique::passive_cve_match::PassiveCveMatch;
use sx_bas::technique::safe_cred_validator::SafeCredValidator;
use sx_bas::technique::safe_ssrf_probe::SafeSsrfProbe;
use sx_bas::technique::theoretical_reachability::TheoreticalReachability;

// P1-008 expansion — 25 additional safe-mode techniques.
use sx_bas::technique::credential_access::t1003_os_credential_dumping::T1003OsCredentialDumping;
use sx_bas::technique::credential_access::t1056_input_capture::T1056InputCapture;
use sx_bas::technique::credential_access::t1110_brute_force::T1110BruteForce;
use sx_bas::technique::credential_access::t1212_exploit_for_cred_access::T1212ExploitForCredAccess;
use sx_bas::technique::credential_access::t1552_unsecured_credentials::T1552UnsecuredCredentials;
use sx_bas::technique::initial_access::t1078_valid_accounts::T1078ValidAccounts;
use sx_bas::technique::initial_access::t1133_external_remote_services::T1133ExternalRemoteServices;
use sx_bas::technique::initial_access::t1190_exploit_public_facing_app::T1190ExploitPublicFacingApp;
use sx_bas::technique::initial_access::t1199_trusted_relationship::T1199TrustedRelationship;
use sx_bas::technique::initial_access::t1566_phishing::T1566Phishing;
use sx_bas::technique::lateral_movement::t1021_remote_services::T1021RemoteServices;
use sx_bas::technique::lateral_movement::t1080_taint_shared_content::T1080TaintSharedContent;
use sx_bas::technique::lateral_movement::t1210_exploit_remote_services::T1210ExploitRemoteServices;
use sx_bas::technique::lateral_movement::t1534_internal_spearphishing::T1534InternalSpearphishing;
use sx_bas::technique::lateral_movement::t1570_lateral_tool_transfer::T1570LateralToolTransfer;
use sx_bas::technique::persistence::t1098_account_manipulation::T1098AccountManipulation;
use sx_bas::technique::persistence::t1136_create_account::T1136CreateAccount;
use sx_bas::technique::persistence::t1505_server_software_component::T1505ServerSoftwareComponent;
use sx_bas::technique::persistence::t1543_create_or_modify_system_process::T1543CreateOrModifySystemProcess;
use sx_bas::technique::persistence::t1547_boot_logon_autostart::T1547BootLogonAutostart;
use sx_bas::technique::privilege_escalation::t1068_exploit_for_privesc::T1068ExploitForPrivEsc;
use sx_bas::technique::privilege_escalation::t1078_004_cloud_accounts::T1078004CloudAccounts;
use sx_bas::technique::privilege_escalation::t1134_access_token_manipulation::T1134AccessTokenManipulation;
use sx_bas::technique::privilege_escalation::t1548_abuse_elevation_control::T1548AbuseElevationControl;
use sx_bas::technique::privilege_escalation::t1611_escape_to_host::T1611EscapeToHost;
use tokio::sync::Notify;
use tracing::info;

/// Bundle returned by [`build`].
pub(crate) struct BasBundle {
    /// Public BAS entry point — runs one technique through the full safety
    /// pipeline.
    pub run_use_case: Arc<RunSimulationUseCase>,
    /// The shared kill-switch handle. Production wires the same `Arc` to
    /// the engagement-side kill-switch adapter so a single trip aborts
    /// every in-flight simulation.
    pub kill_switch: Arc<dyn KillSwitchPort>,
}

/// In-process [`KillSwitchPort`] backed by a single [`Notify`] and an
/// atomic flag. Mirrors the shape of `sx_bas::service::kill_switch_gate::
/// NotifyKillSwitchPort` but lives inside the monolith so the wider
/// composition root can construct it directly without depending on
/// crate-internal helpers that may evolve.
#[derive(Debug)]
struct InMemoryKillSwitchPort {
    notify: Arc<Notify>,
    tripped: AtomicBool,
}

impl InMemoryKillSwitchPort {
    fn new() -> Self {
        Self {
            notify: Arc::new(Notify::new()),
            tripped: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl KillSwitchPort for InMemoryKillSwitchPort {
    async fn is_tripped(&self) -> Result<bool, BasError> {
        Ok(self.tripped.load(Ordering::SeqCst))
    }

    fn signal(&self) -> Arc<Notify> {
        Arc::clone(&self.notify)
    }
}

/// In-memory persistent BAS run history. Caps at 1000 entries — oldest
/// rows are evicted to keep memory bounded. Used until a Postgres-backed
/// adapter ships.
#[derive(Debug, Default)]
pub(crate) struct InMemoryBasRunHistory {
    rows: std::sync::Mutex<Vec<sx_api::view::bas_view::BasRunHistoryView>>,
}

impl InMemoryBasRunHistory {
    /// Maximum history depth retained in memory.
    pub(crate) const CAP: usize = 1000;
}

#[async_trait]
impl sx_api::port::BasRunHistoryPort for InMemoryBasRunHistory {
    async fn record(
        &self,
        entry: sx_api::view::bas_view::BasRunHistoryView,
    ) -> Result<(), sx_api::port::Phase3PortError> {
        let mut guard = self
            .rows
            .lock()
            .map_err(|_| sx_api::port::Phase3PortError::Internal("history poisoned".into()))?;
        // Idempotent on `simulation_id`.
        if guard.iter().any(|r| r.simulation_id == entry.simulation_id) {
            return Ok(());
        }
        guard.insert(0, entry);
        if guard.len() > Self::CAP {
            guard.truncate(Self::CAP);
        }
        Ok(())
    }

    async fn list(
        &self,
        engagement_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<sx_api::view::bas_view::BasRunHistoryView>, sx_api::port::Phase3PortError> {
        let guard = self
            .rows
            .lock()
            .map_err(|_| sx_api::port::Phase3PortError::Internal("history poisoned".into()))?;
        let it = guard.iter().filter(|r| match engagement_id {
            Some(want) => r.engagement_id.as_deref() == Some(want),
            None => true,
        });
        Ok(it.take(limit).cloned().collect())
    }
}

/// Build the BAS bundle with the production safe-only technique set.
///
/// # Errors
///
/// Returns an error if a technique fails to register (would indicate a
/// duplicate `id` — a logic bug in this composition root).
#[allow(dead_code)] // parent composition root wires this in
pub(crate) fn build() -> anyhow::Result<BasBundle> {
    // 1. Registry: register every safe-only technique that ships today.
    let mut registry = TechniqueRegistry::new();
    registry
        .register(Arc::new(TheoreticalReachability::new(
            Vec::new(),
            "entry".to_owned(),
            None,
        )))
        .map_err(|e| anyhow::anyhow!("register theoretical_reachability_v1: {e}"))?;
    registry
        .register(Arc::new(PassiveCveMatch::new(
            std::collections::HashMap::new(),
        )))
        .map_err(|e| anyhow::anyhow!("register passive_cve_match_v1: {e}"))?;
    registry
        .register(Arc::new(SafeSsrfProbe::new(
            "https://target.sentinelx.invalid".to_owned(),
            "https://oob.sentinelx.invalid".to_owned(),
        )))
        .map_err(|e| anyhow::anyhow!("register safe_ssrf_probe_v1: {e}"))?;
    registry
        .register(Arc::new(SafeCredValidator::new(
            "sentinelx-canary".to_owned(),
            // Hash placeholder — the technique never executes a real
            // credential validation; this slot is consumed only by tests
            // and the safety-pipeline preflight.
            "0".repeat(64),
            "https://idp.invalid".to_owned(),
        )))
        .map_err(|e| anyhow::anyhow!("register safe_cred_validator_v1: {e}"))?;

    // P1-008 expansion: 25 additional safe-only technique stubs.
    // All declare PassiveValidation or Theoretical as `max_mode`; the
    // SafetyPipeline still re-checks each one's ceiling at request time.
    register_p1_008_techniques(&mut registry)?;

    // 2. Kill switch: in-memory port, exposed to the wider composition
    //    root so a single trip aborts every running technique.
    let kill_switch: Arc<dyn KillSwitchPort> = Arc::new(InMemoryKillSwitchPort::new());
    let kill_switch_gate = KillSwitchGate::new(Arc::clone(&kill_switch));

    // 3. Safety pipeline: composes ModeGate (default ceiling enforced by
    //    each technique's max_mode), WindowGate, DualApprovalGate
    //    (thresholds applied by gate internals: 1/2/3 by mode), and the
    //    kill-switch gate above.
    let pipeline = Arc::new(SafetyPipeline::new(kill_switch_gate));

    // 4. Use case.
    let run_use_case = Arc::new(RunSimulationUseCase::new(Arc::new(registry), pipeline));

    info!(
        target = "adapters.bas.built",
        techniques = 4 + 25,
        "bas bundle constructed"
    );

    Ok(BasBundle {
        run_use_case,
        kill_switch,
    })
}

/// Register the 25 safe-only technique stubs added in P1-008.
///
/// Each stub is constructed with an empty inventory; production code is
/// expected to swap in tenant-scoped inventories at request time via the
/// `derived-technique` pattern used elsewhere in this adapter.
fn register_p1_008_techniques(registry: &mut TechniqueRegistry) -> anyhow::Result<()> {
    // Macro-free: each `register` call returns BasError on duplicate id,
    // surfaced as anyhow context for clear failure messages at startup.
    macro_rules! reg {
        ($name:expr, $instance:expr) => {
            registry
                .register(Arc::new($instance))
                .map_err(|e| anyhow::anyhow!(concat!("register ", $name, ": {}"), e))?;
        };
    }

    // TA0001 Initial Access
    reg!(
        "t1190_exploit_public_facing_app_v1",
        T1190ExploitPublicFacingApp::new(Vec::new())
    );
    reg!(
        "t1133_external_remote_services_v1",
        T1133ExternalRemoteServices::new(Vec::new())
    );
    reg!(
        "t1078_valid_accounts_v1",
        T1078ValidAccounts::new(Vec::new())
    );
    reg!("t1566_phishing_v1", T1566Phishing::new(Vec::new()));
    reg!(
        "t1199_trusted_relationship_v1",
        T1199TrustedRelationship::new(Vec::new())
    );

    // TA0003 Persistence
    reg!(
        "t1098_account_manipulation_v1",
        T1098AccountManipulation::new(Vec::new())
    );
    reg!(
        "t1136_create_account_v1",
        T1136CreateAccount::new(Vec::new())
    );
    reg!(
        "t1505_server_software_component_v1",
        T1505ServerSoftwareComponent::new(Vec::new())
    );
    reg!(
        "t1547_boot_logon_autostart_v1",
        T1547BootLogonAutostart::new(Vec::new())
    );
    reg!(
        "t1543_create_or_modify_system_process_v1",
        T1543CreateOrModifySystemProcess::new(Vec::new())
    );

    // TA0004 Privilege Escalation
    reg!(
        "t1068_exploit_for_privesc_v1",
        T1068ExploitForPrivEsc::new(Vec::new())
    );
    reg!(
        "t1078_004_cloud_accounts_v1",
        T1078004CloudAccounts::new(Vec::new())
    );
    reg!(
        "t1611_escape_to_host_v1",
        T1611EscapeToHost::new(Vec::new())
    );
    reg!(
        "t1134_access_token_manipulation_v1",
        T1134AccessTokenManipulation::new(Vec::new())
    );
    reg!(
        "t1548_abuse_elevation_control_v1",
        T1548AbuseElevationControl::new(Vec::new())
    );

    // TA0006 Credential Access
    reg!(
        "t1003_os_credential_dumping_v1",
        T1003OsCredentialDumping::new(Vec::new())
    );
    reg!("t1110_brute_force_v1", T1110BruteForce::new(Vec::new()));
    reg!("t1056_input_capture_v1", T1056InputCapture::new(Vec::new()));
    reg!(
        "t1212_exploit_for_cred_access_v1",
        T1212ExploitForCredAccess::new(Vec::new())
    );
    reg!(
        "t1552_unsecured_credentials_v1",
        T1552UnsecuredCredentials::new(Vec::new())
    );

    // TA0008 Lateral Movement
    reg!(
        "t1021_remote_services_v1",
        T1021RemoteServices::new(Vec::new())
    );
    reg!(
        "t1210_exploit_remote_services_v1",
        T1210ExploitRemoteServices::new(Vec::new())
    );
    reg!(
        "t1534_internal_spearphishing_v1",
        T1534InternalSpearphishing::new(Vec::new())
    );
    reg!(
        "t1570_lateral_tool_transfer_v1",
        T1570LateralToolTransfer::new(Vec::new())
    );
    reg!(
        "t1080_taint_shared_content_v1",
        T1080TaintSharedContent::new(Vec::new())
    );

    Ok(())
}
