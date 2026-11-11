//! Convenience re-exports for downstream callers.
//!
//! ```rust,ignore
//! use sx_bas::prelude::*;
//! ```

pub use crate::controller::run_simulation::RunSimulationUseCase;
pub use crate::error::BasError;
pub use crate::model::approval::{Approval, ApprovalPolicy, RulesOfEngagement};
pub use crate::model::chain::{
    canonical_chains, ChainRun, ChainRunStatus, ChainStepRecord, ChainStepStatus, LateralChain,
    TechniqueRef,
};
pub use crate::model::mode::AttackMode;
pub use crate::model::simulation::{
    EvidenceRecord, EvidenceSink, InMemoryEvidenceSink, SimulationOutcome, SimulationRequest,
    SimulationStepContext, StepResult,
};
pub use crate::model::technique::{AttackTechnique, Capabilities, IntensityHint, MitreTag};
pub use crate::model::window::ChangeWindow;
pub use crate::service::approval_gate::DualApprovalGate;
pub use crate::service::chain_executor::{ChainExecutionContext, ChainExecutor};
pub use crate::service::kill_switch_gate::{KillSwitchGate, KillSwitchPort, NotifyKillSwitchPort};
pub use crate::service::mode_gate::ModeGate;
pub use crate::service::registry::TechniqueRegistry;
pub use crate::service::safety_pipeline::SafetyPipeline;
pub use crate::service::window_gate::WindowGate;
pub use crate::technique::passive_cve_match::{PassiveCveMatch, PoCAvailability};
pub use crate::technique::safe_cred_validator::SafeCredValidator;
pub use crate::technique::safe_ssrf_probe::SafeSsrfProbe;
pub use crate::technique::theoretical_reachability::TheoreticalReachability;

// P1-008 expansion: TA0001 Initial Access
pub use crate::technique::initial_access::t1078_valid_accounts::T1078ValidAccounts;
pub use crate::technique::initial_access::t1133_external_remote_services::T1133ExternalRemoteServices;
pub use crate::technique::initial_access::t1190_exploit_public_facing_app::T1190ExploitPublicFacingApp;
pub use crate::technique::initial_access::t1199_trusted_relationship::T1199TrustedRelationship;
pub use crate::technique::initial_access::t1566_phishing::T1566Phishing;

// P1-008 expansion: TA0003 Persistence
pub use crate::technique::persistence::t1098_account_manipulation::T1098AccountManipulation;
pub use crate::technique::persistence::t1136_create_account::T1136CreateAccount;
pub use crate::technique::persistence::t1505_server_software_component::T1505ServerSoftwareComponent;
pub use crate::technique::persistence::t1543_create_or_modify_system_process::T1543CreateOrModifySystemProcess;
pub use crate::technique::persistence::t1547_boot_logon_autostart::T1547BootLogonAutostart;

// P1-008 expansion: TA0004 Privilege Escalation
pub use crate::technique::privilege_escalation::t1068_exploit_for_privesc::T1068ExploitForPrivEsc;
pub use crate::technique::privilege_escalation::t1078_004_cloud_accounts::T1078004CloudAccounts;
pub use crate::technique::privilege_escalation::t1134_access_token_manipulation::T1134AccessTokenManipulation;
pub use crate::technique::privilege_escalation::t1548_abuse_elevation_control::T1548AbuseElevationControl;
pub use crate::technique::privilege_escalation::t1611_escape_to_host::T1611EscapeToHost;

// P1-008 expansion: TA0006 Credential Access
pub use crate::technique::credential_access::t1003_os_credential_dumping::T1003OsCredentialDumping;
pub use crate::technique::credential_access::t1056_input_capture::T1056InputCapture;
pub use crate::technique::credential_access::t1110_brute_force::T1110BruteForce;
pub use crate::technique::credential_access::t1212_exploit_for_cred_access::T1212ExploitForCredAccess;
pub use crate::technique::credential_access::t1552_unsecured_credentials::T1552UnsecuredCredentials;

// P1-008 expansion: TA0008 Lateral Movement
pub use crate::technique::lateral_movement::t1021_remote_services::T1021RemoteServices;
pub use crate::technique::lateral_movement::t1080_taint_shared_content::T1080TaintSharedContent;
pub use crate::technique::lateral_movement::t1210_exploit_remote_services::T1210ExploitRemoteServices;
pub use crate::technique::lateral_movement::t1534_internal_spearphishing::T1534InternalSpearphishing;
pub use crate::technique::lateral_movement::t1570_lateral_tool_transfer::T1570LateralToolTransfer;
