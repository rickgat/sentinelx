//! Convenience re-exports for downstream callers.
//!
//! Importing `use sx_autonomy::prelude::*;` gives a caller every public
//! type they need to wire up the autonomy capabilities — the use cases,
//! the domain models, the service traits, and the error type.

pub use crate::controller::propose_pr::ProposePrUseCase;
pub use crate::controller::share_with_network::ShareWithNetworkUseCase;
pub use crate::controller::start_validation::StartContinuousValidationUseCase;
pub use crate::error::AutonomyError;
pub use crate::model::consent::{SharingScope, TenantConsent};
pub use crate::model::pr_proposal::{FileChange, PrProposal, RepoTarget};
pub use crate::model::schedule::Schedule;
pub use crate::model::threat_share::{ThreatObservation, ThreatShareBundle};
pub use crate::model::validation_report::{TechniqueOutcome, ValidationOutcome, ValidationReport};
pub use crate::service::pr_generator::{
    AutoRemediationPrGenerator, GithubClient, PrGeneratorConfig, PrOutcome,
};
pub use crate::service::pr_safety::{BranchProtectionGuard, DiffSizeGuard};
pub use crate::service::threat_network::ThreatNetworkClient;
pub use crate::service::validation_engine::{
    ContinuousValidationEngine, EngineHandle, SimulationOutcomeKind, SimulationPort,
    SimulationPortOutcome, ValidationReportSink,
};
