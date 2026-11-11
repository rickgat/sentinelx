//! Use-case (controller) layer.
//!
//! Each submodule exposes one `*UseCase` struct with a single `execute` method.
//! Use cases compose ports + services + view DTOs.

pub mod activate_engagement;
pub mod approve_engagement;
pub mod create_engagement;
pub mod terminate_engagement;
pub mod trigger_kill_switch;
pub mod validate_scan_request;

pub use activate_engagement::ActivateEngagementUseCase;
pub use approve_engagement::ApproveEngagementUseCase;
pub use create_engagement::CreateEngagementUseCase;
pub use terminate_engagement::{TerminateEngagementUseCase, TerminationOutcome};
pub use trigger_kill_switch::TriggerKillSwitchUseCase;
pub use validate_scan_request::ValidateScanRequestUseCase;
