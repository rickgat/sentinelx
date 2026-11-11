//! Service layer for BAS.
//!
//! - [`mode_gate`] — rejects techniques whose `max_mode` exceeds the
//!   engagement's ceiling.
//! - [`window_gate`] — enforces change windows for active modes.
//! - [`approval_gate`] — dual-approval gate (`ActiveExploit` ≥ 2,
//!   `RedTeam` ≥ 3).
//! - [`kill_switch_gate`] — sub-5s SLA kill switch enforcement.
//! - [`registry`] — central registry of techniques.
//! - [`safety_pipeline`] — composes the four gates in fixed order.

pub mod approval_gate;
pub mod chain_executor;
pub mod kill_switch_gate;
pub mod mode_gate;
pub mod registry;
pub mod safety_pipeline;
pub mod window_gate;
