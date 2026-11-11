//! Domain services — pure logic and ports.
//!
//! Submodules:
//! * [`clock`] — `Clock` trait + `SystemClock` / `FakeClock`.
//! * [`denylist`] — pre-compiled denylist checker.
//! * [`dual_approval`] — N-of-M approval policy.
//! * [`kill_switch`] — kill-switch trait + in-memory impl.
//! * [`scope_validator`] — the canonical scope-allow decision function.

pub mod clock;
pub mod denylist;
pub mod dual_approval;
pub mod kill_switch;
pub mod scope_validator;

pub use clock::{Clock, FakeClock, SystemClock};
pub use denylist::{DenylistChecker, DenylistHit};
pub use dual_approval::{ApprovalPolicy, ApprovalThresholds};
pub use kill_switch::{
    InMemoryKillSwitch, KillReason, KillSwitch, KillSwitchEvent, KillSwitchScope,
};
pub use scope_validator::ScopeValidator;
