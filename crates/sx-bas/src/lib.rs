//! `sx-bas` — Breach & Attack Simulation (BAS) for `SentinelX`.
//!
//! This crate is the **most safety-critical** subsystem in the platform
//! (TRD §3.3). It owns the operating-mode ladder, MITRE-tagged attack
//! techniques, and the four-stage safety pipeline that gates every step.
//!
//! # Operating modes
//!
//! Every BAS run executes in exactly one [`AttackMode`]:
//!
//! 1. [`AttackMode::Theoretical`] — graph traversal only, **no packets**.
//! 2. [`AttackMode::PassiveValidation`] — cached intel + signature match.
//! 3. [`AttackMode::SafeInteractive`] — non-destructive probes (OOB callbacks).
//! 4. [`AttackMode::ActiveExploit`] — exploit verification with limited PoC
//!    (dual-approval + RoE + change window required).
//! 5. [`AttackMode::RedTeam`] — full chain (signed RoE + change window + 3+ approvals).
//!
//! # Safety contract
//!
//! - The default mode for any new run is [`AttackMode::Theoretical`].
//!   Promotion to a higher mode requires an explicit operator action with an
//!   audit trail.
//! - Every technique declares a `max_mode`. The [`safety_pipeline::SafetyPipeline`]
//!   refuses to dispatch a technique whose `max_mode` exceeds the engagement's
//!   active mode ceiling.
//! - The kill switch SLA from trip to abort is **≤ 5 seconds**.
//!   See [`service::kill_switch_gate::KillSwitchGate`].
//! - **Exploit code is proposed, not executed.** The crate ships only
//!   safe-only sample techniques. Active and RedTeam paths return
//!   [`BasError::ExecutionBlocked`] unless a `dangerous_execution` feature
//!   flag is enabled — which is never on in this crate.
//!
//! # Layout
//!
//! ```text
//! src/
//! ├── error.rs                  BasError
//! ├── prelude.rs
//! ├── model/                    AttackMode, AttackTechnique, Approval, …
//! ├── service/                  ModeGate, ApprovalGate, WindowGate,
//! │                             KillSwitchGate, SafetyPipeline, registry
//! ├── technique/                safe-only sample techniques (MITRE-tagged)
//! └── controller/               RunSimulationUseCase
//! ```

#![forbid(unsafe_code)]
// Crate-level doc comments reference modes (Theoretical, PassiveValidation, etc.)
// and acronyms (RoE, PoC) as prose; backticking them in every reference is noisy
// without improving readability.
#![allow(clippy::doc_markdown)]

pub mod controller;
pub mod error;
pub mod model;
pub mod prelude;
pub mod service;
pub mod technique;

pub use error::BasError;
