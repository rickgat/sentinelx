//! `sx-engagement` — engagement lifecycle and **scanning safety controls**.
//!
//! This is `SentinelX`'s "permission to scan" service. It owns:
//!
//! * Engagement state transitions (`Draft → Active → Paused → Completed | Aborted`).
//! * [`ScopeValidator`] — the canonical "may this scan proceed?" decision
//!   function. The same validator runs at the **API boundary**, at the
//!   **worker boundary**, and once more at the **probe boundary** — three
//!   call sites of the same `evaluate` function, so a missed guard at any
//!   one site does not translate into an unauthorized probe.
//! * [`DenylistChecker`] — global, pre-compiled deny list (e.g. `*.gov`,
//!   `*.mil`). Checked **first**; a denylist hit blocks the request
//!   regardless of the engagement's scope. There is no override.
//! * [`KillSwitch`] — the trait + an in-memory implementation. The Redis
//!   adapter lives downstream (not in this crate) and plugs in via the trait.
//! * [`ApprovalPolicy`] — N-of-M human-approval gate. Threshold counts come
//!   from configuration, never from compiled-in defaults.
//!
//! # Safety-first principles
//!
//! 1. The denylist is checked **before** scope evaluation. A denylist match
//!    always wins.
//! 2. Engagements may only authorize scans when they are `Active`, inside
//!    their time window, and have the required number of approvals.
//! 3. Every denial emits a structured `tracing::warn!` carrying tenant /
//!    engagement IDs and the cause — never any request bodies, secrets, or
//!    PII.
//! 4. No `unsafe_code`. No `.unwrap()` / `.expect()` / `panic!()` in
//!    production paths.
//!
//! # Layout
//!
//! ```text
//! src/
//! ├── error.rs                              EngagementError
//! ├── model/                                domain types
//! ├── view/                                 request/response DTOs
//! ├── service/                              ScopeValidator, DenylistChecker,
//! │                                         KillSwitch, ApprovalPolicy, Clock
//! ├── controller/                           use cases
//! ├── port.rs                               EngagementRepository
//! └── prelude.rs
//! ```
//!
//! # Future re-exports from `sx-core`
//!
//! The aggregate root (`Engagement`), value object (`ScopeTarget`) and port
//! (`EngagementRepository`) currently live here. Once the `sx-core`
//! engagement entity module lands, this crate will re-export those types
//! from `sx_core` so the contract is shared with downstream adapter crates.

#![forbid(unsafe_code)]

pub mod controller;
pub mod error;
pub mod model;
pub mod port;
pub mod prelude;
pub mod service;
pub mod view;

pub use error::EngagementError;
