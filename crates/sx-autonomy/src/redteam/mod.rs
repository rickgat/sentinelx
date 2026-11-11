//! AI Red Team adversary composer.
//!
//! The composer turns a [`selector::TargetSpec`] into a plausible MITRE
//! ATT&CK kill chain — an ordered list of [`chain::ChainStep`]s whose
//! [`chain::KillChainPhase`] values are monotonically non-decreasing
//! through the 14 ATT&CK phases. Each step is drawn from a
//! [`selector::TechniqueCatalogue`] that exposes only **safe-mode**
//! techniques: any technique whose minimum required intensity is
//! [`sx_core::value_object::intensity::ScanIntensity::ActiveExploit`]
//! (or stronger) is rejected at compose time.
//!
//! # Capability surface
//!
//! - [`chain::AttackChain`] — the composed kill chain.
//! - [`chain::ChainStep`] — a single technique anchored to a phase, with
//!   a `[0.0, 1.0]` confidence.
//! - [`chain::KillChainPhase`] — the 14 ATT&CK phases, ordered.
//! - [`selector::TechniqueCatalogue`] — pluggable trait; the crate ships
//!   an [`selector::EmbeddedCatalogue`] with ~25 well-known safe-mode
//!   techniques tagged by phase.
//! - [`selector::compose`] — deterministic composition: at most one
//!   step per phase, in canonical phase order, capped by `max_steps`.
//! - [`scoring`] — heuristic per-step score and a chain-wide score that
//!   is the product of step confidences, floored at `1e-6`.
//!
//! # Safety contract
//!
//! - `#![forbid(unsafe_code)]` (workspace-wide).
//! - The composer **never** emits a step whose source technique requires
//!   active exploitation. If a [`selector::TechniqueCatalogue`]
//!   implementation lies about its tags, [`selector::compose`] still
//!   refuses to include the offending entry — the guard is enforced at
//!   the call site, not just the data source.
//! - This module is library-internal: no HTTP route, no I/O, no
//!   persistence.

pub mod chain;
pub mod scoring;
pub mod selector;
