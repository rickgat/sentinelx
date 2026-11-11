//! `sx-audit` — tamper-evident, append-only audit log.
//!
//! Every security-relevant action across `SentinelX` is recorded as an
//! [`AuditEntry`](crate::model::entry::AuditEntry). Entries form a
//! per-tenant SHA-256 hash chain: each entry stores the hash of its
//! predecessor, so any historical tampering can be detected by replaying
//! the chain through [`VerifyChainUseCase`](crate::controller::verify_chain::VerifyChainUseCase).
//!
//! This crate is storage-agnostic: it defines the [`AuditSink`](crate::service::sink::AuditSink)
//! port and lets implementations live elsewhere (typically `sx-storage`).
//!
//! ## Crate layout
//!
//! - [`model`] — domain types: [`model::entry::AuditEntry`], [`model::actor::Actor`], [`model::action::AuditAction`].
//! - [`service`] — stateless services: hashing, chain construction, persistence port.
//! - [`controller`] — application use-cases: `record_event`, `verify_chain`.
//! - [`prelude`] — curated re-exports for downstream callers.

#![forbid(unsafe_code)]

pub mod anchor;
pub mod anchor_external;
pub mod anchor_run;
pub mod chain;
pub mod chain_verifier;
pub mod controller;
pub mod error;
pub mod model;
pub mod prelude;
pub mod service;
pub mod time_travel;
pub mod tsa_fallback;

pub use chain::{ChainError, HashChain, CHAIN_HASH_HEX_LEN};
pub use chain_verifier::{
    broken_payload, AuditChainBrokenPayload, BreakObserver, BrokenChainSubscriber, ChainBreakEvent,
    ChainVerifier, Clock as ChainVerifierClock, RecordingSubscriber,
    SystemClock as ChainVerifierSystemClock, VerifyTickResult, DEFAULT_INTERVAL,
};
