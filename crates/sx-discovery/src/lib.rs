//! # `sx-discovery`
//!
//! Asset discovery layer for `SentinelX`.
//!
//! Defines a polymorphic [`service::scanner::Scanner`] abstraction and ships
//! three non-intrusive sample scanners suitable for Phase 1:
//!
//! 1. **`DnsResolver`** — resolves A/AAAA/CNAME/MX/TXT for a domain target.
//! 2. **`TcpPortProbe`** — banner-grab on a configurable port set, strict
//!    rate limit, no payloads.
//! 3. **`HttpFingerprint`** — single GET, captures status / headers /
//!    server-framework hints. No JS, no traversal, no auth bypass.
//!
//! Every scanner validates incoming `ScanRequest`s against the engagement
//! [`contracts::ScopeValidator`] before any packet leaves the process, honors
//! both a global concurrency limit and per-target token bucket, and aborts
//! within budget whenever the [`contracts::KillSwitch`] trips.
//!
//! ## Layout
//!
//! The crate follows the `SentinelX` MVC pattern:
//!
//! - [`model`] — value objects describing what a scan produced.
//! - [`view`] — DTOs exchanged with the API layer.
//! - [`controller`] — use-cases (orchestrators) consumed by the API crate.
//! - [`service`] — domain services: the scanner trait, registry, rate
//!   limiter, and the safety gate that fuses scope + kill switch.
//! - [`scanner`] — concrete, safe scanner implementations.
//! - [`contracts`] — minimal local trait definitions that mirror the
//!   contracts `SentinelX`'s `sx-core` / `sx-engagement` crates expose to
//!   the rest of the system. Kept here so this crate compiles and is
//!   testable in isolation; downstream consumers may bridge real
//!   implementations.
//! - [`prelude`] — re-exports for typical call sites.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod api_dast;
pub mod contracts;
pub mod controller;
pub mod error;
/// HIGH-009 — Kubernetes admission webhook (blocking mode).
pub mod k8s_admission;
pub mod model;
pub mod prelude;
pub mod prowler_import;
pub mod scanner;
pub mod service;
pub mod view;

pub use crate::error::DiscoveryError;
