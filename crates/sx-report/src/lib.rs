//! # `sx-report`
//!
//! Multi-format reporting layer for `SentinelX`.
//!
//! Generates artefacts in five formats from a single [`model::ReportContext`]:
//!
//! 1. **Executive PDF** — 1-3 page posture summary plus the top-5 risks and a
//!    seven-day trend chart. No per-finding detail.
//! 2. **Technical PDF** — full per-finding listing with evidence references
//!    and external references.
//! 3. **SARIF 2.1.0** — JSON for ingestion into SIEM/SOAR/code scanning UIs.
//! 4. **STIX 2.1** — JSON bundle for threat-intel sharing.
//! 5. **CSV** — flat per-finding export with RFC-4180 quoting.
//!
//! Every renderer implements the [`port::Renderer`] trait. The
//! [`controller::RenderReportUseCase`] dispatches on a
//! [`port::ReportFormat`] selector.
//!
//! ## Hard constraints
//!
//! - **No unsafe code.** Workspace lints already forbid this.
//! - **Deterministic PDF output.** Given identical inputs (including
//!   [`model::ReportContext::generated_at`]) the byte output is identical.
//!   Random metadata IDs inside `printpdf` are normalised by a SHA-256
//!   derived value at save time.
//! - **No `unwrap` / `expect` / `panic!` in production paths.** Tests may
//!   relax this locally.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod controller;
pub mod diff;
pub mod error;
pub mod model;
pub mod port;
pub mod prelude;
pub mod renderer;
pub mod scheduler;

pub use crate::error::ReportError;
