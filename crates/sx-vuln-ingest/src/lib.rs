//! # `sx-vuln-ingest`
//!
//! Credentialed vulnerability scanner ingest (P0-002).
//!
//! Parses scanner exports (Nessus `.nessus` and OpenVAS XML), deduplicates
//! findings by `(asset_id, check_id)`, and maps external plugin ids onto an
//! internal `check_id` registry. The crate is deliberately decoupled from
//! storage and I/O: the public surface accepts an in-memory payload and
//! returns a structured [`ImportReport`] that an adapter can persist.
//!
//! ## Modules
//!
//! - [`parser::nessus`] — Nessus `.nessus` XML parser.
//! - [`parser::openvas`] — OpenVAS XML report parser.
//! - [`registry`] — external plugin id → internal `check_id` mapping.
//! - [`dedup`] — `(asset_id, check_id)` deduplication.
//!
//! ## Safety
//!
//! `#![forbid(unsafe_code)]` — no unsafe blocks anywhere in this crate.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_const_for_fn,
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    clippy::needless_pass_by_value,
    clippy::doc_markdown
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::missing_panics_doc,
        clippy::missing_errors_doc
    )
)]

pub mod dedup;
pub mod model;
pub mod parser;
pub mod registry;
pub mod service;

pub use crate::model::{ImportReport, NormalizedFinding, Severity, SourceFormat, VulnIngestError};
pub use crate::service::{InMemoryVulnIngestService, VulnIngestService};
