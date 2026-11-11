//! `sx-ai-audit` — comprehensive AI security check & audit for `SentinelX`.
//!
//! This crate is a **defensive / authorized-testing** subsystem. It audits
//! the AI assets a tenant operates (LLM endpoints, model registries, vector
//! stores, model files, agent frameworks, MCP servers) and produces a
//! structured report that downstream HTTP + dashboard layers render.
//!
//! Every capability that reaches out to a live target is gated behind the
//! engagement **scope** model: a probe run against an out-of-scope target
//! returns [`error::AiAuditError::OutOfScope`] rather than sending anything.
//!
//! # Modules
//!
//! * [`inventory`] — the [`inventory::AiAsset`] model, the
//!   [`inventory::AiAssetSource`] trait, and an in-memory source.
//! * [`aibom`] — a CycloneDX-ML-style AI-BOM document builder.
//! * [`probe`] — a static prompt-injection / jailbreak probe corpus, an
//!   [`probe::LlmTarget`] trait for the thing under test, and a passive
//!   [`probe::Evaluator`] that scores responses **without executing**
//!   anything.
//! * [`modelfile`] — a model-file supply-chain scanner: dangerous pickle
//!   opcode detection + safetensors header validation over a byte slice.
//! * [`mapping`] — OWASP LLM Top-10 + MITRE ATLAS mapping enums.
//! * [`governance`] — AI governance control definitions (NIST AI RMF,
//!   ISO/IEC 42001, EU AI Act) + an evidence record type.
//! * [`copilot_audit`] — an append-only copilot-decision audit record and
//!   sink trait (satisfying ADR-0004 §Decision item 7).
//! * [`service`] — the [`service::AiAuditService`] that composes the above.
//!
//! # Safety
//!
//! * `#![forbid(unsafe_code)]`.
//! * No panics, no `unwrap`/`expect`/`println` in non-test code.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Pedantic/nursery relaxations kept to the minimum this crate needs.
//
// * `doc_markdown` fires on `CycloneDX`, `OWASP`, `ATLAS`, `JSON`, `MCP`,
//   `LLM`, etc. which appear verbatim throughout the docs.
// * `module_name_repetitions` is already allowed workspace-wide; repeated
//   here for the few `AiAudit*` names that live inside the `service`
//   module.
// * `missing_const_for_fn` flags small accessors whose bodies could be
//   `const` in theory but are not worth the churn.
#![allow(
    clippy::doc_markdown,
    clippy::module_name_repetitions,
    clippy::missing_const_for_fn
)]
// Unit tests index into fixed-shape collections idiomatically.
#![cfg_attr(test, allow(clippy::indexing_slicing))]

pub mod aibom;
pub mod copilot_audit;
pub mod error;
pub mod governance;
pub mod inventory;
pub mod mapping;
pub mod modelfile;
pub mod prelude;
pub mod probe;
pub mod service;

pub use error::AiAuditError;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Render the current UTC instant as an RFC 3339 timestamp string.
///
/// Formatting a valid [`OffsetDateTime`] with the well-known RFC 3339
/// descriptor cannot fail in practice; on the unreachable error path we
/// fall back to an empty string rather than panic (the workspace denies
/// `unwrap`/`expect`).
#[must_use]
pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}
