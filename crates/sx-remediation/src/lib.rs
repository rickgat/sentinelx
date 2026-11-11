//! # `sx-remediation`
//!
//! Remediation layer for `SentinelX`. Two responsibilities:
//!
//! 1. **Vendor advisory mirror** — pulls patch metadata from vendor security
//!    feeds (MSRC, Red Hat, Ubuntu, Cisco) behind a common
//!    [`service::source::VendorAdvisorySource`] abstraction, and fans queries
//!    out across sources via
//!    [`service::registry::MultiSourceAdvisoryRegistry`].
//! 2. **AI Remediation Copilot** — given a finding plus the advisories
//!    discovered above, produces an
//!    [`model::ai_remediation::AiRemediation`] using a tightly-guard-railed
//!    Claude LLM call.
//!
//! ## Guardrails
//!
//! The copilot is **propose-only**: it never executes code, never invokes
//! tools, and always defers to a human approver. Before any text reaches the
//! model the [`service::sanitiser::Sanitiser`] strips role markers, redacts
//! PII, and normalises whitespace. After the model responds, output is
//! schema-validated, citations are enforced against the advisory URL set, and
//! the configured token budget is clipped.
//!
//! ## Layout
//!
//! - [`model`] — value objects (advisories, copilot input/output).
//! - [`service`] — vendor sources, sanitiser, LLM client, registry.
//! - [`controller`] — use-cases consumed by the API layer.
//! - [`error`] — crate-level [`RemediationError`].
//! - [`prelude`] — re-exports for typical call sites.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod controller;
pub mod error;
pub mod model;
pub mod prelude;
pub mod service;

pub use crate::error::RemediationError;
