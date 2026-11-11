//! PDF report rendering for compliance framework documents.
//!
//! This module is the entry point for turning a maintained Markdown
//! compliance mapping (e.g. `docs/compliance/pci-dss-v4-mapping.md`)
//! into a deliverable PDF artifact for auditors and CISO stakeholders.
//!
//! Layout:
//! ```text
//! pdf.rs   ── pulldown-cmark walker + printpdf renderer.
//! ```
//!
//! The module is intentionally pure (no async, no I/O beyond filesystem
//! reads of the input markdown). PDF bytes are written via
//! [`std::fs::write`] inside [`pdf::render_pci_dss`].

pub mod pdf;

pub use pdf::{render_pci_dss, ReportError};
