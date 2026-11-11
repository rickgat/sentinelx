//! # `sx-compliance` — `SentinelX` Compliance Library
//!
//! Static, in-process catalog of compliance controls (ISO 27001, SOC 2,
//! PCI DSS, HIPAA, NIST 800-53, CIS AWS Foundations) and a mapper that
//! translates security findings into the controls they affect.
//!
//! This crate is intentionally **pure**: no I/O, no databases, no
//! networking. The catalog is constructed lazily and held behind an
//! [`std::sync::Arc`] so use-cases can share it cheaply.
//!
//! ## Layout
//!
//! ```text
//! model/        ── Framework, Control, Mapping, Evidence types.
//! service/      ── ControlCatalog (static library) + ControlMapper.
//! controller/   ── MapFindingToControlsUseCase + CollectEvidenceUseCase.
//! ```
//!
//! See [`prelude`] for a curated re-export glob.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// Pedantic / nursery lints we deliberately accept:
//   - `missing_const_for_fn`: methods may evolve to hold state.
//   - `needless_pass_by_value`: small DTOs communicate intent.
//   - `module_name_repetitions`: domain types repeat the module name on purpose.
//   - `option_if_let_else`: branchy match arms read better than `Option::map_or`.
//   - `must_use_candidate`: enforced selectively at item level.
//   - `multiple_crate_versions`: tolerated at the workspace edge.
//   - `indexing_slicing`: hand-rolled ZIP writer / collector aggregations index
//     into freshly-allocated buffers whose length is locally proven.
//   - `significant_drop_tightening`: short-lived mutex guards on in-memory
//     stores; tightening at every call site is busywork without functional win.
//   - `doc_markdown`: doc comments include acronyms (S3, IAM, MFA, LoC, OpenAPI)
//     that read naturally without backticks.
//   - `cast_possible_truncation`: ZIP central-directory offsets are bounded by
//     the assertion that the bundle fits in `u32` (32-bit ZIP).
//   - `struct_excessive_bools`: `IamPasswordPolicy` mirrors the AWS API shape.
//   - `too_long_first_doc_paragraph` / `items_after_statements`: stylistic.
#![allow(
    clippy::missing_const_for_fn,
    clippy::needless_pass_by_value,
    clippy::module_name_repetitions,
    clippy::option_if_let_else,
    clippy::missing_errors_doc,
    clippy::indexing_slicing,
    clippy::significant_drop_tightening,
    clippy::significant_drop_in_scrutinee,
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::struct_excessive_bools,
    clippy::too_long_first_doc_paragraph,
    clippy::items_after_statements
)]

pub mod collector;
pub mod controller;
pub mod error;
pub mod evidence;
pub mod model;
pub mod p1_004;
pub mod prelude;
pub mod report;
pub mod service;

pub use error::ComplianceError;
