//! Scanner-specific XML parsers.
//!
//! Each parser converts a single export body into a `Vec<NormalizedFinding>`,
//! delegating registry lookup and dedup to the [`crate::registry`] and
//! [`crate::dedup`] modules.

pub mod nessus;
pub mod openvas;
