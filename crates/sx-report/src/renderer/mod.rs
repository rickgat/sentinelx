//! Concrete renderer implementations.
//!
//! Each module ships a struct implementing [`crate::port::Renderer`].

pub mod csv;
pub mod diff_pdf;
pub mod executive_pdf;
pub mod sarif;
pub mod stix;
pub mod technical_pdf;

mod pdf_common;
