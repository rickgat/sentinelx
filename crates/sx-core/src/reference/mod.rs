//! Curated reference data for finding enrichment (TOP5-#3 Phase 1).
//!
//! This module holds pure reference data — lookup tables that map a
//! `check_id` (or other emitter-side key) to a canonical enrichment
//! payload (CVSS v3.1 / CWE / MITRE ATT&CK / compliance controls).
//!
//! Reference data lives in `sx-core` rather than in any one emitter
//! crate so that:
//!
//! - The same payload is used by the high-level [`crate::sarif`]
//!   exporter, by every emitter (DAST, API DAST, etc.), and by the
//!   live `services/sx-monolith` HTTP-header probe — guaranteeing one
//!   source of truth and preventing the "DTO drift" defect logged as
//!   SX-REVIEW-002 C1.
//! - `sx-core` already declares the value-object types
//!   ([`crate::value_object::cvss_v31::CvssV31`],
//!   [`crate::value_object::cwe::CweId`], …); the constructors live
//!   one module away.
//!
//! Per the project rule "zero I/O in `sx-core`": every entry here is a
//! compile-time string table; no network calls, no file reads.

pub mod api_dast_enrichment;
pub mod audit_enrichment;
pub mod cspm_enrichment;
pub mod dlp_enrichment;
pub mod header_enrichment;
pub mod log_ingest_enrichment;
pub mod rba_block_enrichment;
pub mod saml_attack_enrichment;
pub mod url_guard;
pub mod webapp_enrichment;
