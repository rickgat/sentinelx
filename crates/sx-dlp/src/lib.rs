//! # sx-dlp — DLP content-inspection adapter
//!
//! Lightweight Data-Loss-Prevention adapter that scans a payload for
//! well-known sensitive data patterns:
//!
//! - **PAN / credit card** (issuer-specific prefixes + Luhn check digit).
//! - **US SSN** (`AAA-GG-SSSS`, with non-zero areas/groups).
//! - **AWS access key id** (`AKIA…`, `ASIA…`).
//! - **AWS secret access key** (length + base64-alphabet heuristic).
//! - **GitHub personal access token** (`ghp_…`, `gho_…`, `ghu_…`,
//!   `ghs_…`, `ghr_…`).
//! - **JWT** (three base64url segments separated by `.`).
//! - **PEM private key block** (`-----BEGIN ... PRIVATE KEY-----`).
//!
//! ## Threat-model
//!
//! Implementation is **inline, deterministic, regex + Luhn + entropy +
//! NER-context** (HIGH-004). The crate's primary purpose is to power the
//! controller surface; richer ML passes can be layered behind the same
//! [`service::DlpService`] trait without changing callers.
//!
//! ## Multi-signal confidence fusion (HIGH-004)
//!
//! Every raw regex hit is scored by up to four independent signals
//! (regex match `0.40`, Luhn `0.30` PAN-only, entropy band `0.15`,
//! NER-context cue `0.15`). The signals are blended through a
//! calibrated logistic into a per-finding `confidence ∈ [0, 1]`. Tenants
//! configure a `min_confidence` threshold; findings below it are dropped
//! silently. A built-in [`suppression::SuppressionList`] additionally
//! drops well-known test PANs, RFC example SSNs, AWS docs sample keys
//! and the jwt.io demo token before fusion runs. See
//! [`detector::DlpDetector`] for the orchestrator.
//!
//! ## Privacy posture
//!
//! - The raw payload is **never persisted** by this crate. Callers may
//!   choose to forward a copy to disk, but the adapter and the
//!   `InMemoryDlpService` only retain *metadata* (kind, byte-count,
//!   match-count, redacted preview).
//! - Match previews follow a fixed redaction rule: first 4 characters
//!   of the literal match, then `*` padding, then the last 2 characters.
//!   For very short matches (< 6 chars) the entire match is replaced
//!   with `*`.
//! - The crate forbids `unsafe` and has no `unwrap()` / `expect()` in
//!   production code (enforced by workspace lints).
//!
//! ## Payload cap
//!
//! Every entry point enforces [`MAX_PAYLOAD_BYTES`] = 10 MB. Larger
//! payloads fast-fail with [`DlpError::PayloadTooLarge`]. The HTTP
//! controller layer enforces the same limit again so a hostile caller
//! cannot bypass it by going around the adapter.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod config;
pub mod detector;
pub mod patterns;
pub mod preview;
pub mod service;
pub mod signals;
pub mod suppression;

pub use crate::config::{TenantDetectorConfig, TenantDetectorConfigStore};
pub use crate::detector::{fuse, sigmoid, DetectionEvent, DlpDetector, Span, FUSION_SLOPE};
pub use crate::patterns::{DlpMatch, DlpMatchKind};
pub use crate::service::{
    ContentInspector, DlpError, DlpScanResult, DlpService, FnInspector, InMemoryDlpService,
    KindSummary, ScanHistoryEntry, ScanSource, ScoredDlpMatch,
};
pub use crate::signals::{DlpSignal, SignalContext, SignalEvidence, SignalKind};
pub use crate::suppression::{SuppressionEntry, SuppressionList};

/// Hard cap on payload size accepted by every entry point. 10 MB.
pub const MAX_PAYLOAD_BYTES: usize = 10 * 1024 * 1024;
