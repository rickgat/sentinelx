//! Data types produced and consumed by the evidence-collector framework.
//!
//! The shapes here are deliberately framework-agnostic: a collector
//! returns an [`Evidence`] envelope tagged with the framework + control
//! it was gathered for, and downstream subsystems (storage, bundle
//! export, signed manifest) can treat all evidence uniformly.
//!
//! Per the TRD, the SHA-256 in [`Evidence::sha256`] is computed over
//! the `payload` bytes only — collector version metadata is recorded
//! alongside the envelope but never folded into the digest, so the
//! same observation hashes identically even as collector code evolves.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::model::framework::Framework;

/// Content-type discriminator for an [`Evidence`] payload.
///
/// The collector framework purposefully restricts itself to a small,
/// auditable set of media types. Anything richer (e.g. an HTML report,
/// a screencast) should be packaged into one of these wrappers (PDF,
/// PNG, or ZIP) before being handed to a sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceContentType {
    /// Structured JSON document (e.g. a query result, a config dump).
    Json,
    /// Free-form text (e.g. a CLI transcript).
    Text,
    /// PNG image (e.g. a dashboard screenshot).
    Png,
    /// PDF document (e.g. a generated control report).
    Pdf,
    /// CSV table (e.g. a findings export).
    Csv,
    /// ZIP archive (e.g. a bundle of related artifacts).
    Zip,
}

impl EvidenceContentType {
    /// Short machine-readable code matching the serde representation.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Text => "text",
            Self::Png => "png",
            Self::Pdf => "pdf",
            Self::Csv => "csv",
            Self::Zip => "zip",
        }
    }

    /// IANA media type string suitable for HTTP `Content-Type` headers.
    #[must_use]
    pub const fn media_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Text => "text/plain",
            Self::Png => "image/png",
            Self::Pdf => "application/pdf",
            Self::Csv => "text/csv",
            Self::Zip => "application/zip",
        }
    }
}

/// A single piece of collected evidence.
///
/// Records are immutable once produced — the canonical construction
/// path is [`Evidence::new`] which stamps the SHA-256 digest of the
/// payload at build time so downstream consumers never need to
/// recompute it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Framework-local control identifier (e.g. `"SX-KILL-SWITCH-TESTED"`).
    pub control_id: &'static str,
    /// Owning compliance framework.
    pub framework: Framework,
    /// UTC timestamp at which the evidence was collected.
    #[serde(with = "time::serde::rfc3339")]
    pub collected_at: OffsetDateTime,
    /// Media type of the [`Evidence::payload`] bytes.
    pub content_type: EvidenceContentType,
    /// Raw payload bytes — the body of the evidence artifact.
    pub payload: Vec<u8>,
    /// SHA-256 digest over [`Evidence::payload`] only.
    ///
    /// Per TRD §28: the collector version is metadata and is *not*
    /// folded into the digest, so identical observations produce
    /// identical hashes across collector upgrades.
    pub sha256: [u8; 32],
    /// Semver string identifying the collector implementation that
    /// produced this record (e.g. `"1.0.0"`).
    pub collector_version: &'static str,
}

impl Evidence {
    /// Construct a new [`Evidence`] record, stamping the SHA-256 digest
    /// of `payload` automatically.
    #[must_use]
    pub fn new(
        control_id: &'static str,
        framework: Framework,
        collected_at: OffsetDateTime,
        content_type: EvidenceContentType,
        payload: Vec<u8>,
        collector_version: &'static str,
    ) -> Self {
        let sha256 = sha256_of(&payload);
        Self {
            control_id,
            framework,
            collected_at,
            content_type,
            payload,
            sha256,
            collector_version,
        }
    }

    /// Lowercase hex rendering of [`Evidence::sha256`].
    ///
    /// Convenience helper for logs, CLI output, and manifest entries.
    #[must_use]
    pub fn sha256_hex(&self) -> String {
        hex::encode(self.sha256)
    }
}

/// Compute the SHA-256 digest of `bytes`.
///
/// Exposed at module scope so collectors and tests can verify a
/// payload's expected hash without rebuilding an [`Evidence`] record.
#[must_use]
pub fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}
