//! Data model shared by parser, dedup, registry, and service layers.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Supported scanner export formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceFormat {
    /// Tenable Nessus `.nessus` (NessusClientData_v2 XML).
    Nessus,
    /// Greenbone / OpenVAS GMP XML report.
    Openvas,
}

impl SourceFormat {
    /// Display string used in storage / wire formats.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nessus => "nessus",
            Self::Openvas => "openvas",
        }
    }

    /// Parse a wire-format string. Case-insensitive.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "nessus" | "nessus_v2" | "nessus-v2" => Some(Self::Nessus),
            "openvas" | "gmp" | "greenbone" => Some(Self::Openvas),
            _ => None,
        }
    }
}

/// Canonical severity rank — mirrors the SentinelX domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational — no impact, advisory only.
    Info,
    /// Low — defence-in-depth class.
    Low,
    /// Medium — exploitable under non-default conditions.
    Medium,
    /// High — exploitable with material impact.
    High,
    /// Critical — remote unauthenticated exploit, or RCE.
    Critical,
}

impl Severity {
    /// Display string used in storage / wire formats.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    /// Map a Nessus / OpenVAS numeric severity (0..=4) onto the enum.
    #[must_use]
    pub const fn from_nessus_rank(rank: u8) -> Self {
        match rank {
            0 => Self::Info,
            1 => Self::Low,
            2 => Self::Medium,
            3 => Self::High,
            _ => Self::Critical,
        }
    }

    /// Map an OpenVAS CVSS-style score (0.0..=10.0) onto the enum.
    /// Uses the FIRST.org severity bands (`<4`, `<7`, `<9`, otherwise critical).
    #[must_use]
    pub fn from_cvss(score: f64) -> Self {
        if score < 0.1 {
            Self::Info
        } else if score < 4.0 {
            Self::Low
        } else if score < 7.0 {
            Self::Medium
        } else if score < 9.0 {
            Self::High
        } else {
            Self::Critical
        }
    }

    /// Map an OpenVAS `threat` token (`Log` / `Low` / `Medium` / `High` /
    /// `Critical`) onto the enum.
    #[must_use]
    pub fn from_openvas_threat(threat: &str) -> Self {
        match threat.trim().to_ascii_lowercase().as_str() {
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            "critical" => Self::Critical,
            _ => Self::Info,
        }
    }
}

/// One normalized finding produced by the parser layer.
///
/// `asset_id` is the unique target identifier the scanner emitted (IP,
/// hostname, FQDN, etc.). `check_id` is the SentinelX-internal stable
/// identifier the registry mapped the scanner's plugin id to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NormalizedFinding {
    /// Internal stable check identifier (e.g. `NESSUS.11936`).
    pub check_id: String,
    /// External plugin id as emitted by the scanner.
    pub external_id: String,
    /// Asset / target identifier (IP / FQDN / hostname).
    pub asset_id: String,
    /// Canonical severity.
    pub severity: Severity,
    /// Short human title.
    pub title: String,
    /// Long-form description.
    pub description: String,
    /// First CVE reference (when present).
    pub cve: Option<String>,
    /// CVSS v3 base score (0.0..=10.0) when present.
    pub cvss_v3: Option<f64>,
    /// Optional remediation hint.
    pub remediation: Option<String>,
    /// Originating scanner family.
    pub source: SourceFormat,
}

/// Per-import summary returned by [`crate::service::VulnIngestService::import`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImportReport {
    /// Owning tenant UUID.
    pub tenant_id: String,
    /// Originating scanner family.
    pub source: SourceFormat,
    /// Distinct asset count.
    pub asset_count: usize,
    /// Distinct `(asset_id, check_id)` count.
    pub finding_count: usize,
    /// Findings dropped by the dedup pass.
    pub duplicates_dropped: usize,
    /// Lines that failed to parse and were skipped.
    pub parse_errors: usize,
    /// Normalized findings produced by the import (post-dedup).
    pub findings: Vec<NormalizedFinding>,
}

/// Errors produced anywhere in the parser / service pipeline.
#[derive(Debug, Error)]
pub enum VulnIngestError {
    /// The XML body could not be read.
    #[error("xml read error: {0}")]
    Xml(String),
    /// The XML parsed but the document shape was not recognised.
    #[error("unrecognised document shape: {0}")]
    UnrecognisedShape(String),
    /// The caller supplied an unsupported source format.
    #[error("unsupported source format: {0}")]
    UnsupportedFormat(String),
    /// The payload exceeded the configured size limit.
    #[error("payload too large: {actual} bytes (max {max})")]
    PayloadTooLarge {
        /// Payload size received.
        actual: usize,
        /// Configured maximum.
        max: usize,
    },
    /// A required field was missing from the document.
    #[error("missing field: {0}")]
    MissingField(String),
    /// Internal failure.
    #[error("internal: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_format_round_trips() {
        assert_eq!(SourceFormat::parse("nessus"), Some(SourceFormat::Nessus));
        assert_eq!(SourceFormat::parse("NESSUS_V2"), Some(SourceFormat::Nessus));
        assert_eq!(SourceFormat::parse("openvas"), Some(SourceFormat::Openvas));
        assert_eq!(
            SourceFormat::parse("greenbone"),
            Some(SourceFormat::Openvas)
        );
        assert_eq!(SourceFormat::parse("qualys"), None);
        assert_eq!(SourceFormat::Nessus.as_str(), "nessus");
        assert_eq!(SourceFormat::Openvas.as_str(), "openvas");
    }

    #[test]
    fn severity_from_nessus_rank_covers_full_band() {
        assert_eq!(Severity::from_nessus_rank(0), Severity::Info);
        assert_eq!(Severity::from_nessus_rank(1), Severity::Low);
        assert_eq!(Severity::from_nessus_rank(2), Severity::Medium);
        assert_eq!(Severity::from_nessus_rank(3), Severity::High);
        assert_eq!(Severity::from_nessus_rank(4), Severity::Critical);
        assert_eq!(Severity::from_nessus_rank(99), Severity::Critical);
    }

    #[test]
    fn severity_from_cvss_classifies_correctly() {
        assert_eq!(Severity::from_cvss(0.0), Severity::Info);
        assert_eq!(Severity::from_cvss(3.9), Severity::Low);
        assert_eq!(Severity::from_cvss(4.0), Severity::Medium);
        assert_eq!(Severity::from_cvss(6.9), Severity::Medium);
        assert_eq!(Severity::from_cvss(7.0), Severity::High);
        assert_eq!(Severity::from_cvss(8.9), Severity::High);
        assert_eq!(Severity::from_cvss(9.0), Severity::Critical);
        assert_eq!(Severity::from_cvss(10.0), Severity::Critical);
    }

    #[test]
    fn severity_from_openvas_threat_is_case_insensitive() {
        assert_eq!(Severity::from_openvas_threat("LOG"), Severity::Info);
        assert_eq!(Severity::from_openvas_threat("Low"), Severity::Low);
        assert_eq!(Severity::from_openvas_threat(" High "), Severity::High);
        assert_eq!(
            Severity::from_openvas_threat("critical"),
            Severity::Critical
        );
        assert_eq!(Severity::from_openvas_threat("garbage"), Severity::Info);
    }

    #[test]
    fn severity_as_str_round_trips() {
        for s in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert!(!s.as_str().is_empty());
        }
    }
}
