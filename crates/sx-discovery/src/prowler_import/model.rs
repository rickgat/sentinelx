//! Value objects for the Prowler v4 import pipeline.

use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::contracts::TenantId;

/// Supported Prowler providers for P1-009.
///
/// AWS is intentionally excluded here — the OCSF-driven path in
/// [`crate::scanner::cspm`] handles AWS at the scanner layer. The native
/// JSON importer only covers GCP and Azure to avoid double-ingestion of
/// AWS findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudProvider {
    /// Google Cloud Platform.
    Gcp,
    /// Microsoft Azure.
    Azure,
}

impl CloudProvider {
    /// Lowercase string used in storage / wire formats.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gcp => "gcp",
            Self::Azure => "azure",
        }
    }

    /// Parse a Prowler `Provider` string. Accepts common variants.
    ///
    /// Returns `None` for `aws` (handled by the OCSF path) and any
    /// unknown value.
    #[must_use]
    pub fn from_prowler(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "gcp" | "google" | "googlecloud" | "google_cloud" => Some(Self::Gcp),
            "azure" | "az" => Some(Self::Azure),
            _ => None,
        }
    }
}

impl fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Canonical severity scale used by the multicloud table.
///
/// Maps from Prowler's `critical / high / medium / low / informational`
/// (Prowler v4 spells the lowest tier `informational` in some places and
/// `info` in others; we accept both).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational only — no security impact.
    Info,
    /// Low — minor hygiene issue.
    Low,
    /// Medium — meaningful misconfiguration.
    Medium,
    /// High — exploitable misconfiguration.
    High,
    /// Critical — actively exploitable or KEV-uplift target.
    Critical,
}

impl Severity {
    /// Lowercase string form used in storage / API responses.
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

    /// Parse Prowler's severity string. Unknown values clamp to
    /// [`Severity::Medium`].
    #[must_use]
    pub fn from_prowler(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "critical" => Self::Critical,
            "high" => Self::High,
            "low" => Self::Low,
            "informational" | "info" => Self::Info,
            // "medium" plus everything unknown clamps to Medium.
            _ => Self::Medium,
        }
    }

    /// Return the next-higher severity, saturating at
    /// [`Severity::Critical`]. Used for KEV uplifts.
    #[must_use]
    pub const fn uplift_one(self) -> Self {
        match self {
            Self::Info => Self::Low,
            Self::Low => Self::Medium,
            Self::Medium => Self::High,
            Self::High | Self::Critical => Self::Critical,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Status of a single Prowler check execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ProwlerStatus {
    /// Check passed — no finding emitted.
    Pass,
    /// Check failed — finding emitted.
    Fail,
    /// Check was muted by configuration.
    Muted,
    /// Check could not run (timeout, missing permission, etc.).
    Manual,
}

impl ProwlerStatus {
    /// Parse from Prowler's `Status` field (case-insensitive). Unknown values
    /// fall through to [`Self::Manual`] so we never lose unparseable rows
    /// — they're recorded but won't generate findings.
    #[must_use]
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_uppercase().as_str() {
            "PASS" => Self::Pass,
            "FAIL" => Self::Fail,
            "MUTED" => Self::Muted,
            _ => Self::Manual,
        }
    }
}

/// Parsed, normalised Prowler finding before `SentinelX` check-id mapping or
/// KEV uplift.
///
/// All optional metadata is preserved verbatim from the upstream JSON so we
/// can carry it onto [`MulticloudCspmFinding`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProwlerFinding {
    /// Raw Prowler `CheckID` (e.g. `iam_password_policy_minimum_length_14`).
    pub prowler_check_id: String,
    /// Cloud provider this finding originated from.
    pub provider: CloudProvider,
    /// Cloud account identifier: GCP project id or Azure subscription id.
    pub account_id: String,
    /// GCP region or Azure location, when known.
    pub region: Option<String>,
    /// Native resource identifier (GCP resource path / Azure resource id).
    pub resource_uid: String,
    /// Short, human-readable resource name.
    pub resource_name: Option<String>,
    /// Resource type as reported by Prowler (e.g.
    /// `Microsoft.Storage/storageAccounts`).
    pub resource_type: Option<String>,
    /// Severity reported by Prowler. May be uplifted at write time.
    pub severity: Severity,
    /// Status — only [`ProwlerStatus::Fail`] becomes a finding row.
    pub status: ProwlerStatus,
    /// Free-form extended status message.
    pub status_extended: Option<String>,
    /// Long-form description / risk text.
    pub description: Option<String>,
    /// Remediation hint.
    pub remediation: Option<String>,
    /// CIS Benchmark reference (e.g. `CIS GCP 1.2`).
    pub compliance_refs: Vec<String>,
}

/// A row in the per-tenant `cspm_findings_multicloud` table.
///
/// Carries the cross-cloud canonicalised form of a Prowler finding, with the
/// `SentinelX` check-id, the resolved provider-agnostic resource path, and the
/// post-uplift severity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MulticloudCspmFinding {
    /// UUID v7 row id.
    pub id: Uuid,
    /// Tenant scope.
    pub tenant_id: TenantId,
    /// SentinelX-canonical check id (mapped via [`crate::prowler_import::registry`]).
    pub check_id: String,
    /// Original Prowler check id, retained for audit / debugging.
    pub prowler_check_id: String,
    /// `gcp` or `azure`.
    pub cloud_provider: CloudProvider,
    /// Cloud account: GCP project id / Azure subscription id.
    pub account_id: String,
    /// Region / location, if known.
    pub region: Option<String>,
    /// ARN-equivalent stable resource id. For GCP this is the resource path;
    /// for Azure it is the Azure resource ID.
    pub asset_id: String,
    /// Short, human-readable resource name.
    pub resource_name: Option<String>,
    /// Resource type as reported by Prowler.
    pub resource_type: Option<String>,
    /// Final severity after KEV uplift.
    pub severity: Severity,
    /// Severity prior to KEV uplift. Equal to `severity` when no uplift fired.
    pub original_severity: Severity,
    /// `true` iff the KEV catalogue uplifted this finding.
    pub kev_uplifted: bool,
    /// Free-form status message from Prowler.
    pub status_extended: Option<String>,
    /// Description / risk text.
    pub description: Option<String>,
    /// Remediation hint.
    pub remediation: Option<String>,
    /// Compliance frame references (CIS v2.0 controls etc.).
    pub compliance_refs: Vec<String>,
    /// When this row was first persisted.
    pub created_at: OffsetDateTime,
}
