//! [`FindingCategory`] and [`Mapping`] — the bridge between findings and controls.
//!
//! The category is a deliberately small enum: each variant maps to a
//! curated set of controls in the catalog, decided once and frozen at
//! build time. The set lives in [`crate::service::mapper`].

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::ComplianceError;
use crate::model::control::Control;

/// Categories used to bridge findings to compliance controls.
///
/// Each variant represents a class of security problem the platform can
/// report. The [`crate::service::mapper::ControlMapper`] returns the set
/// of controls relevant to each category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    /// Weak / missing authentication (no MFA, default creds, weak password).
    Authentication,
    /// Broken authorization (privilege escalation, IDOR, missing access checks).
    Authorization,
    /// Sensitive data is stored without encryption at rest.
    EncryptionAtRest,
    /// Sensitive data is transmitted without encryption in transit.
    EncryptionInTransit,
    /// Audit / activity logging is missing, partial, or untrustworthy.
    Logging,
    /// Unpatched / vulnerable software components.
    VulnerabilityManagement,
    /// Flat networks / missing segmentation between trust zones.
    NetworkSegmentation,
    /// Backup or disaster-recovery posture is inadequate.
    BackupRecovery,
    /// Hardcoded / exposed / poorly rotated secrets.
    SecretsManagement,
    /// Drift from a hardened configuration baseline.
    ConfigurationDrift,
    /// Inadequate incident response readiness or runbooks.
    IncidentResponse,
}

impl FindingCategory {
    /// All known variants in declaration order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Authentication,
            Self::Authorization,
            Self::EncryptionAtRest,
            Self::EncryptionInTransit,
            Self::Logging,
            Self::VulnerabilityManagement,
            Self::NetworkSegmentation,
            Self::BackupRecovery,
            Self::SecretsManagement,
            Self::ConfigurationDrift,
            Self::IncidentResponse,
        ]
    }

    /// Short machine-readable code matching the serde representation.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::Authorization => "authorization",
            Self::EncryptionAtRest => "encryption_at_rest",
            Self::EncryptionInTransit => "encryption_in_transit",
            Self::Logging => "logging",
            Self::VulnerabilityManagement => "vulnerability_management",
            Self::NetworkSegmentation => "network_segmentation",
            Self::BackupRecovery => "backup_recovery",
            Self::SecretsManagement => "secrets_management",
            Self::ConfigurationDrift => "configuration_drift",
            Self::IncidentResponse => "incident_response",
        }
    }

    /// Parse a finding-category code (the snake-case form).
    ///
    /// Returns [`ComplianceError::UnknownCategory`] for any value the
    /// crate does not recognise. This is the same helper that the CLI
    /// uses to validate user input.
    pub fn parse(s: &str) -> Result<Self, ComplianceError> {
        Self::from_str(s)
    }
}

impl fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl FromStr for FindingCategory {
    type Err = ComplianceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Accept both kebab-case and snake_case for forgiving CLI input.
        let normalised = s.to_ascii_lowercase().replace('-', "_");
        match normalised.as_str() {
            "authentication" => Ok(Self::Authentication),
            "authorization" => Ok(Self::Authorization),
            "encryption_at_rest" => Ok(Self::EncryptionAtRest),
            "encryption_in_transit" => Ok(Self::EncryptionInTransit),
            "logging" => Ok(Self::Logging),
            "vulnerability_management" => Ok(Self::VulnerabilityManagement),
            "network_segmentation" => Ok(Self::NetworkSegmentation),
            "backup_recovery" => Ok(Self::BackupRecovery),
            "secrets_management" => Ok(Self::SecretsManagement),
            "configuration_drift" => Ok(Self::ConfigurationDrift),
            "incident_response" => Ok(Self::IncidentResponse),
            _ => Err(ComplianceError::UnknownCategory(s.to_owned())),
        }
    }
}

/// A static category-to-controls mapping row.
///
/// Held by the [`crate::service::mapper::ControlMapper`] — exposed for
/// callers that want to render or export the full mapping table.
#[derive(Debug, Clone)]
pub struct Mapping {
    /// Source category for the mapping row.
    pub category: FindingCategory,
    /// Controls that the category implicates, in catalog order.
    pub controls: Vec<Control>,
}
