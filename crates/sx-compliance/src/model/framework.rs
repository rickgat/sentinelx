//! [`Framework`] — the discriminator identifying a compliance framework.
//!
//! Variants are serialised in lower-case (no underscores in stable form
//! beyond what the framework name itself implies) so the on-disk format
//! remains compact and unambiguous: `"iso27001"`, `"soc2"`, `"pcidss"`,
//! `"hipaa"`, `"nist80053"`, `"cisaws"`.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::ComplianceError;

/// The compliance frameworks `SentinelX` currently ships.
///
/// The variant set is small and meant to evolve slowly; new frameworks
/// should be added via a deliberate review (they ship as catalog data,
/// not as runtime configuration).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Framework {
    /// ISO/IEC 27001:2022 — Information security management systems.
    Iso27001,
    /// AICPA SOC 2 Trust Services Criteria.
    Soc2,
    /// PCI DSS 4.0 — Payment Card Industry Data Security Standard.
    PciDss,
    /// HIPAA Security Rule — 45 CFR Part 164.
    Hipaa,
    /// NIST SP 800-53 Rev 5 — Security and Privacy Controls.
    Nist80053,
    /// CIS AWS Foundations Benchmark v1.5.0.
    CisAws,
    /// FedRAMP Moderate baseline — NIST SP 800-53 Rev 5 control selection.
    FedRampModerate,
}

impl Framework {
    /// All known variants in declaration order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Iso27001,
            Self::Soc2,
            Self::PciDss,
            Self::Hipaa,
            Self::Nist80053,
            Self::CisAws,
            Self::FedRampModerate,
        ]
    }

    /// Short machine-readable code matching the serde representation.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Iso27001 => "iso27001",
            Self::Soc2 => "soc2",
            Self::PciDss => "pcidss",
            Self::Hipaa => "hipaa",
            Self::Nist80053 => "nist80053",
            Self::CisAws => "cisaws",
            Self::FedRampModerate => "fedrampmoderate",
        }
    }

    /// Long human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Iso27001 => "ISO/IEC 27001:2022",
            Self::Soc2 => "SOC 2 Trust Services Criteria",
            Self::PciDss => "PCI DSS 4.0",
            Self::Hipaa => "HIPAA Security Rule",
            Self::Nist80053 => "NIST SP 800-53 Rev 5",
            Self::CisAws => "CIS AWS Foundations Benchmark v1.5.0",
            Self::FedRampModerate => "FedRAMP Moderate (NIST SP 800-53 Rev 5)",
        }
    }
}

impl fmt::Display for Framework {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl FromStr for Framework {
    type Err = ComplianceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "iso27001" | "iso 27001" | "iso/iec 27001" => Ok(Self::Iso27001),
            "soc2" | "soc 2" => Ok(Self::Soc2),
            "pcidss" | "pci-dss" | "pci dss" => Ok(Self::PciDss),
            "hipaa" => Ok(Self::Hipaa),
            "nist80053" | "nist-800-53" | "nist 800-53" => Ok(Self::Nist80053),
            "cisaws" | "cis-aws" | "cis aws" => Ok(Self::CisAws),
            "fedrampmoderate" | "fedramp-moderate" | "fedramp moderate" | "fedramp_moderate" => {
                Ok(Self::FedRampModerate)
            }
            other => Err(ComplianceError::UnknownFramework(other.to_owned())),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn framework_serialises_to_known_strings() {
        // The serde representation MUST match the documented codes for
        // forward-compatibility of on-disk data.
        let cases = [
            (Framework::Iso27001, "\"iso27001\""),
            (Framework::Soc2, "\"soc2\""),
            (Framework::PciDss, "\"pcidss\""),
            (Framework::Hipaa, "\"hipaa\""),
            (Framework::Nist80053, "\"nist80053\""),
            (Framework::CisAws, "\"cisaws\""),
            (Framework::FedRampModerate, "\"fedrampmoderate\""),
        ];
        for (fw, expected) in cases {
            let s = serde_json::to_string(&fw).unwrap();
            assert_eq!(s, expected, "{fw:?}");
        }
    }

    #[test]
    fn framework_round_trip_from_str() {
        for fw in Framework::all() {
            let parsed: Framework = fw.code().parse().unwrap();
            assert_eq!(parsed, *fw);
        }
    }

    #[test]
    fn unknown_framework_rejected() {
        let r: Result<Framework, _> = "totally-unknown-framework".parse();
        assert!(matches!(r, Err(ComplianceError::UnknownFramework(_))));
    }

    #[test]
    fn fedramp_moderate_aliases_parse() {
        for s in [
            "fedrampmoderate",
            "fedramp-moderate",
            "fedramp moderate",
            "fedramp_moderate",
        ] {
            assert_eq!(s.parse::<Framework>().unwrap(), Framework::FedRampModerate);
        }
        // Bare "fedramp" is intentionally not a full framework id.
        assert!("fedramp".parse::<Framework>().is_err());
    }
}
