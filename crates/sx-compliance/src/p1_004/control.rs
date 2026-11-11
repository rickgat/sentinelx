//! Per-control identifiers + the built-in P1-004 catalogue.
//!
//! `ControlId` is a `String` newtype so callers cannot accidentally pass a
//! finding id or a tenant id where a control id is expected. The built-in
//! catalogue is the closed set the MVP collectors target.

use serde::{Deserialize, Serialize};

/// Compliance framework label associated with a built-in control.
///
/// Multi-label is intentional: most "common controls" appear in
/// multiple frameworks. The mapping in [`ControlMeta::frameworks`]
/// records which ones the collector's evidence satisfies. The string
/// representation matches the existing `Framework` enum where
/// possible (`"soc2"`, `"iso27001"`, `"pci_dss"`) so downstream
/// dashboards can join cleanly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameworkLabel {
    /// AICPA SOC 2 trust services criteria.
    Soc2,
    /// ISO/IEC 27001:2022 Annex A.
    Iso27001,
    /// PCI DSS v4.0.
    PciDss,
}

impl FrameworkLabel {
    /// Short, machine-readable code matching the serde tag.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Soc2 => "soc2",
            Self::Iso27001 => "iso27001",
            Self::PciDss => "pci_dss",
        }
    }
}

/// Framework-local control identifier.
///
/// Carries only the SentinelX namespace (`"SX-…"`); the framework
/// references live in [`ControlMeta::frameworks`] so a control can
/// satisfy multiple frameworks without ambiguity in the database.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ControlId(pub String);

impl ControlId {
    /// Construct from anything convertible into a `String`.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Borrow the inner string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ControlId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for ControlId {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

/// Static metadata attached to every built-in control.
///
/// `Serialize` only — the built-in catalogue lives in code as a
/// `&'static [FrameworkLabel]` slice, which is not `Deserialize`. The
/// API layer never round-trips this struct; it produces it for read-only
/// listing endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControlMeta {
    /// SentinelX-local control identifier.
    pub id: ControlId,
    /// One-line auditor-readable description.
    pub title: &'static str,
    /// Compliance frameworks this control's evidence satisfies.
    pub frameworks: &'static [FrameworkLabel],
}

/// Stable id constants — these strings are committed to in the
/// audit log and the manifest, so they must not change between
/// releases without an explicit migration plan.
pub mod ids {
    /// MFA enrolment rate across the tenant's user base.
    pub const MFA_ENROLLMENT_RATE: &str = "SX-MFA-ENROLLMENT-RATE";
    /// AWS IAM account password policy snapshot.
    pub const AWS_IAM_PASSWORD_POLICY: &str = "SX-AWS-IAM-PASSWORD-POLICY";
    /// Vault sealed-state probe.
    pub const VAULT_SEALED_STATE: &str = "SX-VAULT-SEALED-STATE";
    /// Kill-switch tested-recently check (90-day window).
    pub const KILL_SWITCH_TESTED_RECENTLY: &str = "SX-KILL-SWITCH-TESTED-RECENTLY";
    /// Audit chain integrity verification (7-day window).
    pub const AUDIT_CHAIN_INTEGRITY_VERIFY: &str = "SX-AUDIT-CHAIN-INTEGRITY-VERIFY";
}

/// The closed set of built-in controls shipped with P1-004 MVP.
#[must_use]
pub fn builtin_controls() -> Vec<ControlMeta> {
    vec![
        ControlMeta {
            id: ControlId::new(ids::MFA_ENROLLMENT_RATE),
            title: "MFA enrolment rate across active users meets policy threshold.",
            frameworks: &[
                FrameworkLabel::Soc2,
                FrameworkLabel::Iso27001,
                FrameworkLabel::PciDss,
            ],
        },
        ControlMeta {
            id: ControlId::new(ids::AWS_IAM_PASSWORD_POLICY),
            title: "AWS IAM account password policy meets PCI/SOC2 minimums.",
            frameworks: &[FrameworkLabel::Soc2, FrameworkLabel::PciDss],
        },
        ControlMeta {
            id: ControlId::new(ids::VAULT_SEALED_STATE),
            title: "Vault key-management service is unsealed and reachable.",
            frameworks: &[FrameworkLabel::Soc2, FrameworkLabel::Iso27001],
        },
        ControlMeta {
            id: ControlId::new(ids::KILL_SWITCH_TESTED_RECENTLY),
            title: "Autonomous-action kill-switch was tested within the last 90 days.",
            frameworks: &[FrameworkLabel::Soc2, FrameworkLabel::Iso27001],
        },
        ControlMeta {
            id: ControlId::new(ids::AUDIT_CHAIN_INTEGRITY_VERIFY),
            title: "Append-only audit chain verifies cleanly over the last 7 days.",
            frameworks: &[
                FrameworkLabel::Soc2,
                FrameworkLabel::Iso27001,
                FrameworkLabel::PciDss,
            ],
        },
    ]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn control_id_round_trips_through_serde() {
        let id = ControlId::new(ids::MFA_ENROLLMENT_RATE);
        let s = serde_json::to_string(&id).unwrap();
        // transparent serde — bare string, no JSON object.
        assert_eq!(s, "\"SX-MFA-ENROLLMENT-RATE\"");
        let back: ControlId = serde_json::from_str(&s).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn builtin_catalogue_has_five_entries() {
        let cats = builtin_controls();
        assert_eq!(cats.len(), 5);
        let ids: Vec<&str> = cats.iter().map(|c| c.id.as_str()).collect();
        assert!(ids.contains(&ids::MFA_ENROLLMENT_RATE));
        assert!(ids.contains(&ids::AWS_IAM_PASSWORD_POLICY));
        assert!(ids.contains(&ids::VAULT_SEALED_STATE));
        assert!(ids.contains(&ids::KILL_SWITCH_TESTED_RECENTLY));
        assert!(ids.contains(&ids::AUDIT_CHAIN_INTEGRITY_VERIFY));
    }

    #[test]
    fn framework_label_codes_are_stable() {
        assert_eq!(FrameworkLabel::Soc2.code(), "soc2");
        assert_eq!(FrameworkLabel::Iso27001.code(), "iso27001");
        assert_eq!(FrameworkLabel::PciDss.code(), "pci_dss");
    }
}
