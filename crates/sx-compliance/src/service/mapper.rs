//! [`ControlMapper`] — translate a [`FindingCategory`] into affected controls.
//!
//! The mapping is opinionated and curated: each category maps to one or
//! two controls per framework, picked to cover the high-value, high-
//! frequency findings that the `SentinelX` engagement layer can produce.
//! Where a framework lacks a clean equivalent for a category, we
//! intentionally omit it — false positives in the mapping table are
//! worse than slightly thinner coverage.

use std::sync::Arc;

use crate::model::control::Control;
use crate::model::framework::Framework;
use crate::model::mapping::{FindingCategory, Mapping};
use crate::service::catalog::ControlCatalog;

/// Stateless mapper that returns the set of controls implicated by a
/// [`FindingCategory`], drawing from a shared [`ControlCatalog`].
#[derive(Debug, Clone)]
pub struct ControlMapper {
    catalog: Arc<ControlCatalog>,
}

impl ControlMapper {
    /// Construct a mapper backed by `catalog`.
    #[must_use]
    pub fn new(catalog: Arc<ControlCatalog>) -> Self {
        Self { catalog }
    }

    /// Borrow the underlying catalog.
    #[must_use]
    pub fn catalog(&self) -> &ControlCatalog {
        &self.catalog
    }

    /// Return every control that the given category implicates.
    ///
    /// The result preserves catalog order (framework declaration order,
    /// then control id within framework), is deduplicated, and skips
    /// references that fail to resolve in the catalog (defence-in-depth
    /// — should never happen with the shipped catalog).
    #[must_use]
    pub fn for_category(&self, category: FindingCategory) -> Vec<Control> {
        let refs = category_to_control_refs(category);
        let mut out: Vec<Control> = Vec::with_capacity(refs.len());
        for (fw, id) in refs {
            if let Some(c) = self.catalog.find(*fw, id) {
                if !out
                    .iter()
                    .any(|existing| existing.id == c.id && existing.framework == c.framework)
                {
                    out.push(c.clone());
                }
            }
        }
        out
    }

    /// Return the full mapping table — one [`Mapping`] row per category.
    #[must_use]
    pub fn all_mappings(&self) -> Vec<Mapping> {
        FindingCategory::all()
            .iter()
            .copied()
            .map(|cat| Mapping {
                category: cat,
                controls: self.for_category(cat),
            })
            .collect()
    }
}

/// Static mapping from a finding category to (framework, control id) pairs.
///
/// Rationale: each category lists the controls that — across the supported
/// frameworks — most directly speak to that class of failure. We prefer
/// to under-map than to over-map: every line here is a deliberate "this
/// finding category demonstrably implicates this control" claim that
/// auditors can defend.
const fn category_to_control_refs(
    category: FindingCategory,
) -> &'static [(Framework, &'static str)] {
    match category {
        // Weak / missing auth — privileged access (ISO), logical access
        // (SOC 2), strong auth requirement (PCI), HIPAA technical access,
        // and NIST IA-2 identification/authentication.
        FindingCategory::Authentication => &[
            (Framework::Iso27001, "A.8.2"),
            (Framework::Soc2, "CC6.1"),
            (Framework::PciDss, "8.3.1"),
            (Framework::Hipaa, "164.312(a)(1)"),
            (Framework::Nist80053, "IA-2"),
            (Framework::CisAws, "1.10"),
        ],

        // Broken access controls — ISO access control, SOC 2 logical
        // access, NIST AC-3 / AC-6.
        FindingCategory::Authorization => &[
            (Framework::Iso27001, "A.5.15"),
            (Framework::Soc2, "CC6.1"),
            (Framework::Nist80053, "AC-3"),
            (Framework::Nist80053, "AC-6"),
            (Framework::Hipaa, "164.312(a)(1)"),
            (Framework::CisAws, "1.4"),
        ],

        // Encryption at rest — EBS volume encryption (CIS), HIPAA
        // transmission/storage broadly, NIST SC-8 closest analogue.
        FindingCategory::EncryptionAtRest => &[
            (Framework::Iso27001, "A.5.23"),
            (Framework::Soc2, "CC6.7"),
            (Framework::PciDss, "2.2.1"),
            (Framework::Hipaa, "164.312(e)(1)"),
            (Framework::Nist80053, "SC-8"),
            (Framework::CisAws, "2.2.1"),
        ],

        // Cleartext transit — secure coding (ISO), SOC 2 CC6.7,
        // PCI configuration standards, HIPAA transmission security, NIST SC-8.
        FindingCategory::EncryptionInTransit => &[
            (Framework::Iso27001, "A.8.28"),
            (Framework::Soc2, "CC6.7"),
            (Framework::PciDss, "2.2.1"),
            (Framework::Hipaa, "164.312(e)(1)"),
            (Framework::Nist80053, "SC-8"),
        ],

        // Logging gaps — ISO monitoring, SOC 2 system monitoring,
        // PCI audit logging requirement, NIST AU-2 and AU-12, CIS
        // CloudTrail enablement.
        FindingCategory::Logging => &[
            (Framework::Iso27001, "A.8.16"),
            (Framework::Soc2, "CC7.2"),
            (Framework::PciDss, "10.2.1"),
            (Framework::Nist80053, "AU-2"),
            (Framework::Nist80053, "AU-12"),
            (Framework::CisAws, "2.1"),
        ],

        // Unpatched software — ISO technical vulnerabilities, PCI 6.3.1,
        // NIST SI-2 flaw remediation, ISO secure coding for downstream.
        FindingCategory::VulnerabilityManagement => &[
            (Framework::Iso27001, "A.8.8"),
            (Framework::Soc2, "CC7.2"),
            (Framework::PciDss, "6.3.1"),
            (Framework::Nist80053, "SI-2"),
            (Framework::Iso27001, "A.8.7"),
        ],

        // Flat networks — PCI NSC configuration, SOC 2 boundary
        // protection, NIST SC-7, ISO A.5.23 for cloud boundaries.
        FindingCategory::NetworkSegmentation => &[
            (Framework::Iso27001, "A.5.23"),
            (Framework::Soc2, "CC6.6"),
            (Framework::PciDss, "1.2.1"),
            (Framework::Nist80053, "SC-7"),
        ],

        // Backup / DR — SOC 2 selection of control activities (broad),
        // ISO threat intel for backup integrity attacks.
        FindingCategory::BackupRecovery => &[
            (Framework::Iso27001, "A.5.7"),
            (Framework::Soc2, "CC5.1"),
            (Framework::Hipaa, "164.308(a)(1)"),
        ],

        // Secrets exposure — IAM hygiene controls, root key removal,
        // strong authentication, audit-log capture of secret access.
        FindingCategory::SecretsManagement => &[
            (Framework::Iso27001, "A.8.2"),
            (Framework::Soc2, "CC6.1"),
            (Framework::PciDss, "8.3.1"),
            (Framework::Nist80053, "IA-2"),
            (Framework::CisAws, "1.4"),
            (Framework::CisAws, "1.5"),
        ],

        // Configuration drift — ISO secure coding, PCI configuration
        // standards, SOC 2 CC5.1, NIST SC-7.
        FindingCategory::ConfigurationDrift => &[
            (Framework::Iso27001, "A.8.28"),
            (Framework::Soc2, "CC5.1"),
            (Framework::PciDss, "2.2.1"),
            (Framework::PciDss, "6.4.1"),
            (Framework::Nist80053, "SC-7"),
        ],

        // Incident response — HIPAA security mgmt process, SOC 2
        // monitoring, ISO threat intel, NIST AU-12 / monitoring alarms.
        FindingCategory::IncidentResponse => &[
            (Framework::Iso27001, "A.5.7"),
            (Framework::Soc2, "CC7.2"),
            (Framework::PciDss, "10.2.1"),
            (Framework::Hipaa, "164.308(a)(1)"),
            (Framework::Hipaa, "164.308(a)(5)"),
            (Framework::CisAws, "3.1"),
        ],
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn mapper() -> ControlMapper {
        ControlMapper::new(ControlCatalog::shared())
    }

    #[test]
    fn mapper_authentication_returns_authentication_controls_only() {
        let controls = mapper().for_category(FindingCategory::Authentication);
        assert!(!controls.is_empty());
        // Sanity: each must come from one of the six supported frameworks.
        for c in &controls {
            assert!(Framework::all().contains(&c.framework));
        }
        // Must include the canonical authentication controls.
        assert!(controls
            .iter()
            .any(|c| c.framework == Framework::Nist80053 && c.id == "IA-2"));
        assert!(controls
            .iter()
            .any(|c| c.framework == Framework::PciDss && c.id == "8.3.1"));
    }

    #[test]
    fn mapper_encryption_in_transit_includes_pci_2_2_1() {
        let controls = mapper().for_category(FindingCategory::EncryptionInTransit);
        assert!(controls
            .iter()
            .any(|c| c.framework == Framework::PciDss && c.id == "2.2.1"));
        assert!(controls
            .iter()
            .any(|c| c.framework == Framework::Nist80053 && c.id == "SC-8"));
    }

    #[test]
    fn mapper_logging_includes_iso_8_16_and_nist_au_2() {
        let controls = mapper().for_category(FindingCategory::Logging);
        assert!(controls
            .iter()
            .any(|c| c.framework == Framework::Iso27001 && c.id == "A.8.16"));
        assert!(controls
            .iter()
            .any(|c| c.framework == Framework::Nist80053 && c.id == "AU-2"));
    }

    #[test]
    fn mapper_returns_nonempty_for_every_category() {
        let m = mapper();
        for cat in FindingCategory::all() {
            assert!(
                !m.for_category(*cat).is_empty(),
                "category {cat:?} should map to at least one control",
            );
        }
    }

    #[test]
    fn all_mappings_returns_eleven_rows() {
        assert_eq!(mapper().all_mappings().len(), FindingCategory::all().len());
    }
}
