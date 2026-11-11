//! Mapping table from Prowler check IDs to `SentinelX` check IDs.
//!
//! Prowler ships hundreds of provider-specific check identifiers
//! (`iam_sa_user_managed_keys`, `storage_blob_public_access_level_is_disabled`,
//! …). `SentinelX`'s findings ledger uses provider-prefixed canonical IDs of
//! the form `cspm.<provider>.<short_name>`. This module is the single
//! authoritative bridge between the two.
//!
//! ## Why canonical IDs?
//!
//! - The dedupe key is `(tenant_id, asset_id, check_id)`. Without a stable
//!   canonical form, a single Prowler renaming would create duplicate
//!   findings.
//! - The remediation playbook catalogue indexes by `SentinelX` check id, not
//!   Prowler check id.
//! - Cross-cloud baselines (e.g. "no overly-permissive storage") want a
//!   shared umbrella id that Prowler doesn't provide.
//!
//! ## Falling back
//!
//! Unknown Prowler check ids fall through to
//! `cspm.<provider>.unmapped.<prowler_id>` so they can still be tracked,
//! dashboarded and deduped. The `MappedCheck::is_unmapped` flag flags these
//! rows for later catalogue updates.

use std::collections::HashMap;

use super::model::CloudProvider;

/// The result of mapping a Prowler check id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedCheck {
    /// SentinelX-canonical check id.
    pub check_id: String,
    /// `true` if the source Prowler id was not present in the registry —
    /// the caller may want to flag these for review.
    pub is_unmapped: bool,
}

/// Static + extensible mapping table from Prowler check ids to `SentinelX`
/// canonical ids.
#[derive(Debug, Clone)]
pub struct CheckIdRegistry {
    table: HashMap<String, String>,
}

impl CheckIdRegistry {
    /// Build a registry seeded with the Phase-1 baseline mappings for GCP
    /// and Azure.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut table: HashMap<String, String> = HashMap::new();
        // -------------------------------------------------------------
        // GCP baseline (CIS GCP v2.0 highlights).
        // -------------------------------------------------------------
        for (prowler, sx) in [
            (
                "iam_sa_user_managed_keys",
                "cspm.gcp.iam.sa_user_managed_keys",
            ),
            (
                "iam_sa_no_user_managed_keys",
                "cspm.gcp.iam.sa_user_managed_keys",
            ),
            ("iam_no_user_keys", "cspm.gcp.iam.no_user_keys"),
            (
                "iam_member_with_serviceaccountuser_or_token_creator_roles",
                "cspm.gcp.iam.broad_service_account_role",
            ),
            (
                "compute_instance_public_ip",
                "cspm.gcp.compute.instance_public_ip",
            ),
            (
                "compute_firewall_rule_open_to_internet",
                "cspm.gcp.compute.firewall_open_to_internet",
            ),
            (
                "storage_bucket_uniform_bucket_level_access",
                "cspm.gcp.storage.uniform_bucket_level_access",
            ),
            (
                "storage_bucket_public_access",
                "cspm.gcp.storage.bucket_public_access",
            ),
            (
                "kms_key_rotation_enabled",
                "cspm.gcp.kms.key_rotation_disabled",
            ),
            (
                "logging_audit_logs_enabled",
                "cspm.gcp.logging.audit_logs_disabled",
            ),
        ] {
            table.insert(prowler.to_owned(), sx.to_owned());
        }
        // -------------------------------------------------------------
        // Azure baseline (CIS Azure v2.0 highlights).
        // -------------------------------------------------------------
        for (prowler, sx) in [
            (
                "storage_blob_public_access_level_is_disabled",
                "cspm.azure.storage.blob_public_access_enabled",
            ),
            (
                "storage_secure_transfer_required_is_enabled",
                "cspm.azure.storage.secure_transfer_disabled",
            ),
            (
                "storage_default_network_access_rule_is_denied",
                "cspm.azure.storage.default_network_access_allowed",
            ),
            (
                "network_nsg_allow_internet_inbound_ssh",
                "cspm.azure.network.nsg_ssh_open_to_internet",
            ),
            (
                "network_nsg_allow_internet_inbound_rdp",
                "cspm.azure.network.nsg_rdp_open_to_internet",
            ),
            (
                "vm_endpoint_protection_installed",
                "cspm.azure.vm.endpoint_protection_missing",
            ),
            (
                "keyvault_logging_enabled",
                "cspm.azure.keyvault.logging_disabled",
            ),
            (
                "monitor_diagnostic_setting_with_appropriate_categories",
                "cspm.azure.monitor.diagnostic_setting_missing_categories",
            ),
            (
                "defender_ensure_defender_for_storage_is_on",
                "cspm.azure.defender.storage_disabled",
            ),
            (
                "sqlserver_tde_encryption_enabled",
                "cspm.azure.sql.tde_disabled",
            ),
        ] {
            table.insert(prowler.to_owned(), sx.to_owned());
        }
        Self { table }
    }

    /// Build an empty registry (useful in tests).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            table: HashMap::new(),
        }
    }

    /// Insert / override one mapping.
    pub fn insert(&mut self, prowler_check_id: impl Into<String>, sx_check_id: impl Into<String>) {
        self.table
            .insert(prowler_check_id.into(), sx_check_id.into());
    }

    /// Look up the `SentinelX` check id for a Prowler check.
    ///
    /// Falls back to `cspm.<provider>.unmapped.<prowler_id>` when no
    /// explicit mapping exists.
    #[must_use]
    pub fn map(&self, provider: CloudProvider, prowler_check_id: &str) -> MappedCheck {
        self.table.get(prowler_check_id).map_or_else(
            || MappedCheck {
                check_id: format!(
                    "cspm.{provider}.unmapped.{prowler_check_id}",
                    provider = provider.as_str(),
                ),
                is_unmapped: true,
            },
            |sx| MappedCheck {
                check_id: sx.clone(),
                is_unmapped: false,
            },
        )
    }

    /// Number of registered explicit mappings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// `true` iff no mappings are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

impl Default for CheckIdRegistry {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn defaults_contain_known_gcp_and_azure_checks() {
        let r = CheckIdRegistry::with_defaults();
        assert!(!r.is_empty());
        let gcp = r.map(CloudProvider::Gcp, "iam_sa_user_managed_keys");
        assert_eq!(gcp.check_id, "cspm.gcp.iam.sa_user_managed_keys");
        assert!(!gcp.is_unmapped);
        let azure = r.map(
            CloudProvider::Azure,
            "storage_blob_public_access_level_is_disabled",
        );
        assert_eq!(
            azure.check_id,
            "cspm.azure.storage.blob_public_access_enabled"
        );
    }

    #[test]
    fn unknown_check_falls_through_to_unmapped() {
        let r = CheckIdRegistry::with_defaults();
        let m = r.map(CloudProvider::Gcp, "totally_new_check");
        assert!(m.is_unmapped);
        assert_eq!(m.check_id, "cspm.gcp.unmapped.totally_new_check");
    }

    #[test]
    fn overrides_take_precedence() {
        let mut r = CheckIdRegistry::empty();
        r.insert("foo", "cspm.azure.foo.v1");
        let m = r.map(CloudProvider::Azure, "foo");
        assert_eq!(m.check_id, "cspm.azure.foo.v1");
        assert!(!m.is_unmapped);
    }
}
