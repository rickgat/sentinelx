//! KEV severity-uplift hook.
//!
//! CISA's Known Exploited Vulnerabilities (KEV) catalogue is normally a CVE
//! catalogue, not a CSPM check catalogue. For misconfigurations that are
//! *known to be a precondition* for actively exploited CVEs (e.g. anonymous
//! public storage buckets, exposed metadata services, missing TDE on
//! Internet-reachable databases) we want to **uplift severity by one tier**
//! at write time so the multicloud dashboard prioritises them.
//!
//! This module exposes a tiny [`KevCatalog`] trait so the production wiring
//! can plug in `sx-intel-feeds`' richer catalogue, while tests / partial
//! deployments use [`NullKevCatalog`] or [`InMemoryKevCatalog`].

use std::collections::HashSet;

use super::model::CloudProvider;

/// Catalogue of `SentinelX` check ids that should be severity-uplifted when
/// they appear in a finding.
pub trait KevCatalog: Send + Sync + std::fmt::Debug {
    /// `true` iff `check_id` is in the KEV-adjacent set for `provider`.
    fn matches(&self, provider: CloudProvider, check_id: &str) -> bool;
}

/// No-op catalogue: never matches. Use in tests and when the KEV feed is
/// unavailable.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullKevCatalog;

impl KevCatalog for NullKevCatalog {
    fn matches(&self, _provider: CloudProvider, _check_id: &str) -> bool {
        false
    }
}

/// In-memory KEV catalogue. Wire feeders may rebuild this from the upstream
/// CISA feed plus a per-provider misconfiguration overlay maintained by the
/// `SentinelX` content team.
#[derive(Debug, Default, Clone)]
pub struct InMemoryKevCatalog {
    set: HashSet<(CloudProvider, String)>,
}

impl InMemoryKevCatalog {
    /// New empty catalogue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a `(provider, sx_check_id)` entry.
    pub fn insert(&mut self, provider: CloudProvider, check_id: impl Into<String>) {
        self.set.insert((provider, check_id.into()));
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.set.len()
    }

    /// `true` iff empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

impl KevCatalog for InMemoryKevCatalog {
    fn matches(&self, provider: CloudProvider, check_id: &str) -> bool {
        self.set.contains(&(provider, check_id.to_owned()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn null_catalog_never_matches() {
        let c = NullKevCatalog;
        assert!(!c.matches(CloudProvider::Gcp, "anything"));
        assert!(!c.matches(CloudProvider::Azure, "anything"));
    }

    #[test]
    fn in_memory_catalog_exact_match() {
        let mut c = InMemoryKevCatalog::new();
        c.insert(
            CloudProvider::Azure,
            "cspm.azure.storage.blob_public_access_enabled",
        );
        assert!(c.matches(
            CloudProvider::Azure,
            "cspm.azure.storage.blob_public_access_enabled"
        ));
        assert!(!c.matches(
            CloudProvider::Gcp,
            "cspm.azure.storage.blob_public_access_enabled"
        ));
        assert!(!c.matches(CloudProvider::Azure, "other"));
    }
}
