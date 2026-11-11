//! Dedupe by `(tenant_id, asset_id, check_id)`.
//!
//! Prowler reruns frequently produce overlapping reports. The multicloud
//! findings table must collapse two reports of the same misconfiguration
//! into a single row. We dedupe at write time using the composite key
//! `(tenant_id, asset_id, check_id)` per the spec.
//!
//! The [`Deduplicator`] is a process-local helper that filters duplicates
//! **inside a single import batch**. Cross-batch deduping is the sink's
//! responsibility (production: a unique index in Postgres; tests: an
//! in-memory `HashMap` in [`super::importer::InMemoryMulticloudSink`]).

use std::collections::HashSet;

use crate::contracts::TenantId;

/// Composite dedupe key.
///
/// The `*_id` suffixes are kept intentionally — each field is a foreign-key-
/// shaped identifier and the `clippy::struct_field_names` lint's "shared
/// postfix" warning would otherwise mask the very intent of the type.
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DedupeKey {
    /// Tenant scope.
    pub tenant_id: TenantId,
    /// ARN-equivalent stable resource identifier.
    pub asset_id: String,
    /// `SentinelX`-canonical check id.
    pub check_id: String,
}

impl DedupeKey {
    /// Build a key.
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        asset_id: impl Into<String>,
        check_id: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id,
            asset_id: asset_id.into(),
            check_id: check_id.into(),
        }
    }
}

/// Single-pass deduplicator for one import batch.
#[derive(Debug, Default)]
pub struct Deduplicator {
    seen: HashSet<DedupeKey>,
}

impl Deduplicator {
    /// Build an empty deduplicator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of unique keys observed so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// `true` iff no keys have been observed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Attempt to register `key`. Returns `true` if the key was new (and
    /// the finding should be written), `false` if it was already present.
    pub fn admit(&mut self, key: DedupeKey) -> bool {
        self.seen.insert(key)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn admits_new_keys() {
        let mut d = Deduplicator::new();
        let t = TenantId::new();
        assert!(d.admit(DedupeKey::new(t, "asset-1", "cspm.gcp.iam.x")));
        assert!(d.admit(DedupeKey::new(t, "asset-2", "cspm.gcp.iam.x")));
        assert!(d.admit(DedupeKey::new(t, "asset-1", "cspm.gcp.iam.y")));
        assert_eq!(d.len(), 3);
    }

    #[test]
    fn rejects_repeats() {
        let mut d = Deduplicator::new();
        let t = TenantId::new();
        assert!(d.admit(DedupeKey::new(t, "asset-1", "cspm.gcp.iam.x")));
        assert!(!d.admit(DedupeKey::new(t, "asset-1", "cspm.gcp.iam.x")));
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn different_tenants_dont_collide() {
        let mut d = Deduplicator::new();
        let t1 = TenantId::new();
        let t2 = TenantId::new();
        assert!(d.admit(DedupeKey::new(t1, "asset-1", "cspm.gcp.iam.x")));
        assert!(d.admit(DedupeKey::new(t2, "asset-1", "cspm.gcp.iam.x")));
        assert_eq!(d.len(), 2);
    }
}
