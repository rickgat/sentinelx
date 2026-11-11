//! Per-tenant admission-rule policy.
//!
//! Each tenant owns a [`RulePack`] — the ordered set of rules the
//! engine evaluates against every inbound `AdmissionRequest`. The pack
//! also carries per-namespace overrides so operationally critical
//! namespaces (most commonly `kube-system`) can opt out of enforcement
//! without disabling the webhook altogether.
//!
//! The engine resolves the active rule pack at request time via
//! [`TenantRulePolicy::for_tenant`]. The default policy returns a
//! permissive empty pack so a freshly-installed webhook does NOT
//! accidentally start denying every workload before the operator has
//! authored a rule pack.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::RwLock;

use super::rules::{
    AdmissionRule, MandatoryLabels, NoHostNetwork, NoLatestTag, NoPrivileged, PodSecurityStandard,
    PssProfile,
};

/// One tenant's active rule pack, plus the namespace opt-out list.
#[derive(Clone, Default)]
pub struct RulePack {
    /// Rules evaluated in order; the first deny short-circuits.
    pub rules: Vec<Arc<dyn AdmissionRule>>,
    /// Namespaces opted out of all enforcement (the engine returns
    /// `allow` with no rule evaluation).
    pub namespace_optouts: HashSet<String>,
    /// Dry-run flag at the rule-pack level. When `true`, the engine
    /// evaluates every rule but always responds `allow=true`, surfacing
    /// the would-be deny reason as a `warning` so operators can stage
    /// enforcement.
    pub dry_run: bool,
}

impl std::fmt::Debug for RulePack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RulePack")
            .field(
                "rules",
                &self.rules.iter().map(|r| r.id()).collect::<Vec<_>>(),
            )
            .field("namespace_optouts", &self.namespace_optouts)
            .field("dry_run", &self.dry_run)
            .finish()
    }
}

impl RulePack {
    /// Construct an empty rule pack (default: every request allowed).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Construct the "recommended" rule pack — the five built-ins minus
    /// `mandatory-labels` (which requires per-tenant configuration of
    /// the required label set). `kube-system` is opted out by default.
    #[must_use]
    pub fn recommended() -> Self {
        let mut optouts = HashSet::new();
        optouts.insert("kube-system".to_owned());
        optouts.insert("kube-public".to_owned());
        optouts.insert("kube-node-lease".to_owned());
        Self {
            rules: vec![
                Arc::new(PodSecurityStandard::new(PssProfile::Baseline)),
                Arc::new(NoPrivileged),
                Arc::new(NoHostNetwork),
                Arc::new(NoLatestTag),
            ],
            namespace_optouts: optouts,
            dry_run: false,
        }
    }

    /// Construct a fully-strict rule pack — PSS restricted + every
    /// other built-in. Useful as a starting point for production
    /// deployments.
    #[must_use]
    pub fn strict(mandatory_labels: Vec<String>) -> Self {
        Self {
            rules: vec![
                Arc::new(PodSecurityStandard::new(PssProfile::Restricted)),
                Arc::new(NoPrivileged),
                Arc::new(NoHostNetwork),
                Arc::new(NoLatestTag),
                Arc::new(MandatoryLabels::new(mandatory_labels)),
            ],
            namespace_optouts: HashSet::new(),
            dry_run: false,
        }
    }

    /// True when `namespace` is in the opt-out list (case-sensitive,
    /// like Kubernetes itself).
    #[must_use]
    pub fn is_namespace_optout(&self, namespace: &str) -> bool {
        self.namespace_optouts.contains(namespace)
    }
}

/// Tenant-keyed policy store.
///
/// Adapters may swap the in-memory implementation here for a
/// Postgres-backed store of `(tenant_id, namespace) → rule pack`; the
/// engine talks to the trait, not the store.
pub trait TenantRulePolicy: Send + Sync + std::fmt::Debug {
    /// Return the rule pack to evaluate for `tenant_id`. Implementations
    /// MUST return a non-`None` value so the engine can fall back to
    /// [`RulePack::empty`] (allow everything) when no policy is wired
    /// up — silently denying every workload is worse than failing open
    /// at startup time before the operator has authored a pack.
    fn for_tenant(&self, tenant_id: &str) -> RulePack;
}

/// In-process, mutable rule-pack store. Used by the monolith adapter
/// for the MVP; the production deployment will plug a Postgres-backed
/// implementation behind the same trait.
#[derive(Debug, Default)]
pub struct InMemoryTenantRulePolicy {
    packs: RwLock<HashMap<String, RulePack>>,
    /// Pack returned when a tenant has no entry. Defaults to
    /// [`RulePack::empty`]; operators set this to a recommended pack
    /// in the adapter.
    default: RwLock<RulePack>,
}

impl InMemoryTenantRulePolicy {
    /// Construct a store with [`RulePack::empty`] as the fallback.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the default rule pack returned when a tenant has no
    /// explicit entry.
    #[allow(clippy::missing_panics_doc, clippy::expect_used)] // RwLock poisoning is a bug, not a runtime condition
    pub fn set_default(&self, pack: RulePack) {
        let mut guard = self.default.write().expect("default lock poisoned");
        *guard = pack;
    }

    /// Set the rule pack for `tenant_id`.
    #[allow(clippy::missing_panics_doc, clippy::expect_used)]
    pub fn set_pack(&self, tenant_id: impl Into<String>, pack: RulePack) {
        let mut guard = self.packs.write().expect("packs lock poisoned");
        guard.insert(tenant_id.into(), pack);
    }

    /// Remove a tenant's pack (falls back to default on next lookup).
    #[allow(clippy::missing_panics_doc, clippy::expect_used)]
    pub fn remove(&self, tenant_id: &str) {
        let mut guard = self.packs.write().expect("packs lock poisoned");
        guard.remove(tenant_id);
    }
}

impl TenantRulePolicy for InMemoryTenantRulePolicy {
    #[allow(clippy::expect_used)] // RwLock poisoning is a bug, not a runtime condition
    fn for_tenant(&self, tenant_id: &str) -> RulePack {
        let packs = self.packs.read().expect("packs lock poisoned");
        if let Some(p) = packs.get(tenant_id) {
            return p.clone();
        }
        drop(packs);
        let def = self.default.read().expect("default lock poisoned");
        def.clone()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn empty_pack_allows_every_namespace_implicitly() {
        let pack = RulePack::empty();
        assert!(pack.rules.is_empty());
        assert!(!pack.is_namespace_optout("default"));
        assert!(!pack.is_namespace_optout("kube-system"));
    }

    #[test]
    fn recommended_pack_optouts_kube_system_family() {
        let pack = RulePack::recommended();
        assert!(pack.is_namespace_optout("kube-system"));
        assert!(pack.is_namespace_optout("kube-public"));
        assert!(pack.is_namespace_optout("kube-node-lease"));
        assert!(!pack.is_namespace_optout("default"));
        assert!(!pack.rules.is_empty());
    }

    #[test]
    fn strict_pack_carries_mandatory_labels() {
        let pack = RulePack::strict(vec!["app".into(), "owner".into()]);
        assert_eq!(
            pack.rules
                .iter()
                .filter(|r| r.id() == "mandatory-labels")
                .count(),
            1
        );
    }

    #[test]
    fn in_memory_returns_default_when_tenant_unknown() {
        let store = InMemoryTenantRulePolicy::new();
        store.set_default(RulePack::recommended());
        let pack = store.for_tenant("t-unknown");
        assert!(pack.is_namespace_optout("kube-system"));
    }

    #[test]
    fn in_memory_per_tenant_pack_takes_priority_over_default() {
        let store = InMemoryTenantRulePolicy::new();
        store.set_default(RulePack::recommended());
        store.set_pack("t-a", RulePack::strict(vec!["app".into()]));
        let pack = store.for_tenant("t-a");
        assert!(pack.rules.iter().any(|r| r.id() == "pss-restricted"));
        assert!(pack.rules.iter().any(|r| r.id() == "mandatory-labels"));
    }

    #[test]
    fn in_memory_remove_falls_back_to_default() {
        let store = InMemoryTenantRulePolicy::new();
        store.set_default(RulePack::recommended());
        store.set_pack("t-a", RulePack::strict(vec![]));
        assert!(store
            .for_tenant("t-a")
            .rules
            .iter()
            .any(|r| r.id() == "pss-restricted"));
        store.remove("t-a");
        assert!(store
            .for_tenant("t-a")
            .rules
            .iter()
            .any(|r| r.id() == "pss-baseline"));
    }
}
