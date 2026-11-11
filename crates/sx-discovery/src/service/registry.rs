//! Append-only registry of [`Scanner`] implementations.
//!
//! The registry is intentionally minimal: it is a read-mostly lookup
//! structure populated at process boot via
//! [`crate::controller::register_scanner::RegisterScannerUseCase`]. The
//! controller layer uses [`ScannerRegistry::matching`] to pick scanners
//! capable of handling a given request.

use std::collections::HashMap;
use std::sync::Arc;

use crate::contracts::{ScanIntensity, ScopeTarget};
use crate::error::DiscoveryError;
use crate::service::scanner::{Scanner, ScannerId, TargetKind};

/// Append-only registry of scanners keyed by [`ScannerId`].
#[derive(Debug, Default)]
pub struct ScannerRegistry {
    by_id: HashMap<ScannerId, Arc<dyn Scanner>>,
}

impl ScannerRegistry {
    /// Build an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert `scanner`. Returns an error if a scanner with the same id is
    /// already registered — the registry is append-only.
    pub fn register(&mut self, scanner: Arc<dyn Scanner>) -> Result<(), DiscoveryError> {
        let id = scanner.id();
        if self.by_id.contains_key(&id) {
            return Err(DiscoveryError::internal(format!(
                "scanner already registered: {id}",
            )));
        }
        self.by_id.insert(id, scanner);
        Ok(())
    }

    /// Look up a scanner by id.
    pub fn lookup(&self, id: &ScannerId) -> Result<Arc<dyn Scanner>, DiscoveryError> {
        self.by_id
            .get(id)
            .cloned()
            .ok_or_else(|| DiscoveryError::ScannerNotFound(id.to_string()))
    }

    /// Number of registered scanners.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// `true` if no scanners are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }

    /// Iterator over all registered scanner ids.
    pub fn ids(&self) -> impl Iterator<Item = ScannerId> + '_ {
        self.by_id.keys().cloned()
    }

    /// Return every scanner whose capabilities can handle `(intensity, target)`.
    #[must_use]
    pub fn matching(
        &self,
        intensity: ScanIntensity,
        target: &ScopeTarget,
    ) -> Vec<Arc<dyn Scanner>> {
        let kind = TargetKind::of(target);
        self.by_id
            .values()
            .filter(|s| s.capabilities().supports(intensity, kind))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::HashSet;

    use async_trait::async_trait;

    use super::*;
    use crate::contracts::ScopeTarget;
    use crate::model::scan_result::ScanResult;
    use crate::service::scanner::{ScanContext, ScannerCapabilities};

    #[derive(Debug)]
    struct DummyScanner(ScannerId);

    #[async_trait]
    impl Scanner for DummyScanner {
        fn id(&self) -> ScannerId {
            self.0.clone()
        }
        fn capabilities(&self) -> ScannerCapabilities {
            ScannerCapabilities {
                max_intensity: ScanIntensity::Light,
                target_kinds: std::iter::once(TargetKind::Domain).collect::<HashSet<_>>(),
                max_throughput_obs_per_sec: 10,
            }
        }
        async fn scan(
            &self,
            _ctx: ScanContext,
            _target: ScopeTarget,
        ) -> Result<ScanResult, DiscoveryError> {
            Err(DiscoveryError::internal("dummy"))
        }
    }

    #[test]
    fn register_and_lookup_round_trip() {
        let id = ScannerId::new("dummy_v1");
        let mut reg = ScannerRegistry::new();
        reg.register(Arc::new(DummyScanner(id.clone()))).unwrap();
        let got = reg.lookup(&id).unwrap();
        assert_eq!(got.id(), id);
    }

    #[test]
    fn duplicate_registration_is_rejected() {
        let id = ScannerId::new("dup_v1");
        let mut reg = ScannerRegistry::new();
        reg.register(Arc::new(DummyScanner(id.clone()))).unwrap();
        let again = reg.register(Arc::new(DummyScanner(id)));
        assert!(again.is_err());
    }

    #[test]
    fn lookup_unknown_returns_not_found() {
        let reg = ScannerRegistry::new();
        let r = reg.lookup(&ScannerId::new("nope"));
        assert!(matches!(r, Err(DiscoveryError::ScannerNotFound(_))));
    }

    #[test]
    fn matching_filters_by_capabilities() {
        let id = ScannerId::new("filter_v1");
        let mut reg = ScannerRegistry::new();
        reg.register(Arc::new(DummyScanner(id))).unwrap();
        let domain = ScopeTarget::Domain(crate::contracts::Fqdn::new("example.com").unwrap());
        let matched = reg.matching(ScanIntensity::Light, &domain);
        assert_eq!(matched.len(), 1);
    }
}
