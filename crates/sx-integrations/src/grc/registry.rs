//! Map a tenant's configured [`GrcKind`] onto a concrete connector
//! instance.
//!
//! The registry is intentionally tiny: it holds at most one connector
//! per [`GrcKind`] variant. The monolith adapter is responsible for
//! materialising connectors from tenant credentials at boot (or on
//! demand) and registering them here.
//!
//! ## MVP scope
//!
//! Per the P2-009 contract, **one GRC per tenant** — the registry maps
//! a [`GrcKind`] onto a [`GrcConnector`] trait object so the background
//! job (and the manual sync endpoint) can resolve the right connector
//! by the kind stored on the tenant's `grc_connections` row.

use std::collections::HashMap;
use std::sync::Arc;

use super::connector::{GrcConnector, GrcKind};

/// In-memory registry of GRC connector trait objects keyed by
/// [`GrcKind`].
#[derive(Default, Clone)]
pub struct GrcConnectorRegistry {
    by_kind: HashMap<GrcKind, Arc<dyn GrcConnector>>,
}

impl std::fmt::Debug for GrcConnectorRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrcConnectorRegistry")
            .field("kinds", &self.kinds())
            .finish_non_exhaustive()
    }
}

impl GrcConnectorRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `connector` under its self-reported [`GrcKind`]. Any
    /// previously registered connector for the same kind is replaced
    /// and returned to the caller for orderly cleanup.
    pub fn register(&mut self, connector: Arc<dyn GrcConnector>) -> Option<Arc<dyn GrcConnector>> {
        let kind = connector.kind();
        self.by_kind.insert(kind, connector)
    }

    /// Resolve a connector by [`GrcKind`]. Returns `None` when nothing
    /// is registered.
    #[must_use]
    pub fn get(&self, kind: GrcKind) -> Option<Arc<dyn GrcConnector>> {
        self.by_kind.get(&kind).cloned()
    }

    /// Return every registered [`GrcKind`].
    #[must_use]
    pub fn kinds(&self) -> Vec<GrcKind> {
        let mut out: Vec<GrcKind> = self.by_kind.keys().copied().collect();
        out.sort_by_key(|k| k.as_wire());
        out
    }

    /// Number of registered connectors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_kind.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_kind.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::grc::DrataConnector;

    #[test]
    fn register_and_get_roundtrip() {
        let mut reg = GrcConnectorRegistry::new();
        assert!(reg.is_empty());
        let drata: Arc<dyn GrcConnector> = Arc::new(DrataConnector::new());
        let prev = reg.register(Arc::clone(&drata));
        assert!(prev.is_none());
        assert_eq!(reg.len(), 1);
        let fetched = reg.get(GrcKind::Drata).unwrap();
        assert_eq!(fetched.kind(), GrcKind::Drata);
    }

    #[test]
    fn register_replaces_existing() {
        let mut reg = GrcConnectorRegistry::new();
        let first: Arc<dyn GrcConnector> = Arc::new(DrataConnector::new());
        let second: Arc<dyn GrcConnector> = Arc::new(DrataConnector::new());
        reg.register(Arc::clone(&first));
        let prev = reg.register(Arc::clone(&second));
        assert!(prev.is_some());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn get_missing_returns_none() {
        let reg = GrcConnectorRegistry::new();
        assert!(reg.get(GrcKind::Vanta).is_none());
    }

    #[test]
    fn kinds_sorted_by_wire() {
        let mut reg = GrcConnectorRegistry::new();
        reg.register(Arc::new(DrataConnector::new()));
        let kinds = reg.kinds();
        assert_eq!(kinds, vec![GrcKind::Drata]);
    }
}
