//! Technique registry.
//!
//! Composition-root wiring constructs a [`TechniqueRegistry`], registers every
//! safe-only technique, and hands the registry to
//! [`crate::controller::run_simulation::RunSimulationUseCase`]. Duplicate-id
//! registration is rejected.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::BasError;
use crate::model::mode::AttackMode;
use crate::model::technique::AttackTechnique;

/// Holds registered techniques keyed by their stable id.
#[derive(Debug, Default)]
pub struct TechniqueRegistry {
    entries: HashMap<&'static str, Arc<dyn AttackTechnique>>,
}

impl TechniqueRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Register a technique. Returns [`BasError::DuplicateTechnique`] when
    /// the technique's id is already taken.
    pub fn register(&mut self, t: Arc<dyn AttackTechnique>) -> Result<(), BasError> {
        let id = t.id();
        if self.entries.contains_key(id) {
            return Err(BasError::DuplicateTechnique(id.to_owned()));
        }
        self.entries.insert(id, t);
        Ok(())
    }

    /// Look up a technique by id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<Arc<dyn AttackTechnique>> {
        self.entries.get(id).cloned()
    }

    /// Returns every technique whose `max_mode` is `<= mode`.
    #[must_use]
    pub fn list_for_mode(&self, mode: AttackMode) -> Vec<Arc<dyn AttackTechnique>> {
        let mut out: Vec<Arc<dyn AttackTechnique>> = self
            .entries
            .values()
            .filter(|t| t.max_mode() <= mode)
            .cloned()
            .collect();
        out.sort_by_key(|t| t.id());
        out
    }

    /// Returns the number of registered techniques.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when no techniques are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
// Tests construct fixed-size vectors and index them directly.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::TechniqueRegistry;
    use crate::error::BasError;
    use crate::model::mode::AttackMode;
    use crate::model::technique::AttackTechnique;
    use crate::technique::passive_cve_match::PassiveCveMatch;
    use crate::technique::theoretical_reachability::TheoreticalReachability;
    use std::sync::Arc;

    #[test]
    fn registry_duplicate_register_fails() {
        let mut r = TechniqueRegistry::new();
        let a = Arc::new(TheoreticalReachability::new(Vec::new(), "x".into(), None));
        let b = Arc::new(TheoreticalReachability::new(Vec::new(), "y".into(), None));
        r.register(a).unwrap();
        let err = r.register(b).unwrap_err();
        assert!(matches!(err, BasError::DuplicateTechnique(_)));
    }

    #[test]
    fn registry_get_returns_registered() {
        let mut r = TechniqueRegistry::new();
        let a = Arc::new(TheoreticalReachability::new(Vec::new(), "x".into(), None));
        let id = a.id();
        r.register(a).unwrap();
        assert!(r.get(id).is_some());
        assert!(r.get("not-registered").is_none());
    }

    #[test]
    fn list_for_mode_filters_by_ceiling() {
        let mut r = TechniqueRegistry::new();
        let reach = Arc::new(TheoreticalReachability::new(Vec::new(), "x".into(), None));
        let passive = Arc::new(PassiveCveMatch::new(std::collections::HashMap::new()));
        r.register(reach).unwrap();
        r.register(passive).unwrap();

        // Theoretical ceiling: only the Theoretical technique fits.
        let only_t = r.list_for_mode(AttackMode::Theoretical);
        assert_eq!(only_t.len(), 1);
        assert_eq!(only_t[0].max_mode(), AttackMode::Theoretical);

        // PassiveValidation ceiling: both fit.
        let both = r.list_for_mode(AttackMode::PassiveValidation);
        assert_eq!(both.len(), 2);
    }
}
