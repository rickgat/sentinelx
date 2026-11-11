//! The [`Twin`] container — assets, directed edges, and the compromised set.
//!
//! The data structures here are pure values: no locks, no I/O, no async. The
//! container is owned by whoever drives the simulation (typically a
//! `bas`-side controller) and is mutated only through its API.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::error::TwinError;
use crate::state::{clamp_unit, AssetId, AssetState, CompromiseState};

/// Directed edge between two assets, weighted with the probability that an
/// attacker who controls `from` can successfully pivot to `to` in a single
/// tick.
///
/// `exploit_probability` is clamped into `[0.0, 1.0]` at construction time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Edge {
    /// Source asset (the attacker's current foothold).
    pub from: AssetId,
    /// Destination asset (the pivot target).
    pub to: AssetId,
    /// Probability in `[0.0, 1.0]` that propagation succeeds on a tick.
    pub exploit_probability: f64,
}

impl Edge {
    /// Build an edge, clamping `exploit_probability` into `[0.0, 1.0]`.
    /// `NaN` is mapped to `0.0` so propagation arithmetic never produces
    /// `NaN`.
    #[must_use]
    pub fn new(from: AssetId, to: AssetId, exploit_probability: f64) -> Self {
        Self {
            from,
            to,
            exploit_probability: clamp_unit(exploit_probability),
        }
    }
}

/// In-memory replica of the asset+edge graph plus the set of currently
/// compromised nodes.
///
/// `Twin` is deliberately small: the tick algorithm in [`crate::tick`] does
/// all the work. Mutations go through this type's methods so invariants are
/// preserved (no dangling edge endpoints, no duplicate asset ids, no
/// compromised id without a backing [`AssetState`]).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Twin {
    /// All assets indexed by id.
    pub assets: HashMap<AssetId, AssetState>,
    /// All directed edges. Multiple edges between the same pair are allowed
    /// (different pivot vectors); the tick algorithm considers each
    /// independently.
    pub edges: Vec<Edge>,
    /// Ids of currently-compromised assets, mirrored from the per-asset
    /// `compromise_state` for fast membership tests during a tick.
    pub compromised: HashSet<AssetId>,
}

impl Twin {
    /// Build an empty twin.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an asset. Fails with [`TwinError::Invariant`] if an asset
    /// with the same id is already present.
    pub fn add_asset(&mut self, asset: AssetState) -> Result<(), TwinError> {
        if self.assets.contains_key(&asset.id) {
            return Err(TwinError::invariant(format!(
                "duplicate asset id: {}",
                asset.id
            )));
        }
        if asset.compromise_state.can_originate_propagation() {
            let _ = self.compromised.insert(asset.id);
        }
        let _ = self.assets.insert(asset.id, asset);
        Ok(())
    }

    /// Register a directed edge. Fails with [`TwinError::UnknownAsset`] if
    /// either endpoint has not been added yet.
    pub fn add_edge(&mut self, edge: Edge) -> Result<(), TwinError> {
        if !self.assets.contains_key(&edge.from) {
            return Err(TwinError::UnknownAsset(edge.from));
        }
        if !self.assets.contains_key(&edge.to) {
            return Err(TwinError::UnknownAsset(edge.to));
        }
        self.edges.push(edge);
        Ok(())
    }

    /// Force an asset into [`CompromiseState::Compromised`]. Fails with
    /// [`TwinError::UnknownAsset`] if the id is not registered. A node that
    /// is already [`CompromiseState::Contained`] is **not** demoted — the
    /// call returns `Ok(())` without changing state.
    pub fn mark_compromised(&mut self, id: AssetId) -> Result<(), TwinError> {
        let asset = self
            .assets
            .get_mut(&id)
            .ok_or(TwinError::UnknownAsset(id))?;
        if matches!(asset.compromise_state, CompromiseState::Contained) {
            return Ok(());
        }
        asset.compromise_state = CompromiseState::Compromised;
        let _ = self.compromised.insert(id);
        Ok(())
    }

    /// Force an asset into [`CompromiseState::Contained`]. Fails with
    /// [`TwinError::UnknownAsset`] if the id is not registered. Removes the
    /// asset from the compromised set so it no longer drives propagation.
    pub fn mark_contained(&mut self, id: AssetId) -> Result<(), TwinError> {
        let asset = self
            .assets
            .get_mut(&id)
            .ok_or(TwinError::UnknownAsset(id))?;
        asset.compromise_state = CompromiseState::Contained;
        let _ = self.compromised.remove(&id);
        Ok(())
    }

    /// Returns `true` if the asset id is currently in the compromised set.
    /// Unknown ids return `false` (they cannot be compromised).
    #[must_use]
    pub fn is_compromised(&self, id: AssetId) -> bool {
        self.compromised.contains(&id)
    }

    /// Look up an asset's current state.
    #[must_use]
    pub fn asset(&self, id: AssetId) -> Option<&AssetState> {
        self.assets.get(&id)
    }

    /// Number of registered assets.
    #[must_use]
    pub fn asset_count(&self) -> usize {
        self.assets.len()
    }

    /// Number of registered edges.
    #[must_use]
    pub const fn edge_count(&self) -> usize {
        self.edges.len()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod tests {
    use super::{Edge, Twin};
    use crate::state::{AssetId, AssetKind, AssetState, CompromiseState};

    fn host(score: f64) -> AssetState {
        AssetState::new(AssetId::new(), AssetKind::Host, score)
    }

    #[test]
    fn add_asset_inserts_and_counts() {
        let mut twin = Twin::new();
        let a = host(0.1);
        let id = a.id;
        twin.add_asset(a).unwrap();
        assert_eq!(twin.asset_count(), 1);
        assert!(twin.asset(id).is_some());
    }

    #[test]
    fn add_asset_rejects_duplicate_id() {
        let mut twin = Twin::new();
        let a = host(0.1);
        let id = a.id;
        twin.add_asset(a).unwrap();
        let dup = AssetState::new(id, AssetKind::Host, 0.2);
        let err = twin.add_asset(dup).unwrap_err();
        assert!(matches!(err, crate::TwinError::Invariant(_)));
    }

    #[test]
    fn edge_clamps_probability() {
        let from = AssetId::new();
        let to = AssetId::new();
        assert_eq!(Edge::new(from, to, 1.5).exploit_probability, 1.0);
        assert_eq!(Edge::new(from, to, -0.1).exploit_probability, 0.0);
        assert_eq!(Edge::new(from, to, f64::NAN).exploit_probability, 0.0);
    }

    #[test]
    fn add_edge_requires_known_endpoints() {
        let mut twin = Twin::new();
        let a = host(0.1);
        let id_a = a.id;
        twin.add_asset(a).unwrap();

        let phantom = AssetId::new();
        let err = twin.add_edge(Edge::new(id_a, phantom, 0.5)).unwrap_err();
        assert!(matches!(err, crate::TwinError::UnknownAsset(_)));
    }

    #[test]
    fn mark_compromised_flips_state() {
        let mut twin = Twin::new();
        let a = host(0.1);
        let id = a.id;
        twin.add_asset(a).unwrap();
        assert!(!twin.is_compromised(id));
        twin.mark_compromised(id).unwrap();
        assert!(twin.is_compromised(id));
        assert_eq!(
            twin.asset(id).unwrap().compromise_state,
            CompromiseState::Compromised
        );
    }

    #[test]
    fn mark_compromised_is_noop_on_contained() {
        let mut twin = Twin::new();
        let a = host(0.1);
        let id = a.id;
        twin.add_asset(a).unwrap();
        twin.mark_contained(id).unwrap();
        twin.mark_compromised(id).unwrap();
        assert_eq!(
            twin.asset(id).unwrap().compromise_state,
            CompromiseState::Contained
        );
        assert!(!twin.is_compromised(id));
    }

    #[test]
    fn mark_unknown_asset_errors() {
        let mut twin = Twin::new();
        let ghost = AssetId::new();
        assert!(matches!(
            twin.mark_compromised(ghost).unwrap_err(),
            crate::TwinError::UnknownAsset(_)
        ));
        assert!(matches!(
            twin.mark_contained(ghost).unwrap_err(),
            crate::TwinError::UnknownAsset(_)
        ));
    }
}
