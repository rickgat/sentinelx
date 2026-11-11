//! Per-asset state held inside the digital twin.
//!
//! The twin is intentionally a **self-contained** model: it does not depend
//! on `sx-core` or `sx-graph` so the simulator stays loosely coupled and
//! easy to test. A future integration layer can translate between the
//! production [`sx_core::entity::Asset`] type and the twin's [`AssetState`].
//!
//! All identifiers are UUIDv4 — generated locally so simulations can be
//! constructed from scratch in tests without touching a database.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Newtype wrapper around a UUID identifying an asset inside the twin.
///
/// Equality is structural — the same id refers to the same node across
/// twins, but the twin makes no claim that two twins share asset ids unless
/// the caller arranges that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AssetId(Uuid);

impl AssetId {
    /// Generate a fresh, random asset id (UUIDv4).
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Wrap an existing UUID as an [`AssetId`].
    #[must_use]
    pub const fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    /// Borrow the underlying UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for AssetId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AssetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Coarse-grained kind of an asset, used for telemetry and for biasing
/// future propagation models. The twin itself does not branch on kind in
/// the current tick algorithm — it is recorded for observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AssetKind {
    /// Server, workstation, or virtual machine.
    Host,
    /// Network appliance (router, switch, firewall).
    Network,
    /// Identity principal (user, service account).
    Identity,
    /// Application or service.
    Application,
    /// Data store (database, bucket, share).
    Data,
    /// Anything not covered by a more specific variant.
    Other,
}

/// Where on the kill chain a given asset sits inside the twin.
///
/// Transitions are driven exclusively by [`crate::tick::advance`]; callers
/// can also force a state via [`crate::twin::Twin::mark_compromised`] or
/// [`crate::twin::Twin::mark_contained`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum CompromiseState {
    /// No signal of compromise.
    Healthy,
    /// Indicators of compromise observed but not confirmed.
    Suspected,
    /// Confirmed under adversary control — will spread on the next tick.
    Compromised,
    /// Isolated by a control: cannot spread, cannot be re-compromised.
    Contained,
}

impl CompromiseState {
    /// Returns `true` if propagation may originate from this node.
    #[must_use]
    pub const fn can_originate_propagation(self) -> bool {
        matches!(self, Self::Compromised)
    }

    /// Returns `true` if this node is eligible to be compromised by an
    /// inbound propagation attempt. `Contained` nodes are immune.
    #[must_use]
    pub const fn is_propagation_target(self) -> bool {
        matches!(self, Self::Healthy | Self::Suspected)
    }
}

/// In-memory state of a single asset inside the twin.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetState {
    /// Stable identifier for the asset.
    pub id: AssetId,
    /// Coarse asset kind, for observability.
    pub kind: AssetKind,
    /// Risk score in `[0.0, 1.0]`. The constructor clamps the input to
    /// guarantee the invariant; out-of-band mutation through the public
    /// field is permitted but not recommended.
    pub risk_score: f64,
    /// Current compromise state.
    pub compromise_state: CompromiseState,
}

impl AssetState {
    /// Build a fresh asset in [`CompromiseState::Healthy`] with the given
    /// metadata. `risk_score` is clamped to `[0.0, 1.0]`; `NaN` is mapped
    /// to `0.0` so propagation arithmetic never produces `NaN`.
    #[must_use]
    pub fn new(id: AssetId, kind: AssetKind, risk_score: f64) -> Self {
        Self {
            id,
            kind,
            risk_score: clamp_unit(risk_score),
            compromise_state: CompromiseState::Healthy,
        }
    }
}

/// Clamp `x` into `[0.0, 1.0]`. `NaN` collapses to `0.0` (so downstream
/// probability arithmetic never produces `NaN`).
#[allow(clippy::missing_const_for_fn)] // `f64::clamp` is not const-stable on 1.88.
pub(crate) fn clamp_unit(x: f64) -> f64 {
    if x.is_nan() {
        0.0
    } else {
        x.clamp(0.0, 1.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod tests {
    use super::{clamp_unit, AssetId, AssetKind, AssetState, CompromiseState};

    #[test]
    fn asset_id_round_trip_uuid() {
        let id = AssetId::new();
        let same = AssetId::from_uuid(*id.as_uuid());
        assert_eq!(id, same);
    }

    #[test]
    fn asset_id_display_matches_uuid() {
        let id = AssetId::new();
        assert_eq!(id.to_string(), id.as_uuid().to_string());
    }

    #[test]
    fn new_clamps_risk_score() {
        let a = AssetState::new(AssetId::new(), AssetKind::Host, -0.5);
        assert_eq!(a.risk_score, 0.0);

        let b = AssetState::new(AssetId::new(), AssetKind::Host, 1.5);
        assert_eq!(b.risk_score, 1.0);

        let c = AssetState::new(AssetId::new(), AssetKind::Host, f64::NAN);
        assert_eq!(c.risk_score, 0.0);
    }

    #[test]
    fn new_defaults_to_healthy() {
        let a = AssetState::new(AssetId::new(), AssetKind::Data, 0.5);
        assert_eq!(a.compromise_state, CompromiseState::Healthy);
    }

    #[test]
    fn clamp_unit_passes_through_in_range() {
        assert_eq!(clamp_unit(0.42), 0.42);
        assert_eq!(clamp_unit(0.0), 0.0);
        assert_eq!(clamp_unit(1.0), 1.0);
    }

    #[test]
    fn compromise_state_predicates() {
        assert!(CompromiseState::Compromised.can_originate_propagation());
        assert!(!CompromiseState::Healthy.can_originate_propagation());
        assert!(!CompromiseState::Contained.can_originate_propagation());

        assert!(CompromiseState::Healthy.is_propagation_target());
        assert!(CompromiseState::Suspected.is_propagation_target());
        assert!(!CompromiseState::Compromised.is_propagation_target());
        assert!(!CompromiseState::Contained.is_propagation_target());
    }
}
