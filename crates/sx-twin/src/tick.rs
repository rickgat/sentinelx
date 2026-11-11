//! The deterministic tick state machine.
//!
//! [`advance`] walks the edges out of every currently-compromised node and,
//! for each one, rolls the supplied RNG against `edge.exploit_probability`.
//! On success the target is moved to [`CompromiseState::Compromised`] and a
//! [`Event::Compromised`] is emitted. Any node that was forcibly contained
//! between ticks emits an [`Event::Contained`] on the next call so observers
//! can stitch a complete timeline.
//!
//! # Determinism contract
//!
//! For a given (twin shape, edge insertion order, RNG seed) the output of
//! [`advance`] is bit-identical across runs and platforms. Concretely:
//!
//! 1. Iteration order over the seed set is computed at tick start by
//!    sorting the snapshot — `HashSet` iteration order is not stable, so
//!    we materialise into a `Vec` and sort by `AssetId`.
//! 2. Edges are scanned in insertion order (`Vec` order).
//! 3. The RNG is consumed in the order `(seed, edge_index)` — every edge
//!    out of every compromised seed consumes exactly one `f64` from the
//!    RNG, even when the target is contained, so the stream is stable
//!    against late changes to the contained set.
//!
//! # Cycle safety
//!
//! Newly-compromised nodes do **not** propagate in the same tick — they
//! enter the seed set for the next call. A cycle therefore takes one tick
//! per hop; it cannot loop forever.

use std::collections::HashSet;

use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::state::{AssetId, CompromiseState};
use crate::twin::Twin;

/// Observable outcome of a single tick.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Event {
    /// An asset was newly compromised during this tick by propagation from
    /// `source` across an edge with the recorded `probability`.
    Compromised {
        /// Asset that just transitioned to `Compromised`.
        target: AssetId,
        /// Asset that drove the propagation.
        source: AssetId,
        /// Edge probability that succeeded (post-clamp).
        probability: f64,
    },
    /// An asset that was compromised at the start of the tick is reported
    /// as contained because its state was forcibly set to
    /// [`CompromiseState::Contained`] (via [`Twin::mark_contained`])
    /// between ticks.
    Contained {
        /// Asset that is now contained.
        target: AssetId,
    },
}

/// Advance the twin by one tick.
///
/// See the module-level documentation for the determinism and cycle-safety
/// contracts. The event vector is sorted so that all [`Event::Contained`]
/// events precede [`Event::Compromised`] events, and within each group the
/// order is the deterministic processing order described above.
pub fn advance<R: Rng + ?Sized>(twin: &mut Twin, rng: &mut R) -> Vec<Event> {
    // Snapshot seeds at tick start. We sort to remove HashSet iteration
    // non-determinism from the public output and from the RNG consumption
    // pattern.
    let mut seeds: Vec<AssetId> = twin.compromised.iter().copied().collect();
    seeds.sort();

    // Any seed that is no longer marked Compromised in the asset map was
    // contained out-of-band between ticks — surface that as a Contained
    // event and drop it from the propagation roll. We also clean up the
    // compromised set so the next tick has a consistent view.
    let mut contained_events: Vec<Event> = Vec::new();
    let mut active_seeds: Vec<AssetId> = Vec::with_capacity(seeds.len());
    for seed in seeds {
        let state = twin
            .assets
            .get(&seed)
            .map_or(CompromiseState::Healthy, |a| a.compromise_state);
        if state.can_originate_propagation() {
            active_seeds.push(seed);
        } else {
            // The asset is no longer a propagation source. Emit a
            // Contained event only if it was explicitly contained — not if
            // it was simply removed from the asset map (which is also an
            // invariant violation, but we degrade gracefully).
            if matches!(state, CompromiseState::Contained) {
                contained_events.push(Event::Contained { target: seed });
            }
            let _ = twin.compromised.remove(&seed);
        }
    }

    // Track newly compromised nodes so they don't propagate in this tick
    // (avoids infinite loops on cycles) and so we only emit one event per
    // target per tick.
    let mut newly_compromised: HashSet<AssetId> = HashSet::new();
    let mut compromise_events: Vec<Event> = Vec::new();

    // Edges are iterated in insertion order. For determinism every
    // (seed, edge) pair consumes exactly one RNG sample regardless of
    // whether propagation can succeed.
    for seed in &active_seeds {
        for edge in &twin.edges {
            if edge.from != *seed {
                continue;
            }

            // One f64 draw per edge regardless of outcome — keeps the RNG
            // stream stable under target-state changes.
            let roll: f64 = rng.gen_range(0.0..1.0);

            // Skip if the target was already compromised this tick — we
            // still consumed the draw above to keep determinism.
            if newly_compromised.contains(&edge.to) {
                continue;
            }

            let target_state = match twin.assets.get(&edge.to) {
                Some(a) => a.compromise_state,
                None => continue, // dangling edge — defensive; add_edge prevents this
            };

            if !target_state.is_propagation_target() {
                continue;
            }

            if roll < edge.exploit_probability {
                let _ = newly_compromised.insert(edge.to);
                compromise_events.push(Event::Compromised {
                    target: edge.to,
                    source: *seed,
                    probability: edge.exploit_probability,
                });
            }
        }
    }

    // Apply mutations after the read-only walk so the borrow checker is
    // happy and so within-tick visibility is consistent.
    for ev in &compromise_events {
        if let Event::Compromised { target, .. } = ev {
            if let Some(asset) = twin.assets.get_mut(target) {
                asset.compromise_state = CompromiseState::Compromised;
            }
            let _ = twin.compromised.insert(*target);
        }
    }

    // Stable ordering: Contained first (state lost), then Compromised.
    let mut out = Vec::with_capacity(contained_events.len() + compromise_events.len());
    out.append(&mut contained_events);
    out.append(&mut compromise_events);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::float_cmp)]
mod tests {
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use super::{advance, Event};
    use crate::state::{AssetId, AssetKind, AssetState};
    use crate::twin::{Edge, Twin};

    fn host(score: f64) -> AssetState {
        AssetState::new(AssetId::new(), AssetKind::Host, score)
    }

    #[test]
    fn empty_twin_emits_no_events() {
        let mut twin = Twin::new();
        let mut rng = StdRng::seed_from_u64(0);
        let events = advance(&mut twin, &mut rng);
        assert!(events.is_empty());
    }

    #[test]
    fn high_probability_edge_propagates() {
        let mut twin = Twin::new();
        let a = host(0.5);
        let b = host(0.5);
        let id_a = a.id;
        let id_b = b.id;
        twin.add_asset(a).unwrap();
        twin.add_asset(b).unwrap();
        twin.add_edge(Edge::new(id_a, id_b, 1.0)).unwrap();
        twin.mark_compromised(id_a).unwrap();

        let mut rng = StdRng::seed_from_u64(1);
        let events = advance(&mut twin, &mut rng);
        assert!(twin.is_compromised(id_b));
        assert!(matches!(
            events.as_slice(),
            [Event::Compromised { target, source, .. }] if *target == id_b && *source == id_a
        ));
    }
}
