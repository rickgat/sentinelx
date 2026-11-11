//! Property-based tests for the digital-twin tick state machine.
//!
//! These cover the invariants stated in `src/tick.rs`:
//!
//! 1. **Determinism** — same `(twin shape, edge order, RNG seed)` produces
//!    identical `Vec<Event>` across two independent runs of two
//!    consecutive advances.
//! 2. **Containment** — when every node is `Contained`, no `Compromised`
//!    event is ever emitted, regardless of the graph or seed.
//! 3. **Lower bound on `exploit_probability`** — at `p = 0.0`, propagation
//!    never succeeds, no matter how many ticks run.
//! 4. **Upper bound on `exploit_probability`** — at `p = 1.0`, every
//!    edge whose target is a valid propagation target *always* succeeds
//!    on the first tick.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::float_cmp,
    clippy::needless_range_loop,
    clippy::items_after_statements
)]

use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

use sx_twin::state::{AssetId, AssetKind, AssetState, CompromiseState};
use sx_twin::tick::{advance, Event};
use sx_twin::twin::{Edge, Twin};

/// Build a deterministic mesh of `n` assets with fixed UUIDs and a random
/// set of forward edges. Returns the twin and the list of ids in insertion
/// order so callers can mark specific nodes compromised / contained.
fn build_mesh(n: usize, edges: &[(usize, usize, f64)]) -> (Twin, Vec<AssetId>) {
    let mut twin = Twin::new();
    let mut ids = Vec::with_capacity(n);
    for i in 0..n {
        let id = AssetId::from_uuid(uuid::Uuid::from_u128((i as u128) + 1));
        ids.push(id);
        twin.add_asset(AssetState::new(id, AssetKind::Host, 0.1))
            .unwrap();
    }
    for &(from, to, p) in edges {
        if from < n && to < n && from != to {
            twin.add_edge(Edge::new(ids[from], ids[to], p)).unwrap();
        }
    }
    (twin, ids)
}

/// Strategy: a small mesh size + a list of edges + a u64 seed.
fn mesh_strategy() -> impl Strategy<
    Value = (
        usize,                    // node count
        Vec<(usize, usize, f64)>, // edges
        u64,                      // seed
    ),
> {
    (2usize..6).prop_flat_map(|n| {
        (
            Just(n),
            prop::collection::vec((0..n, 0..n, 0.0f64..=1.0f64), 0..(n * 2)),
            any::<u64>(),
        )
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Same seed + same twin shape → bit-identical event sequence across
    /// two consecutive advances.
    #[test]
    fn same_seed_produces_identical_event_sequences(
        (n, edges, seed) in mesh_strategy(),
        compromised_seed_idx in 0usize..6,
    ) {
        let (mut twin_a, ids_a) = build_mesh(n, &edges);
        let (mut twin_b, ids_b) = build_mesh(n, &edges);
        // Mark the same node compromised in both twins.
        let idx = compromised_seed_idx % n;
        twin_a.mark_compromised(ids_a[idx]).unwrap();
        twin_b.mark_compromised(ids_b[idx]).unwrap();

        let mut rng_a = StdRng::seed_from_u64(seed);
        let mut rng_b = StdRng::seed_from_u64(seed);

        let ev_a1 = advance(&mut twin_a, &mut rng_a);
        let ev_b1 = advance(&mut twin_b, &mut rng_b);
        prop_assert_eq!(&ev_a1, &ev_b1);

        let ev_a2 = advance(&mut twin_a, &mut rng_a);
        let ev_b2 = advance(&mut twin_b, &mut rng_b);
        prop_assert_eq!(&ev_a2, &ev_b2);
    }

    /// When every node is `Contained`, no `Compromised` event ever fires.
    #[test]
    fn fully_contained_set_produces_zero_compromised_events(
        (n, edges, seed) in mesh_strategy(),
    ) {
        let (mut twin, ids) = build_mesh(n, &edges);
        for id in &ids {
            twin.mark_contained(*id).unwrap();
        }
        let mut rng = StdRng::seed_from_u64(seed);
        let events1 = advance(&mut twin, &mut rng);
        let events2 = advance(&mut twin, &mut rng);
        for ev in events1.iter().chain(events2.iter()) {
            prop_assert!(
                !matches!(ev, Event::Compromised { .. }),
                "got a Compromised event from a fully-contained graph: {ev:?}"
            );
        }
        // And no asset should ever flip back to Compromised.
        for id in &ids {
            prop_assert_eq!(
                twin.asset(*id).unwrap().compromise_state,
                CompromiseState::Contained
            );
        }
    }

    /// `exploit_probability = 0.0` never propagates, across many seeds.
    #[test]
    fn zero_probability_never_propagates(
        n in 2usize..5,
        seeds in prop::collection::vec(any::<u64>(), 1..8),
    ) {
        // Build a complete forward graph at p=0.0.
        let mut edges = Vec::new();
        for i in 0..n {
            for j in 0..n {
                if i != j {
                    edges.push((i, j, 0.0_f64));
                }
            }
        }
        let (mut twin, ids) = build_mesh(n, &edges);
        twin.mark_compromised(ids[0]).unwrap();

        for seed in seeds {
            let mut rng = StdRng::seed_from_u64(seed);
            let events = advance(&mut twin, &mut rng);
            let compromise_events = events
                .iter()
                .filter(|e| matches!(e, Event::Compromised { .. }))
                .count();
            prop_assert_eq!(compromise_events, 0);
        }
        // Only the originally-compromised seed remains compromised.
        prop_assert!(twin.is_compromised(ids[0]));
        for id in &ids[1..] {
            prop_assert!(!twin.is_compromised(*id));
        }
    }

    /// `exploit_probability = 1.0` always propagates to every non-`Contained`
    /// neighbour of a compromised seed in a single tick.
    #[test]
    fn one_probability_always_propagates_to_non_contained(
        n in 2usize..6,
        seed in any::<u64>(),
        contain_mask in any::<u64>(),
    ) {
        // Build a star: node 0 → node i for all i in [1, n).
        let edges: Vec<(usize, usize, f64)> = (1..n).map(|i| (0, i, 1.0_f64)).collect();
        let (mut twin, ids) = build_mesh(n, &edges);
        twin.mark_compromised(ids[0]).unwrap();

        // Optionally contain a subset of leaf nodes.
        let mut contained: Vec<usize> = Vec::new();
        for i in 1..n {
            if (contain_mask >> i) & 1 == 1 {
                twin.mark_contained(ids[i]).unwrap();
                contained.push(i);
            }
        }

        let mut rng = StdRng::seed_from_u64(seed);
        let _events = advance(&mut twin, &mut rng);

        for i in 1..n {
            if contained.contains(&i) {
                prop_assert!(
                    !twin.is_compromised(ids[i]),
                    "contained leaf {i} was compromised"
                );
            } else {
                prop_assert!(
                    twin.is_compromised(ids[i]),
                    "non-contained leaf {i} was NOT compromised under p=1.0"
                );
            }
        }
    }
}
