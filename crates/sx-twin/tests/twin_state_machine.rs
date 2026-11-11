//! Integration tests for the `sx-twin` state machine.
//!
//! These cover the contract requirements: round-trips, deterministic RNG,
//! containment blocking, cycle safety, and stable event ordering.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::float_cmp,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::inconsistent_digit_grouping,
    clippy::unreadable_literal,
    clippy::unusual_byte_groupings
)]

use rand::rngs::StdRng;
use rand::SeedableRng;

use sx_twin::state::{AssetId, AssetKind, AssetState, CompromiseState};
use sx_twin::tick::{advance, Event};
use sx_twin::twin::{Edge, Twin};

fn host(score: f64) -> AssetState {
    AssetState::new(AssetId::new(), AssetKind::Host, score)
}

#[test]
fn add_asset_and_edge_round_trip() {
    let mut twin = Twin::new();
    let a = host(0.2);
    let b = host(0.3);
    let id_a = a.id;
    let id_b = b.id;

    twin.add_asset(a).unwrap();
    twin.add_asset(b).unwrap();
    twin.add_edge(Edge::new(id_a, id_b, 0.75)).unwrap();

    assert_eq!(twin.asset_count(), 2);
    assert_eq!(twin.edge_count(), 1);
    assert_eq!(twin.asset(id_a).unwrap().risk_score, 0.2);
    assert_eq!(twin.asset(id_b).unwrap().risk_score, 0.3);
    assert_eq!(twin.edges[0].exploit_probability, 0.75);
}

#[test]
fn mark_compromised_flags_state_and_set() {
    let mut twin = Twin::new();
    let a = host(0.1);
    let id_a = a.id;
    twin.add_asset(a).unwrap();

    assert!(!twin.is_compromised(id_a));
    twin.mark_compromised(id_a).unwrap();

    assert!(twin.is_compromised(id_a));
    assert_eq!(
        twin.asset(id_a).unwrap().compromise_state,
        CompromiseState::Compromised
    );
}

#[test]
fn advance_propagates_along_high_probability_edge() {
    let mut twin = Twin::new();
    let a = host(0.5);
    let b = host(0.5);
    let id_a = a.id;
    let id_b = b.id;
    twin.add_asset(a).unwrap();
    twin.add_asset(b).unwrap();
    twin.add_edge(Edge::new(id_a, id_b, 1.0)).unwrap();
    twin.mark_compromised(id_a).unwrap();

    let mut rng = StdRng::seed_from_u64(7);
    let events = advance(&mut twin, &mut rng);

    assert!(twin.is_compromised(id_b));
    assert_eq!(events.len(), 1);
    match &events[0] {
        Event::Compromised {
            target,
            source,
            probability,
        } => {
            assert_eq!(*target, id_b);
            assert_eq!(*source, id_a);
            assert_eq!(*probability, 1.0);
        }
        other => panic!("expected Compromised event, got {other:?}"),
    }
}

#[test]
fn advance_leaves_healthy_nodes_alone_when_no_path_to_compromised() {
    let mut twin = Twin::new();
    let a = host(0.5);
    let b = host(0.5);
    let c = host(0.5);
    let id_a = a.id;
    let id_b = b.id;
    let id_c = c.id;
    twin.add_asset(a).unwrap();
    twin.add_asset(b).unwrap();
    twin.add_asset(c).unwrap();
    // a -> b only. c is isolated.
    twin.add_edge(Edge::new(id_a, id_b, 1.0)).unwrap();
    twin.mark_compromised(id_a).unwrap();

    let mut rng = StdRng::seed_from_u64(11);
    let _events = advance(&mut twin, &mut rng);

    assert!(twin.is_compromised(id_a));
    assert!(twin.is_compromised(id_b));
    assert!(!twin.is_compromised(id_c));
    assert_eq!(
        twin.asset(id_c).unwrap().compromise_state,
        CompromiseState::Healthy
    );
}

#[test]
fn advance_is_deterministic_under_same_seed() {
    // Build two identical twins with identical (fixed) asset ids so we can
    // assert event-list equality byte-for-byte.
    fn build(id_a: AssetId, id_b: AssetId, id_c: AssetId) -> Twin {
        let mut twin = Twin::new();
        twin.add_asset(AssetState::new(id_a, AssetKind::Host, 0.4))
            .unwrap();
        twin.add_asset(AssetState::new(id_b, AssetKind::Host, 0.4))
            .unwrap();
        twin.add_asset(AssetState::new(id_c, AssetKind::Host, 0.4))
            .unwrap();
        twin.add_edge(Edge::new(id_a, id_b, 0.5)).unwrap();
        twin.add_edge(Edge::new(id_a, id_c, 0.5)).unwrap();
        twin.mark_compromised(id_a).unwrap();
        twin
    }

    let id_a = AssetId::from_uuid(uuid::Uuid::from_u128(0xA));
    let id_b = AssetId::from_uuid(uuid::Uuid::from_u128(0xB));
    let id_c = AssetId::from_uuid(uuid::Uuid::from_u128(0xC));

    let mut twin1 = build(id_a, id_b, id_c);
    let mut twin2 = build(id_a, id_b, id_c);

    let mut rng1 = StdRng::seed_from_u64(20260530);
    let mut rng2 = StdRng::seed_from_u64(20260530);

    let events1 = advance(&mut twin1, &mut rng1);
    let events2 = advance(&mut twin2, &mut rng2);

    assert_eq!(events1, events2);
    assert_eq!(twin1.compromised, twin2.compromised);
}

#[test]
fn contained_state_blocks_further_propagation() {
    let mut twin = Twin::new();
    let a = host(0.5);
    let b = host(0.5);
    let id_a = a.id;
    let id_b = b.id;
    twin.add_asset(a).unwrap();
    twin.add_asset(b).unwrap();
    twin.add_edge(Edge::new(id_a, id_b, 1.0)).unwrap();
    twin.mark_compromised(id_a).unwrap();
    twin.mark_contained(id_b).unwrap();

    let mut rng = StdRng::seed_from_u64(3);
    let events = advance(&mut twin, &mut rng);

    // b is Contained and must NOT be compromised even though probability is 1.0.
    assert!(!twin.is_compromised(id_b));
    assert_eq!(
        twin.asset(id_b).unwrap().compromise_state,
        CompromiseState::Contained
    );
    assert!(events.is_empty());
}

#[test]
fn containing_a_seed_emits_contained_event_and_stops_propagation() {
    let mut twin = Twin::new();
    let a = host(0.5);
    let b = host(0.5);
    let id_a = a.id;
    let id_b = b.id;
    twin.add_asset(a).unwrap();
    twin.add_asset(b).unwrap();
    twin.add_edge(Edge::new(id_a, id_b, 1.0)).unwrap();
    twin.mark_compromised(id_a).unwrap();
    // Force the seed into the compromised set, then contain it before the tick.
    twin.mark_contained(id_a).unwrap();
    // Re-insert into the compromised set to simulate an out-of-band hand-off
    // between subsystems. The tick should see the Contained state on the
    // asset and emit a Contained event for it.
    twin.compromised.insert(id_a);

    let mut rng = StdRng::seed_from_u64(5);
    let events = advance(&mut twin, &mut rng);

    assert!(!twin.is_compromised(id_b));
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], Event::Contained { target } if target == id_a));
}

#[test]
fn cycle_in_graph_does_not_infinite_loop() {
    let mut twin = Twin::new();
    let a = host(0.5);
    let b = host(0.5);
    let c = host(0.5);
    let id_a = a.id;
    let id_b = b.id;
    let id_c = c.id;
    twin.add_asset(a).unwrap();
    twin.add_asset(b).unwrap();
    twin.add_asset(c).unwrap();
    // a -> b -> c -> a, all 1.0
    twin.add_edge(Edge::new(id_a, id_b, 1.0)).unwrap();
    twin.add_edge(Edge::new(id_b, id_c, 1.0)).unwrap();
    twin.add_edge(Edge::new(id_c, id_a, 1.0)).unwrap();
    twin.mark_compromised(id_a).unwrap();

    let mut rng = StdRng::seed_from_u64(17);
    // Tick 1: a propagates to b only (c is not yet a seed).
    let ev1 = advance(&mut twin, &mut rng);
    assert!(twin.is_compromised(id_b));
    assert!(!twin.is_compromised(id_c));
    assert_eq!(ev1.len(), 1);

    // Tick 2: a and b are seeds; c gets compromised. a is already compromised
    // (target check rejects), b -> c succeeds.
    let ev2 = advance(&mut twin, &mut rng);
    assert!(twin.is_compromised(id_c));
    assert_eq!(ev2.len(), 1);

    // Tick 3: all three are compromised — no new events, no infinite loop.
    let ev3 = advance(&mut twin, &mut rng);
    assert!(ev3.is_empty());
}

#[test]
fn event_list_ordering_is_stable() {
    // Sort by AssetId to drive deterministic order. We use fixed UUIDs.
    let id1 = AssetId::from_uuid(uuid::Uuid::from_u128(
        0x0000_0000_0000_0000_0000_0000_0000_0001,
    ));
    let id2 = AssetId::from_uuid(uuid::Uuid::from_u128(
        0x0000_0000_0000_0000_0000_0000_0000_0002,
    ));
    let id3 = AssetId::from_uuid(uuid::Uuid::from_u128(
        0x0000_0000_0000_0000_0000_0000_0000_0003,
    ));
    let id4 = AssetId::from_uuid(uuid::Uuid::from_u128(
        0x0000_0000_0000_0000_0000_0000_0000_0004,
    ));

    let mut twin = Twin::new();
    twin.add_asset(AssetState::new(id1, AssetKind::Host, 0.0))
        .unwrap();
    twin.add_asset(AssetState::new(id2, AssetKind::Host, 0.0))
        .unwrap();
    twin.add_asset(AssetState::new(id3, AssetKind::Host, 0.0))
        .unwrap();
    twin.add_asset(AssetState::new(id4, AssetKind::Host, 0.0))
        .unwrap();
    // id1 -> id3 and id1 -> id4, both 1.0. Insertion order id3 before id4.
    twin.add_edge(Edge::new(id1, id3, 1.0)).unwrap();
    twin.add_edge(Edge::new(id1, id4, 1.0)).unwrap();
    twin.mark_compromised(id1).unwrap();
    twin.mark_compromised(id2).unwrap(); // isolated seed, no edges

    let mut rng = StdRng::seed_from_u64(99);
    let events = advance(&mut twin, &mut rng);

    // Two Compromised events, in edge insertion order (id3 before id4).
    assert_eq!(events.len(), 2);
    match (&events[0], &events[1]) {
        (Event::Compromised { target: t1, .. }, Event::Compromised { target: t2, .. }) => {
            assert_eq!(*t1, id3);
            assert_eq!(*t2, id4);
        }
        other => panic!("unexpected event sequence: {other:?}"),
    }
}

#[test]
fn zero_probability_edge_never_propagates() {
    let mut twin = Twin::new();
    let a = host(0.5);
    let b = host(0.5);
    let id_a = a.id;
    let id_b = b.id;
    twin.add_asset(a).unwrap();
    twin.add_asset(b).unwrap();
    twin.add_edge(Edge::new(id_a, id_b, 0.0)).unwrap();
    twin.mark_compromised(id_a).unwrap();

    for seed in 0..10u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let events = advance(&mut twin, &mut rng);
        assert!(events.is_empty(), "seed {seed} produced events");
    }
    assert!(!twin.is_compromised(id_b));
}

#[test]
fn already_compromised_target_does_not_re_emit() {
    let mut twin = Twin::new();
    let a = host(0.5);
    let b = host(0.5);
    let id_a = a.id;
    let id_b = b.id;
    twin.add_asset(a).unwrap();
    twin.add_asset(b).unwrap();
    twin.add_edge(Edge::new(id_a, id_b, 1.0)).unwrap();
    twin.mark_compromised(id_a).unwrap();
    twin.mark_compromised(id_b).unwrap();

    let mut rng = StdRng::seed_from_u64(123);
    let events = advance(&mut twin, &mut rng);
    assert!(events.is_empty());
}
