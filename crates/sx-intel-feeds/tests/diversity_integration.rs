//! Integration tests for HIGH-011 — threat-intel feed-source diversity
//! enforcement.
//!
//! Pins down the three acceptance-criteria scenarios from
//! `docs/SPRINT_HARDENING_HANDOFF.md` §3 Sprint 4 / HIGH-011:
//!
//! 1. Single-source = low fused confidence (and gated out by default).
//! 2. 3-of-3 same commercial vendor = saturated but NOT 1.0 (correlated
//!    evidence damped; gated out for diversity).
//! 3. 1-commercial + 1-OSS + 1-ISAC = highest fused score (three
//!    independent families; passes the default gate).

#![allow(
    clippy::unwrap_used,
    clippy::float_cmp,
    clippy::expect_used,
    clippy::panic
)]

use sx_intel_feeds::{
    DiversityConfig, DiversityMatcher, FeedFamily, FeedSource, MatchOutcome, Project, Sector,
    Vendor,
};

/// Scenario 1: single feed match — confidence equals the raw prior,
/// `independent_sources == 1`, default gate suppresses.
#[test]
fn diversity_single_source_low_confidence_and_suppressed_by_default() {
    let matcher = DiversityMatcher::new(DiversityConfig::default());
    let sources = vec![FeedSource::new(
        "mandiant",
        FeedFamily::Commercial(Vendor::Mandiant),
        0.7,
    )];

    let outcome = matcher.evaluate(&sources);
    match outcome {
        MatchOutcome::Suppress(conf) => {
            assert_eq!(conf.independent_sources, 1);
            assert!(
                (conf.fused - 0.7).abs() < 1e-6,
                "single-source fused must equal raw prior, got {}",
                conf.fused
            );
        }
        other => panic!("expected Suppress for single-source case, got {other:?}"),
    }
}

/// Scenario 2: three feeds from the SAME commercial vendor — fused
/// score saturates above the strongest single prior but stays well
/// below 1.0 (correlated evidence is damped), and the diversity gate
/// at the default threshold suppresses because there is only ONE
/// distinct family bucket.
#[test]
fn diversity_three_of_three_same_commercial_vendor_saturated_not_one() {
    let sources = vec![
        FeedSource::new("mandiant-a", FeedFamily::Commercial(Vendor::Mandiant), 0.7),
        FeedSource::new("mandiant-b", FeedFamily::Commercial(Vendor::Mandiant), 0.7),
        FeedSource::new("mandiant-c", FeedFamily::Commercial(Vendor::Mandiant), 0.7),
    ];

    // Fuse-only check (no gate): saturation behaviour.
    let matcher_no_gate = DiversityMatcher::new(DiversityConfig::with_minimum(1));
    let conf = matcher_no_gate.fuse(&sources).expect("non-empty");
    assert!(
        conf.fused > 0.7,
        "3 same-vendor feeds must exceed single-feed prior, got {}",
        conf.fused
    );
    assert!(
        conf.fused < 0.95,
        "3 same-vendor feeds MUST NOT saturate to ~1.0, got {}",
        conf.fused
    );
    assert_eq!(
        conf.independent_sources, 1,
        "same family = one independent bucket"
    );

    // Default gate (min=2) must suppress this case.
    let matcher_default = DiversityMatcher::new(DiversityConfig::default());
    match matcher_default.evaluate(&sources) {
        MatchOutcome::Suppress(_) => {}
        other => panic!(
            "default diversity gate must suppress 3-of-3-same-vendor (no diversity), got {other:?}"
        ),
    }
}

/// Scenario 3: one commercial + one OSS + one ISAC. Three independent
/// families ⇒ no damping ⇒ highest fused score; passes the default
/// gate.
#[test]
fn diversity_three_distinct_families_yields_highest_fused_score() {
    let mixed = vec![
        FeedSource::new("mandiant", FeedFamily::Commercial(Vendor::Mandiant), 0.7),
        FeedSource::new("abuse-ch", FeedFamily::Oss(Project::AbuseCh), 0.7),
        FeedSource::new("fs-isac", FeedFamily::Isac(Sector::Financial), 0.7),
    ];
    let same_vendor = vec![
        FeedSource::new("mandiant-a", FeedFamily::Commercial(Vendor::Mandiant), 0.7),
        FeedSource::new("mandiant-b", FeedFamily::Commercial(Vendor::Mandiant), 0.7),
        FeedSource::new("mandiant-c", FeedFamily::Commercial(Vendor::Mandiant), 0.7),
    ];

    let matcher = DiversityMatcher::new(DiversityConfig::default());
    let conf_mixed = matcher.fuse(&mixed).expect("non-empty");
    let conf_same = matcher.fuse(&same_vendor).expect("non-empty");

    assert!(
        conf_mixed.fused > conf_same.fused,
        "diverse-family fusion ({}) must exceed same-family fusion ({})",
        conf_mixed.fused,
        conf_same.fused
    );
    assert_eq!(conf_mixed.independent_sources, 3);

    // Mixed-family must pass default gate.
    match matcher.evaluate(&mixed) {
        MatchOutcome::Emit(conf) => assert_eq!(conf.independent_sources, 3),
        other => panic!("expected Emit for 3-family case, got {other:?}"),
    }
}

/// Additional sanity test: the gate emits only when
/// `independent_sources >= min_independent_sources`. Two distinct
/// families at default min=2 must emit; same two at a tenant-raised
/// min=3 must suppress.
#[test]
fn diversity_gate_respects_tenant_min_threshold() {
    let sources = vec![
        FeedSource::new(
            "crowdstrike",
            FeedFamily::Commercial(Vendor::CrowdStrike),
            0.85,
        ),
        FeedSource::new("abuse-ch", FeedFamily::Oss(Project::AbuseCh), 0.6),
    ];

    let default_matcher = DiversityMatcher::new(DiversityConfig::default());
    match default_matcher.evaluate(&sources) {
        MatchOutcome::Emit(conf) => assert_eq!(conf.independent_sources, 2),
        other => panic!("expected Emit at default min=2, got {other:?}"),
    }

    let strict_matcher = DiversityMatcher::new(DiversityConfig::with_minimum(3));
    match strict_matcher.evaluate(&sources) {
        MatchOutcome::Suppress(conf) => assert_eq!(conf.independent_sources, 2),
        other => panic!("expected Suppress at min=3 with 2 families, got {other:?}"),
    }
}
