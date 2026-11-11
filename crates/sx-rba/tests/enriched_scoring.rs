// LOW-009: integration tests use `.expect()` for the standard
// "this must succeed or the test fails" pattern, build configs via
// `Default + field reassignment` because the per-test surface evolves,
// and define helper `fn t0()` constructors that are not yet `const`
// because `time::macros::datetime!` is non-const.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::field_reassign_with_default,
    clippy::missing_const_for_fn,
    clippy::indexing_slicing,
    clippy::no_effect_underscore_binding
)]

//! Integration tests for [`RbaService::score_with_enriched_context`]
//! (HIGH-001).
//!
//! Each test drives the service with a synthetic [`LoginContext`] plus
//! the necessary tracker pre-population, then asserts both the
//! composite score AND the bucketed action (low / medium / high /
//! block) the service maps it to.
//!
//! We deliberately use ONLY the public crate surface — no peeking at
//! private internals — so these tests double as living documentation
//! of how a downstream caller wires the engine.

use std::net::Ipv4Addr;
use std::time::Duration;

use sx_rba::{bucket_action, LoginContext, RbaAction, RbaConfig, RbaFeatureFlags, RbaService};
use time::macros::datetime;
use time::OffsetDateTime;
use uuid::Uuid;

/// Anchor timestamp the tests pin their wall clock to.
fn t0() -> OffsetDateTime {
    datetime!(2026-06-15 10:00:00 UTC)
}

/// Build a baseline `LoginContext` keyed to `(tenant, user)`.
fn ctx(
    tenant: Uuid,
    user: Uuid,
    ip: Ipv4Addr,
    at: OffsetDateTime,
    fp: Option<&str>,
) -> LoginContext {
    LoginContext {
        tenant_id: tenant,
        user_id: Some(user),
        email: "alice@example.test".into(),
        ip,
        device_fingerprint: fp.map(str::to_owned),
        observed_at: at,
    }
}

#[test]
fn known_device_in_country_with_fresh_mfa_lands_in_allow_bucket() {
    let svc = RbaService::default();
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    // Pre-enrol the device, record a fresh MFA, and seed a clean
    // success-rate history.
    svc.enroll_device_fingerprint(tenant, user, "fp-known", t0() - Duration::from_secs(86_400));
    svc.record_mfa_completion(tenant, user, t0() - Duration::from_secs(300));
    for i in 0..15 {
        svc.record_login_outcome(
            tenant,
            user,
            true,
            t0() - Duration::from_secs(3_600 * (i + 1)),
        );
    }
    // Prior login was from the same US centroid → no travel risk.
    svc.record_login_geo(
        tenant,
        user,
        37.0902,
        -95.7129,
        t0() - Duration::from_secs(3_600),
    );
    let out = svc.score_with_enriched_context(ctx(
        tenant,
        user,
        Ipv4Addr::new(8, 8, 8, 8),
        t0(),
        Some("fp-known"),
    ));
    assert_eq!(
        out.action,
        RbaAction::Allow,
        "score={}, reason={}",
        out.score,
        out.reason
    );
    let cfg = RbaConfig::default();
    assert!(
        out.score < cfg.allow_threshold,
        "expected <{} got {}",
        cfg.allow_threshold,
        out.score
    );
    // Enriched snapshot must carry every signal.
    assert!(out.snapshot.device_fingerprint.is_some());
    assert!(out.snapshot.mfa_recent.is_some());
    assert!(out.snapshot.success_rate.is_some());
    assert!(out.snapshot.impossible_travel.is_some());
}

#[test]
fn unknown_device_after_hours_off_country_steps_up() {
    let svc = RbaService::default();
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    // No prior device, no MFA, no history → conservative defaults.
    // Use an unknown-country IP (240.0.0.1 outside the embedded CSV)
    // at deep-night UTC to push the composite over the 30 allow
    // threshold reliably.
    let out = svc.score_with_enriched_context(ctx(
        tenant,
        user,
        Ipv4Addr::new(240, 0, 0, 1),
        datetime!(2026-06-15 03:00:00 UTC),
        Some("fp-new"),
    ));
    let cfg = RbaConfig::default();
    assert_eq!(out.action, RbaAction::StepUpMfa, "score={}", out.score);
    assert!(out.score >= cfg.allow_threshold && out.score < cfg.block_threshold);
}

#[test]
fn impossible_travel_promotes_into_block_bucket() {
    let svc = RbaService::default();
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    // Seed: 5 minutes ago user was logged in from the US centroid.
    svc.record_login_geo(
        tenant,
        user,
        37.0902, // US
        -95.7129,
        t0() - Duration::from_secs(300),
    );
    // Now they show up from RU IP (89.0.0.1 in the fixture). That's
    // ~9000 km in 5 minutes → > 100_000 km/h, impossible.
    let out = svc.score_with_enriched_context(ctx(
        tenant,
        user,
        Ipv4Addr::new(89, 0, 0, 1),
        t0(),
        Some("fp-new"),
    ));
    let cfg = RbaConfig::default();
    let travel = out
        .snapshot
        .impossible_travel
        .as_ref()
        .expect("travel computed");
    assert_eq!(
        travel.verdict,
        sx_rba::signals::impossible_travel::TravelVerdict::Impossible,
        "speed={:?}",
        travel.speed_kmh
    );
    // The composite combines impossible-travel + off-country + unknown
    // device. That must land in the step-up bucket at minimum.
    assert!(
        out.score >= cfg.allow_threshold,
        "expected at least step-up bucket, got {}",
        out.score
    );
    // bucket_action helper must agree with the service.
    assert_eq!(out.action, bucket_action(out.score, &cfg));
}

#[test]
fn burst_velocity_unknown_country_blocks() {
    let svc = RbaService::default();
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    // Disable the HIGH-001 enrichment for this scenario — we are
    // exercising the legacy ip-geo + velocity + after-hours path on
    // its own. The HIGH-001 conservative defaults would otherwise eat
    // 0.45 of the weight budget and pin the composite below the block
    // threshold.
    let cfg = RbaConfig {
        feature_flags: RbaFeatureFlags {
            enable_device_fp: false,
            enable_mfa_recent: false,
            enable_success_rate: false,
            enable_impossible_travel: false,
            ..RbaFeatureFlags::default()
        },
        ..Default::default()
    };
    svc.put_config(tenant, cfg.clone()).expect("config valid");
    // 14 attempts to ramp velocity to 100, from a country outside the
    // embedded CSV at deep-night UTC.
    let ip = Ipv4Addr::new(240, 0, 0, 1);
    let ts = datetime!(2026-06-15 02:00:00 UTC);
    let mut last = svc.score_with_enriched_context(ctx(tenant, user, ip, ts, None));
    for _ in 0..14 {
        last = svc.score_with_enriched_context(ctx(tenant, user, ip, ts, None));
    }
    assert_eq!(last.action, RbaAction::Block, "score={}", last.score);
    assert!(last.score >= cfg.block_threshold);
}

#[test]
fn disabling_impossible_travel_via_feature_flag_lowers_score() {
    let svc = RbaService::default();
    let tenant_on = Uuid::new_v4();
    let tenant_off = Uuid::new_v4();
    let user = Uuid::new_v4();
    // Both tenants share an "impossible" prior sighting.
    svc.record_login_geo(
        tenant_on,
        user,
        37.0902,
        -95.7129,
        t0() - Duration::from_secs(300),
    );
    svc.record_login_geo(
        tenant_off,
        user,
        37.0902,
        -95.7129,
        t0() - Duration::from_secs(300),
    );
    // Off-tenant disables impossible-travel only.
    let mut cfg_off = RbaConfig::default();
    cfg_off.feature_flags = RbaFeatureFlags {
        enable_impossible_travel: false,
        ..RbaFeatureFlags::default()
    };
    svc.put_config(tenant_off, cfg_off).expect("config valid");
    let with_travel = svc.score_with_enriched_context(ctx(
        tenant_on,
        user,
        Ipv4Addr::new(89, 0, 0, 1),
        t0(),
        Some("fp-new"),
    ));
    let without_travel = svc.score_with_enriched_context(ctx(
        tenant_off,
        user,
        Ipv4Addr::new(89, 0, 0, 1),
        t0(),
        Some("fp-new"),
    ));
    assert!(
        without_travel.score < with_travel.score,
        "disabling impossible-travel must lower the composite ({} vs {})",
        without_travel.score,
        with_travel.score
    );
}

#[test]
fn all_signals_disabled_collapses_score_to_zero_allow() {
    let svc = RbaService::default();
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let cfg = RbaConfig {
        feature_flags: RbaFeatureFlags::all_off(),
        ..Default::default()
    };
    svc.put_config(tenant, cfg).expect("config valid");
    // Even with hostile inputs the score must be 0 → allow.
    let out = svc.score_with_enriched_context(ctx(
        tenant,
        user,
        Ipv4Addr::new(240, 0, 0, 1),
        datetime!(2026-06-15 02:00:00 UTC),
        None,
    ));
    assert_eq!(out.score, 0);
    assert_eq!(out.action, RbaAction::Allow);
}

#[test]
fn enriched_snapshot_serialises_into_jsonb_map() {
    let svc = RbaService::default();
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    svc.record_login_geo(
        tenant,
        user,
        37.0902,
        -95.7129,
        t0() - Duration::from_secs(7_200),
    );
    let out = svc.score_with_enriched_context(ctx(
        tenant,
        user,
        Ipv4Addr::new(8, 8, 8, 8),
        t0(),
        Some("fp"),
    ));
    let map = out.snapshot.to_map();
    assert!(map.contains_key("country"));
    assert!(map.contains_key("impossible_travel"));
    assert!(map.contains_key("device_fingerprint"));
    assert!(map.contains_key("mfa_recent"));
    assert!(map.contains_key("success_rate"));
}
