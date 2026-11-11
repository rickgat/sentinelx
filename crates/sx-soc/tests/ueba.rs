//! Integration tests for the UEBA module — synthetic event-stream driven.
//!
//! These tests pin the end-to-end behaviour of the baseline + anomaly
//! detector pipeline against a realistic stream of events. Unit tests
//! cover the individual functions; here we feed a synthetic stream and
//! assert the aggregate invariants (idempotency, bounded growth,
//! warm-up silence, anomaly emission only after warm-up).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use sx_soc::ueba::baseline::{MAX_ASSETS, MAX_IP_PREFIXES};
use sx_soc::ueba::service::UebaService;
use sx_soc::{
    detect_anomaly, update_baseline_from_event, InMemoryUebaService, Severity, UebaEvent,
    UserBehaviorBaseline,
};
use time::macros::datetime;

/// Construct a fresh event scoped to the synthetic test tenant.
fn evt(user: &str, hour: u8, ip: Option<&str>, asset: Option<&str>) -> UebaEvent {
    let dt = datetime!(2027-01-01 0:00:00 UTC)
        .replace_hour(hour)
        .unwrap();
    let mut e = UebaEvent::new(user, dt);
    e.tenant_id = Some("t-synth".into());
    e.event_id = Some(uuid::Uuid::new_v4().to_string());
    e.source_ip = ip.map(str::to_owned);
    e.asset_id = asset.map(str::to_owned);
    e
}

#[test]
fn synthetic_stream_updates_histogram_idempotently() {
    let mut base = UserBehaviorBaseline::new(Some("t".into()), "alice");

    // 100 events at hour 9, all with distinct event ids — the bucket
    // count must equal the unique event count.
    for i in 0..100 {
        let mut e = evt("alice", 9, Some("10.0.0.1"), Some("crown"));
        e.event_id = Some(format!("e{i}"));
        assert!(update_baseline_from_event(&mut base, &e));
    }
    assert_eq!(base.login_hours_histogram[9], 100);
    assert_eq!(base.total_login_samples(), 100);

    // Replay the same 100 events — every replay must be a no-op
    // (idempotency on event_id).
    for i in 0..100 {
        let mut e = evt("alice", 9, Some("10.0.0.1"), Some("crown"));
        e.event_id = Some(format!("e{i}"));
        assert!(!update_baseline_from_event(&mut base, &e));
    }
    assert_eq!(base.login_hours_histogram[9], 100);
}

#[test]
fn synthetic_stream_stays_bounded_under_load() {
    let mut base = UserBehaviorBaseline::new(Some("t".into()), "alice");
    // 5_000 unique events across 24 hours, 500 distinct asset ids, and
    // 256 distinct /16 prefixes — well above the per-baseline caps.
    for i in 0..5_000_u32 {
        let hour = u8::try_from(i % 24).unwrap();
        let mut e = evt(
            "alice",
            hour,
            Some(&format!("203.{}.0.1", i % 256)),
            Some(&format!("asset-{}", i % 500)),
        );
        e.event_id = Some(format!("e{i}"));
        let _ = update_baseline_from_event(&mut base, &e);
    }
    assert!(base.ip_prefixes.len() <= MAX_IP_PREFIXES);
    assert!(base.accessed_assets.len() <= MAX_ASSETS);
    // Histogram is fixed-size by construction.
    assert_eq!(base.login_hours_histogram.len(), 24);
}

#[test]
fn synthetic_stream_silences_anomalies_until_warmup() {
    let mut base = UserBehaviorBaseline::new(Some("t".into()), "alice");
    // 4 events at hour 9 — strictly below the warm-up threshold of 5.
    for i in 0..4 {
        let mut e = evt("alice", 9, None, None);
        e.event_id = Some(format!("e{i}"));
        let _ = update_baseline_from_event(&mut base, &e);
    }
    // A rare-hour event must NOT fire pre-warm-up.
    let rare = evt("alice", 3, None, None);
    assert!(detect_anomaly(&base, &rare).is_none());

    // One more at hour 9 — crosses the warm-up threshold.
    let mut warmup = evt("alice", 9, None, None);
    warmup.event_id = Some("warmup".into());
    let _ = update_baseline_from_event(&mut base, &warmup);
    // Now the same rare-hour event fires.
    let an = detect_anomaly(&base, &rare).expect("anomaly post-warmup");
    assert!(an.dimensions.iter().any(|d| d.dimension == "hour_of_day"));
}

#[tokio::test]
async fn synthetic_stream_emits_anomaly_records_via_service() {
    let svc = InMemoryUebaService::new();
    // Warm up alice with 9 typical 9-to-5 hour events from a stable /16.
    for h in 9..18 {
        let mut e = evt("alice", u8::try_from(h).unwrap(), Some("10.0.0.5"), None);
        e.event_id = Some(format!("warm-{h}"));
        svc.apply(e).await;
    }
    // Now a brand-new /16 prefix at the same hour must fire — IP-prefix
    // dim only, since the hour bucket is non-empty.
    let probe = evt("alice", 10, Some("198.51.100.1"), None);
    let rec = svc.check(&probe).await.expect("anomaly raised");
    assert!(rec
        .anomaly
        .dimensions
        .iter()
        .any(|d| d.dimension == "source_ip_prefix"));
    assert!(matches!(
        rec.anomaly.severity,
        Severity::Medium | Severity::High
    ));

    // The recorded anomaly must surface through `list_anomalies`, scoped
    // to the same tenant.
    let rows = svc.list_anomalies(Some("t-synth"), 10).await;
    assert!(!rows.is_empty());
    assert!(rows.iter().any(|r| r.user_id == "alice"));
}

#[tokio::test]
async fn synthetic_stream_isolates_tenants_in_service_ring() {
    let svc = InMemoryUebaService::new();
    // tenant-A and tenant-B each get a fresh anomaly.
    let mut a = evt("alice", 9, Some("198.51.100.1"), None);
    a.tenant_id = Some("tA".into());
    let mut b = evt("bob", 9, Some("198.51.100.2"), None);
    b.tenant_id = Some("tB".into());
    let _ = svc.check(&a).await;
    let _ = svc.check(&b).await;

    let only_a = svc.list_anomalies(Some("tA"), 10).await;
    let only_b = svc.list_anomalies(Some("tB"), 10).await;
    assert!(only_a.iter().all(|r| r.tenant_id.as_deref() == Some("tA")));
    assert!(only_b.iter().all(|r| r.tenant_id.as_deref() == Some("tB")));
}
