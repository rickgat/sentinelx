//! Integration tests for the UEBA port + view DTO surface (P2-005).
//!
//! The HTTP controller drives a `dyn UebaPort` trait object; this test
//! exercises that contract end-to-end against a fake implementation
//! mirroring the in-memory adapter:
//!
//! 1. `get_baseline` returns `NotFound` until apply has run.
//! 2. `list_anomalies` returns newest-first, respects `limit`, and
//!    isolates by tenant.
//! 3. `UebaAnomalyView` serialises with the exact wire shape the
//!    dashboard depends on (renamed dimension labels, severity string).

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::sync::Mutex;

use async_trait::async_trait;
use sx_api::port::{UebaPort, UebaPortError};
use sx_api::view::ueba_view::{
    UebaAnomaliesResponse, UebaAnomalyDimView, UebaAnomalyView, UebaBaselineView,
};

#[derive(Debug, Default)]
struct FakeUeba {
    baselines: Mutex<Vec<(String, UebaBaselineView)>>,
    anomalies: Mutex<Vec<(String, UebaAnomalyView)>>,
}

impl FakeUeba {
    fn seed_baseline(&self, tenant: &str, user: &str) {
        let mut counts = vec![0u32; 24];
        counts[9] = 3;
        let mut prefixes = BTreeMap::new();
        let _ = prefixes.insert("10.0.0.0/16".to_owned(), 3);
        self.baselines.lock().unwrap().push((
            tenant.to_owned(),
            UebaBaselineView {
                tenant_id: Some(tenant.to_owned()),
                user_id: user.to_owned(),
                login_hour_counts: counts,
                ip_prefixes: prefixes,
                accessed_assets: BTreeMap::new(),
                updated_at: Some("2026-06-12T09:00:00Z".to_owned()),
            },
        ));
    }

    fn seed_anomaly(&self, tenant: &str, user: &str, id: &str, ts: &str) {
        self.anomalies.lock().unwrap().push((
            tenant.to_owned(),
            UebaAnomalyView {
                id: id.to_owned(),
                tenant_id: Some(tenant.to_owned()),
                user_id: user.to_owned(),
                event_id: Some(format!("evt-{id}")),
                score: 4.0,
                dimensions: vec![UebaAnomalyDimView {
                    dimension: "source_ip_prefix".into(),
                    score: 4.0,
                    reason: "first observation of prefix 198.51.100.0/16".into(),
                }],
                severity: "medium".into(),
                detected_at: ts.to_owned(),
            },
        ));
    }
}

#[async_trait]
impl UebaPort for FakeUeba {
    async fn get_baseline(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<UebaBaselineView, UebaPortError> {
        let guard = self.baselines.lock().unwrap();
        guard
            .iter()
            .find(|(t, b)| t == tenant_id && b.user_id == user_id)
            .map(|(_, b)| b.clone())
            .ok_or(UebaPortError::NotFound)
    }

    async fn list_anomalies(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<UebaAnomalyView>, UebaPortError> {
        let guard = self.anomalies.lock().unwrap();
        let mut rows: Vec<UebaAnomalyView> = guard
            .iter()
            .rev()
            .filter(|(t, _)| t == tenant_id)
            .take(limit)
            .map(|(_, a)| a.clone())
            .collect();
        drop(guard);
        // Newest-first by `detected_at`, then by score desc.
        rows.sort_by(|a, b| {
            b.detected_at.cmp(&a.detected_at).then_with(|| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });
        Ok(rows)
    }
}

#[tokio::test]
async fn get_baseline_returns_not_found_before_seed() {
    let port: Box<dyn UebaPort> = Box::new(FakeUeba::default());
    let err = port.get_baseline("t-a", "alice").await.unwrap_err();
    assert!(matches!(err, UebaPortError::NotFound));
}

#[tokio::test]
async fn get_baseline_returns_view_after_seed() {
    let fake = FakeUeba::default();
    fake.seed_baseline("t-a", "alice");
    let port: Box<dyn UebaPort> = Box::new(fake);
    let view = port.get_baseline("t-a", "alice").await.unwrap();
    assert_eq!(view.user_id, "alice");
    assert_eq!(view.login_hour_counts.len(), 24);
    assert_eq!(view.login_hour_counts[9], 3);
    assert!(view.ip_prefixes.contains_key("10.0.0.0/16"));
}

#[tokio::test]
async fn list_anomalies_isolates_by_tenant() {
    let fake = FakeUeba::default();
    fake.seed_anomaly("t-a", "alice", "id-a", "2026-06-12T09:01:00Z");
    fake.seed_anomaly("t-b", "bob", "id-b", "2026-06-12T09:02:00Z");
    let port: Box<dyn UebaPort> = Box::new(fake);

    let only_a = port.list_anomalies("t-a", 10).await.unwrap();
    let only_b = port.list_anomalies("t-b", 10).await.unwrap();
    assert_eq!(only_a.len(), 1);
    assert_eq!(only_b.len(), 1);
    assert_eq!(only_a[0].tenant_id.as_deref(), Some("t-a"));
    assert_eq!(only_b[0].tenant_id.as_deref(), Some("t-b"));
}

#[tokio::test]
async fn list_anomalies_caps_at_limit_and_orders_newest_first() {
    let fake = FakeUeba::default();
    for i in 0..10 {
        let ts = format!("2026-06-12T09:0{i}:00Z");
        fake.seed_anomaly("t-a", "alice", &format!("id-{i}"), &ts);
    }
    let port: Box<dyn UebaPort> = Box::new(fake);
    let rows = port.list_anomalies("t-a", 3).await.unwrap();
    assert_eq!(rows.len(), 3);
    // First entry must be the newest seeded timestamp (`...09:09:00Z`).
    assert_eq!(rows[0].detected_at, "2026-06-12T09:09:00Z");
    assert_eq!(rows[2].detected_at, "2026-06-12T09:07:00Z");
}

#[test]
fn anomaly_response_wire_shape_includes_anomalies_field() {
    let r = UebaAnomaliesResponse {
        anomalies: Vec::new(),
    };
    let raw = serde_json::to_string(&r).unwrap();
    assert!(raw.contains("\"anomalies\""));
    assert!(raw.contains("[]"));
}

#[test]
fn anomaly_view_round_trips() {
    let a = UebaAnomalyView {
        id: "id".into(),
        tenant_id: Some("t".into()),
        user_id: "u".into(),
        event_id: None,
        score: 6.5,
        dimensions: vec![UebaAnomalyDimView {
            dimension: "hour_of_day".into(),
            score: 6.5,
            reason: "hour 3 UTC is 6.5 sigma below mean".into(),
        }],
        severity: "high".into(),
        detected_at: "2026-06-12T03:00:00Z".into(),
    };
    let raw = serde_json::to_string(&a).unwrap();
    let back: UebaAnomalyView = serde_json::from_str(&raw).unwrap();
    assert_eq!(back, a);
    // `event_id` is `None` here — verify it is omitted from the wire shape
    // so the dashboard's `event_id?: string` type matches.
    assert!(!raw.contains("\"event_id\""));
}
