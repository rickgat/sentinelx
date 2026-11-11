//! UEBA service trait + in-memory adapter.
//!
//! [`UebaService`] is the single behavioural surface the SOC adapter calls
//! on every ingested event:
//!
//! 1. `apply` — fold the event into the per-user baseline.
//! 2. `check` — score the event against the current baseline and return any
//!    triggered anomaly.
//! 3. `get_baseline` / `list_anomalies` — read paths used by the HTTP layer.
//!
//! [`InMemoryUebaService`] is a clone-cheap `Arc<Mutex<…>>` implementation
//! suitable for the monolith composition root. Production deployments swap
//! it for a Postgres-backed adapter once the migration in
//! `crates/sx-storage/migrations/20270101001000__create_ueba_state.sql`
//! becomes the source of truth.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::Mutex;

use crate::ueba::anomaly::{detect_anomaly, UebaAnomaly};
use crate::ueba::baseline::{UebaEvent, UserBehaviorBaseline};
use crate::ueba::update::update_baseline_from_event;

/// Persisted record of one detected anomaly. Returned by
/// [`UebaService::list_anomalies`] and projected onto the HTTP view.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnomalyRecord {
    /// Stable id (UUID v4).
    pub id: String,
    /// Tenant the anomaly was raised under. `None` for global.
    pub tenant_id: Option<String>,
    /// Subject of the originating event.
    pub user_id: String,
    /// Originating event id when available.
    pub event_id: Option<String>,
    /// Aggregate anomaly attribution.
    pub anomaly: UebaAnomaly,
    /// Wall-clock time the anomaly was recorded.
    pub detected_at: OffsetDateTime,
}

/// Behavioural surface the SOC adapter calls into on every event.
#[async_trait]
pub trait UebaService: Send + Sync {
    /// Fold the event into the user's baseline (idempotent on `event_id`).
    async fn apply(&self, event: UebaEvent);

    /// Score the event against the current baseline. Persists and returns
    /// the anomaly if one was raised.
    async fn check(&self, event: &UebaEvent) -> Option<AnomalyRecord>;

    /// Snapshot the baseline for `(tenant_id, user_id)`. Returns `None`
    /// when the user has no recorded events yet.
    async fn get_baseline(
        &self,
        tenant_id: Option<&str>,
        user_id: &str,
    ) -> Option<UserBehaviorBaseline>;

    /// Return the most recent anomalies, newest-first, capped at `limit`.
    /// `tenant_id = None` returns all tenants (admin-only at the HTTP
    /// surface).
    async fn list_anomalies(&self, tenant_id: Option<&str>, limit: usize) -> Vec<AnomalyRecord>;
}

/// Key the in-memory store uses to scope baselines per tenant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BaselineKey {
    tenant: Option<String>,
    user: String,
}

/// Shared mutable state behind [`InMemoryUebaService`]. Hoisted into its
/// own struct so the public adapter holds a single `Arc`.
#[derive(Debug, Default)]
struct InnerState {
    /// Baselines keyed by `(tenant_id, user_id)`.
    baselines: HashMap<BaselineKey, UserBehaviorBaseline>,
    /// Bounded ring of recently-detected anomalies, newest-last.
    anomalies: std::collections::VecDeque<AnomalyRecord>,
}

/// Capacity of the in-memory anomaly ring. Older entries are evicted FIFO.
const ANOMALY_RING_CAPACITY: usize = 1_024;

/// In-memory UEBA service implementation.
///
/// Cloneable and shareable across handler tasks; mutual exclusion is
/// `tokio::sync::Mutex` so async paths never block the runtime thread.
#[derive(Debug, Clone, Default)]
pub struct InMemoryUebaService {
    inner: Arc<Mutex<InnerState>>,
}

impl InMemoryUebaService {
    /// Construct a fresh, empty service.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl UebaService for InMemoryUebaService {
    async fn apply(&self, event: UebaEvent) {
        let key = BaselineKey {
            tenant: event.tenant_id.clone(),
            user: event.user_id.clone(),
        };
        let mut guard = self.inner.lock().await;
        let entry = guard
            .baselines
            .entry(key)
            .or_insert_with(|| UserBehaviorBaseline::new(event.tenant_id.clone(), &event.user_id));
        let _ = update_baseline_from_event(entry, &event);
        drop(guard);
    }

    async fn check(&self, event: &UebaEvent) -> Option<AnomalyRecord> {
        let key = BaselineKey {
            tenant: event.tenant_id.clone(),
            user: event.user_id.clone(),
        };
        let mut guard = self.inner.lock().await;
        // Score against an immutable view of the current baseline (default
        // when unknown).
        let baseline =
            guard.baselines.get(&key).cloned().unwrap_or_else(|| {
                UserBehaviorBaseline::new(event.tenant_id.clone(), &event.user_id)
            });
        let Some(anomaly) = detect_anomaly(&baseline, event) else {
            drop(guard);
            return None;
        };
        let rec = AnomalyRecord {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: event.tenant_id.clone(),
            user_id: event.user_id.clone(),
            event_id: event.event_id.clone(),
            anomaly,
            detected_at: OffsetDateTime::now_utc(),
        };
        // Bounded FIFO insert.
        if guard.anomalies.len() >= ANOMALY_RING_CAPACITY {
            let _ = guard.anomalies.pop_front();
        }
        guard.anomalies.push_back(rec.clone());
        drop(guard);
        Some(rec)
    }

    async fn get_baseline(
        &self,
        tenant_id: Option<&str>,
        user_id: &str,
    ) -> Option<UserBehaviorBaseline> {
        let key = BaselineKey {
            tenant: tenant_id.map(str::to_owned),
            user: user_id.to_owned(),
        };
        let guard = self.inner.lock().await;
        let snapshot = guard.baselines.get(&key).cloned();
        drop(guard);
        snapshot
    }

    async fn list_anomalies(&self, tenant_id: Option<&str>, limit: usize) -> Vec<AnomalyRecord> {
        let guard = self.inner.lock().await;
        let mut out: Vec<AnomalyRecord> = guard
            .anomalies
            .iter()
            .rev()
            .filter(|a| {
                tenant_id.is_none() || tenant_id.is_some_and(|t| a.tenant_id.as_deref() == Some(t))
            })
            .take(limit)
            .cloned()
            .collect();
        drop(guard);
        // Sort newest-first by detected_at descending, then by score
        // descending for tie-breaks so high-score anomalies surface first
        // when timestamps collide.
        out.sort_by(|a, b| {
            b.detected_at.cmp(&a.detected_at).then_with(|| {
                b.anomaly
                    .score
                    .partial_cmp(&a.anomaly.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn evt(user: &str, hour: u8, ip: Option<&str>) -> UebaEvent {
        let dt = datetime!(2027-01-01 0:00:00 UTC)
            .replace_hour(hour)
            .unwrap();
        let mut e = UebaEvent::new(user, dt);
        e.tenant_id = Some("t-1".into());
        e.event_id = Some(uuid::Uuid::new_v4().to_string());
        e.source_ip = ip.map(str::to_owned);
        e
    }

    #[tokio::test]
    async fn first_event_creates_baseline_no_anomaly_at_warmup_silence() {
        let svc = InMemoryUebaService::new();
        let e = evt("alice", 10, None);
        // No IP / asset and pre-warmup hour silence → no anomaly.
        let res = svc.check(&e).await;
        // Apply afterwards — the baseline becomes the storage of record.
        svc.apply(e.clone()).await;
        assert!(res.is_none());
        let base = svc
            .get_baseline(Some("t-1"), "alice")
            .await
            .expect("baseline created");
        assert_eq!(base.total_login_samples(), 1);
    }

    #[tokio::test]
    async fn brand_new_ip_after_warmup_records_anomaly() {
        let svc = InMemoryUebaService::new();
        // Seed 6 events from 10.0.0.x so the IP prefix is known.
        for i in 0..6 {
            let mut e = evt("bob", 9, Some(&format!("10.0.0.{i}")));
            e.event_id = Some(format!("seed-{i}"));
            svc.apply(e).await;
        }
        // Brand-new prefix from a different /16.
        let evt2 = evt("bob", 9, Some("198.51.100.4"));
        let an = svc.check(&evt2).await.expect("anomaly raised");
        assert!(an
            .anomaly
            .dimensions
            .iter()
            .any(|d| d.dimension == "source_ip_prefix"));
        let listed = svc.list_anomalies(Some("t-1"), 10).await;
        assert!(!listed.is_empty());
    }

    #[tokio::test]
    async fn tenant_isolation_in_list_anomalies() {
        let svc = InMemoryUebaService::new();
        let mut e = evt("u", 9, Some("198.51.100.1"));
        e.tenant_id = Some("tA".into());
        let _ = svc.check(&e).await;
        let mut e2 = evt("u", 9, Some("198.51.100.2"));
        e2.tenant_id = Some("tB".into());
        let _ = svc.check(&e2).await;

        let a_only = svc.list_anomalies(Some("tA"), 10).await;
        assert_eq!(a_only.len(), 1);
        assert_eq!(a_only[0].tenant_id.as_deref(), Some("tA"));
    }

    #[tokio::test]
    async fn list_anomalies_caps_at_limit() {
        let svc = InMemoryUebaService::new();
        for i in 0..10 {
            let e = evt("u", 9, Some(&format!("198.51.{i}.1")));
            let _ = svc.check(&e).await;
        }
        let cap = svc.list_anomalies(Some("t-1"), 3).await;
        assert_eq!(cap.len(), 3);
    }
}
