//! SOC adapter — wires `sx-soc` (rule engine + correlator + buffered sink)
//! behind the [`sx_api::port::SocPort`] HTTP trait.
//!
//! ## Topology
//!
//! ```text
//!     POST /v1/soc/events
//!             │            (operator-injected Value)
//!             ▼
//!     ┌────────────────┐
//!     │ mpsc::Sender   │ ── owned by SocAdapter
//!     └────────────────┘
//!             │
//!             ▼
//!     ┌────────────────┐
//!     │ mpsc::Receiver │ ── moved into spawned correlator task
//!     └────────────────┘
//!             │
//!             ▼
//!     ┌────────────────┐
//!     │   Correlator   │ ── RuleEngine (starter_pack, 5 rules)
//!     └────────────────┘
//!             │  Vec<Alert>
//!             ▼
//!     ┌─────────────────────────────────┐
//!     │ BufferAlertSink (capacity 200)  │ ── shared with SocAdapter
//!     └─────────────────────────────────┘
//!             │
//!             ▼
//!     GET /v1/soc/alerts  (snapshot → SocAlertView projection)
//! ```
//!
//! The correlator task is owned via its `JoinHandle` on the bundle so the
//! parent composition root can abort it on shutdown if needed. While the
//! adapter is live, the mpsc `Sender` is held inside `SocAdapter`, so the
//! channel does not close on its own; the task only exits when the
//! adapter (and therefore the sender) is dropped.

use std::sync::Arc;

use async_trait::async_trait;
use sx_api::port::{Phase3PortError, SocPort};
use sx_api::view::soc_view::SocAlertView;
use sx_soc::ueba::service::UebaService;
use sx_soc::{
    starter_pack, Alert, AlertSink, BufferAlertSink, Correlator, InMemoryUebaService, RuleEngine,
    Severity, UebaEvent,
};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::mpsc;

/// mpsc queue depth for operator-pushed events.
const EVENT_QUEUE_DEPTH: usize = 256;

/// Buffered-alert ring capacity backing `GET /v1/soc/alerts`.
const BUFFER_CAPACITY: usize = 200;

/// Bundle of SOC trait objects ready for [`sx_api::AppState`] + the spawned
/// correlator task handle. Hold the handle so the composition root can
/// abort it on shutdown.
pub(crate) struct SocBundle {
    /// HTTP-facing port.
    pub soc: Arc<dyn SocPort>,
    /// Spawned correlator drain task. Lives for the duration of the
    /// process — joins only when the mpsc sender (kept inside the
    /// adapter) is dropped.
    #[allow(dead_code)] // retained so the task is not detached without a handle
    pub correlator_handle: tokio::task::JoinHandle<()>,
    /// Direct handle to the buffered alert sink. Retained for
    /// test-introspection (ring-eviction assertions) and for future
    /// admin-only endpoints that need to peek across all tenants.
    #[cfg(test)]
    pub(super) buffer: BufferAlertSink,
}

/// Build the SOC bundle.
///
/// Wires:
/// 1. A [`RuleEngine`] hydrated with the [`starter_pack`] (5 rules).
/// 2. A bounded [`BufferAlertSink`] (capacity = [`BUFFER_CAPACITY`]).
/// 3. A [`Correlator`] joining the engine + sink.
/// 4. An mpsc channel; the sender is retained by the adapter, the
///    receiver moves into the spawned correlator drain.
/// 5. A [`InMemoryUebaService`] handle so every event submitted via
///    `submit_event` (or the drift forwarder) updates the per-user
///    behavioural baseline and, on anomaly, lands a `ueba.anomaly`
///    alert into the shared buffer.
pub(crate) fn build(ueba: InMemoryUebaService) -> SocBundle {
    let engine = RuleEngine::new(starter_pack());
    let buffer = BufferAlertSink::new(BUFFER_CAPACITY);
    let buffer_for_adapter = buffer.clone();
    #[cfg(test)]
    let buffer_for_tests = buffer.clone();
    let sinks: Vec<Arc<dyn AlertSink>> = vec![Arc::new(buffer)];
    let correlator = Correlator::new(engine, sinks);

    let (tx, rx) = mpsc::channel::<serde_json::Value>(EVENT_QUEUE_DEPTH);

    let handle = tokio::spawn(async move {
        let stats = correlator.run(rx).await;
        tracing::info!(
            target: "adapters.soc",
            events = stats.events,
            alerts_raw = stats.alerts_raw,
            alerts_forwarded = stats.alerts_forwarded,
            "sx-soc correlator drained channel and exited",
        );
    });

    SocBundle {
        soc: Arc::new(SocAdapter {
            buffer: buffer_for_adapter,
            tx,
            ueba,
        }),
        correlator_handle: handle,
        #[cfg(test)]
        buffer: buffer_for_tests,
    }
}

/// Concrete adapter wrapping the buffered sink + the mpsc sender.
///
/// Fields are `pub(super)` so the in-module test suite can observe the
/// buffered ring directly without an `Any` downcast through the trait
/// object. Outside this module the adapter is reached exclusively via
/// the [`SocPort`] trait object on the bundle.
pub(super) struct SocAdapter {
    pub(super) buffer: BufferAlertSink,
    pub(super) tx: mpsc::Sender<serde_json::Value>,
    pub(super) ueba: InMemoryUebaService,
}

#[async_trait]
impl SocPort for SocAdapter {
    async fn list_alerts(
        &self,
        tenant_id: Option<&str>,
    ) -> Result<Vec<SocAlertView>, Phase3PortError> {
        let snapshot = self.buffer.snapshot().await;
        let out = snapshot
            .into_iter()
            .filter(|a| alert_visible_to(a, tenant_id))
            .map(project_alert)
            .collect();
        Ok(out)
    }

    async fn submit_event(&self, event: serde_json::Value) -> Result<u32, Phase3PortError> {
        // UEBA hook — best-effort. If the payload does not parse cleanly
        // into a `UebaEvent` the dimension is skipped; UEBA never blocks
        // the SOC correlator path.
        if let Some(uev) = parse_ueba_event(&event) {
            // Detect FIRST against the current baseline, so a brand-new
            // event does not immediately seed itself and silence the
            // anomaly on the same call.
            if let Some(rec) = self.ueba.check(&uev).await {
                let dim_summary = rec
                    .anomaly
                    .dimensions
                    .iter()
                    .map(|d| d.dimension.clone())
                    .collect::<Vec<_>>()
                    .join(",");
                let alert = Alert::new(
                    rec.anomaly.severity,
                    "ueba.anomaly",
                    format!("UEBA anomaly for user {} ({dim_summary})", rec.user_id),
                    rec.anomaly
                        .dimensions
                        .iter()
                        .map(|d| d.reason.clone())
                        .collect::<Vec<_>>()
                        .join("; "),
                    rec.tenant_id.clone(),
                );
                self.buffer.forward(&alert).await;
            }
            self.ueba.apply(uev).await;
        }

        match self.tx.send(event).await {
            Ok(()) => Ok(1),
            Err(_) => Err(Phase3PortError::Dependency(
                "soc correlator channel closed".into(),
            )),
        }
    }
}

/// Best-effort projection of a free-form `Value` payload onto a
/// [`UebaEvent`].
///
/// Returns `None` when the payload lacks the bare-minimum fields
/// (`user_id` + `ts`) the UEBA pipeline needs. The hook is intentionally
/// permissive — every other field is optional.
fn parse_ueba_event(v: &serde_json::Value) -> Option<UebaEvent> {
    let user_id = v
        .get("user_id")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())?;
    let ts_str = v.get("ts").and_then(serde_json::Value::as_str)?;
    let occurred_at = OffsetDateTime::parse(ts_str, &Rfc3339).ok()?;
    let mut evt = UebaEvent::new(user_id, occurred_at);
    evt.tenant_id = v
        .get("tenant_id")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    evt.event_id = v
        .get("event_id")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    evt.source_ip = v
        .get("source_ip")
        .or_else(|| v.get("ip"))
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    evt.asset_id = v
        .get("asset_id")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    Some(evt)
}

/// Visibility predicate: a globally-scoped alert (`tenant_id = None`) is
/// returned to every caller; a tenant-scoped alert is returned only when
/// it matches the caller's tenant claim.
fn alert_visible_to(alert: &Alert, caller_tenant: Option<&str>) -> bool {
    match (&alert.tenant_id, caller_tenant) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(at), Some(ct)) => at == ct,
    }
}

/// Project a [`sx_soc::Alert`] onto the HTTP-facing
/// [`sx_api::view::soc_view::SocAlertView`].
fn project_alert(a: Alert) -> SocAlertView {
    SocAlertView {
        id: a.id,
        severity: severity_label(a.severity).to_owned(),
        kind: a.kind,
        title: a.title,
        fired_at: a
            .fired_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| fallback_ts()),
        tenant_id: a.tenant_id,
    }
}

/// Map [`Severity`] onto its canonical lowercase label.
const fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

/// Fallback timestamp string when RFC 3339 formatting fails (should never
/// happen for `OffsetDateTime::now_utc`, but the API surface is
/// no-panic by contract).
fn fallback_ts() -> String {
    OffsetDateTime::UNIX_EPOCH
        .format(&Rfc3339)
        .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn submit_event_then_list_returns_matching_alert() {
        let bundle = build(InMemoryUebaService::new());
        // Push an event that matches `auth.bruteforce`.
        let event = json!({
            "kind": "auth.login_failure_window",
            "count": 7,
            "ts": OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
            "tenant_id": "tenant-x",
        });
        let accepted = bundle
            .soc
            .submit_event(event)
            .await
            .expect("submit should succeed");
        assert_eq!(accepted, 1);

        // The correlator runs asynchronously; give it a moment to drain.
        // Poll the buffer up to ~1s.
        let alerts = poll_alerts(&bundle, Some("tenant-x"), 1).await;
        assert!(
            alerts.iter().any(|a| a.kind == "auth.bruteforce"),
            "expected auth.bruteforce alert, got {alerts:?}",
        );
    }

    #[tokio::test]
    async fn ring_buffer_evicts_oldest_when_over_capacity() {
        let bundle = build(InMemoryUebaService::new());
        // Push 250 matching events (> BUFFER_CAPACITY = 200).
        //
        // Throttling on `auth.bruteforce` is 5 minutes, so only the first
        // event will reach the sink. To exercise the ring we instead push
        // a mix of events that pass the engine without throttle-collapsing
        // each other — easiest is to use distinct tenant_ids so the
        // (rule_id, tenant_id, kind) throttle keys diverge.
        for i in 0..250_u32 {
            let event = json!({
                "kind": "auth.login_failure_window",
                "count": 7,
                "ts": OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
                "tenant_id": format!("tenant-{i}"),
            });
            bundle.soc.submit_event(event).await.expect("submit");
        }
        // Wait for drain to make progress.
        let _ = poll_total(&bundle, BUFFER_CAPACITY).await;
        // The buffer must be at most BUFFER_CAPACITY entries — ring eviction.
        let snapshot = bundle.buffer.snapshot().await;
        assert!(
            snapshot.len() <= BUFFER_CAPACITY,
            "buffer overran capacity: {} > {}",
            snapshot.len(),
            BUFFER_CAPACITY,
        );
    }

    #[tokio::test]
    async fn list_alerts_filters_by_tenant() {
        let bundle = build(InMemoryUebaService::new());
        // Push two events targeting different tenants.
        for tenant in ["tenant-a", "tenant-b"] {
            let event = json!({
                "kind": "auth.login_failure_window",
                "count": 7,
                "ts": OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
                "tenant_id": tenant,
            });
            bundle.soc.submit_event(event).await.expect("submit");
        }
        let _ = poll_total(&bundle, 2).await;

        let only_a = bundle
            .soc
            .list_alerts(Some("tenant-a"))
            .await
            .expect("list");
        // Every returned alert must be visible to tenant-a (its own
        // tenant or globally scoped).
        for a in &only_a {
            assert!(
                a.tenant_id.as_deref() == Some("tenant-a") || a.tenant_id.is_none(),
                "unexpected alert leak: {a:?}",
            );
        }
    }

    #[tokio::test]
    async fn submit_event_returns_dependency_when_receiver_dropped() {
        // Construct an isolated SocAdapter directly so we can drop the
        // receiver deterministically — without going through the
        // spawn/abort dance which is racy under cooperative scheduling.
        let (tx, rx) = mpsc::channel::<serde_json::Value>(4);
        let adapter = SocAdapter {
            buffer: BufferAlertSink::new(BUFFER_CAPACITY),
            tx,
            ueba: InMemoryUebaService::new(),
        };
        drop(rx);
        let port: Arc<dyn SocPort> = Arc::new(adapter);
        let result = port.submit_event(json!({"kind": "anything"})).await;
        assert!(
            matches!(result, Err(Phase3PortError::Dependency(_))),
            "expected Dependency after dropped receiver, got {result:?}",
        );
    }

    #[tokio::test]
    async fn project_alert_uses_canonical_severity_labels() {
        for (sev, label) in [
            (Severity::Critical, "critical"),
            (Severity::High, "high"),
            (Severity::Medium, "medium"),
            (Severity::Low, "low"),
            (Severity::Info, "info"),
        ] {
            let alert = Alert::new(sev, "k", "title", "desc", None);
            let view = project_alert(alert);
            assert_eq!(view.severity, label);
        }
    }

    #[tokio::test]
    async fn list_alerts_on_empty_buffer_returns_empty_vec() {
        let bundle = build(InMemoryUebaService::new());
        let out = bundle
            .soc
            .list_alerts(Some("tenant-z"))
            .await
            .expect("list");
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn alert_visible_to_handles_all_scope_combinations() {
        let global = Alert::new(Severity::Info, "k", "t", "d", None);
        let scoped = Alert::new(Severity::Info, "k", "t", "d", Some("tenant-x".into()));

        assert!(alert_visible_to(&global, Some("tenant-x")));
        assert!(alert_visible_to(&global, None));
        assert!(alert_visible_to(&scoped, Some("tenant-x")));
        assert!(!alert_visible_to(&scoped, Some("tenant-y")));
        assert!(!alert_visible_to(&scoped, None));
    }

    // ---------- helpers ----------

    /// Poll the buffered sink until it holds at least `min` alerts or the
    /// deadline expires. Returns the projected view at the end.
    async fn poll_alerts(
        bundle: &SocBundle,
        tenant: Option<&str>,
        min: usize,
    ) -> Vec<SocAlertView> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let out = bundle.soc.list_alerts(tenant).await.expect("list");
            if out.len() >= min || std::time::Instant::now() >= deadline {
                return out;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// Poll the buffer (across all tenants) until it holds at least `min`
    /// entries or the deadline expires. Returns the final raw length.
    async fn poll_total(bundle: &SocBundle, min: usize) -> usize {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let len = bundle.buffer.len().await;
            if len >= min || std::time::Instant::now() >= deadline {
                return len;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}
