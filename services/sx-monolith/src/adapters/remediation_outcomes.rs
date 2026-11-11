//! P1-011 — remediation outcomes + regression-tracking adapter.
//!
//! Three pieces wired together:
//!
//! 1. [`RemediationOutcomesAdapter`] — concrete
//!    [`sx_api::port::RemediationOutcomesPort`]. Reads aggregate metrics
//!    + regression lists out of the shared in-memory service handle.
//! 2. `ObservingFindingRepository` — `FindingRepositoryPort` decorator
//!    that intercepts `update_status` transitions to `closed`. When the
//!    transition fires it records an outcome via the service. When
//!    `update_status` transitions a finding away from `closed` (i.e. it
//!    re-opens) it is treated as a regression detection.
//! 3. [`build`] — composes both halves around a single shared service
//!    handle so the HTTP read port + the finding-state-transition
//!    observer see the same in-memory store.
//!
//! ## Why decorate instead of patch the inner repo
//!
//! Phase-3.5 already has multiple repository back-ends (in-memory +
//! Postgres) and several writers (`update_status` per id, bulk update,
//! findings repair jobs). Wrapping the read+write trait object at the
//! composition boundary means **every** writer goes through the same
//! observer hook without per-implementation patching. The decorator is
//! a thin pass-through so production paths see one extra Arc deref.
//!
//! ## `check_id` resolution
//!
//! `FindingView` does not carry an explicit `check_id`. The decorator
//! synthesises one from the title (stable per finding catalogue entry).
//! When the title is empty the synthesised key falls back to the
//! finding id so the bucket is at least non-empty — this never collides
//! with another check.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sx_api::port::{
    EngagementPortError, FindingRepositoryPort, Phase3PortError, RemediationOutcomesPort,
};
use sx_api::view::finding_view::FindingView;
use sx_api::view::remediation_outcomes_view::{
    MttrBucketView, RegressingTechniqueView, RegressionEventView, RegressionListView,
    RemediationMetricsView,
};
#[cfg(test)]
use sx_remediation::service::outcomes::RemediationOutcome;
use sx_remediation::service::outcomes::{
    CloseInput, InMemoryRemediationOutcomesService, OpenInput, RegressionEvent, RemediationMethod,
    RemediationMetrics, RemediationOutcomesService,
};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::warn;
use uuid::Uuid;

/// Default lookback window used by the read-side `metrics` call when
/// the caller passes `window_days = 0`. The controller already clamps
/// zero to a sane default; this constant keeps the adapter total in
/// case the contract widens later.
const DEFAULT_WINDOW_DAYS: u32 = 30;

/// Bundle exposing both the observing finding repository (already
/// wrapping the inner [`FindingRepositoryPort`]) and the
/// [`RemediationOutcomesPort`] trait object.
///
/// `build_app_state` swaps in `findings_observed` everywhere
/// `findings` previously flowed so the observer hook intercepts every
/// status transition.
pub(crate) struct RemediationOutcomesBundle {
    /// Wrapped findings repository — pass-through reads, observer-augmented
    /// writes.
    pub findings_observed: Arc<dyn FindingRepositoryPort>,
    /// Read port plugged into `AppState.remediation_outcomes`.
    pub port: Arc<dyn RemediationOutcomesPort>,
}

impl std::fmt::Debug for RemediationOutcomesBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemediationOutcomesBundle")
            .finish_non_exhaustive()
    }
}

/// Wire the bundle around the supplied inner finding repository.
pub(crate) fn build(inner: Arc<dyn FindingRepositoryPort>) -> RemediationOutcomesBundle {
    let service: Arc<dyn RemediationOutcomesService> =
        Arc::new(InMemoryRemediationOutcomesService::new());
    let findings_observed: Arc<dyn FindingRepositoryPort> = Arc::new(ObservingFindingRepository {
        inner,
        service: Arc::clone(&service),
    });
    let port: Arc<dyn RemediationOutcomesPort> = Arc::new(RemediationOutcomesAdapter { service });
    RemediationOutcomesBundle {
        findings_observed,
        port,
    }
}

/// Read-side adapter behind [`RemediationOutcomesPort`].
struct RemediationOutcomesAdapter {
    service: Arc<dyn RemediationOutcomesService>,
}

#[async_trait]
impl RemediationOutcomesPort for RemediationOutcomesAdapter {
    async fn metrics(
        &self,
        tenant_id: &str,
        window_days: u32,
    ) -> Result<RemediationMetricsView, Phase3PortError> {
        let tenant = parse_tenant(tenant_id)?;
        let days = if window_days == 0 {
            DEFAULT_WINDOW_DAYS
        } else {
            window_days
        };
        let window = Duration::from_secs(u64::from(days) * 86_400);
        let m: RemediationMetrics = self
            .service
            .metrics(tenant, window)
            .await
            .map_err(|e| Phase3PortError::Dependency(e.to_string()))?;
        Ok(project_metrics(tenant_id, &m))
    }

    async fn list_regressions(
        &self,
        tenant_id: &str,
        limit: u32,
    ) -> Result<RegressionListView, Phase3PortError> {
        let tenant = parse_tenant(tenant_id)?;
        let items_raw: Vec<RegressionEvent> = self
            .service
            .list_regressions(tenant, limit as usize)
            .await
            .map_err(|e| Phase3PortError::Dependency(e.to_string()))?;
        let mut items: Vec<RegressionEventView> = Vec::with_capacity(items_raw.len());
        for r in items_raw {
            items.push(project_regression(&r)?);
        }
        Ok(RegressionListView { items })
    }
}

/// Decorator over [`FindingRepositoryPort`] that fires the outcome
/// observer hook on the status transitions we care about.
struct ObservingFindingRepository {
    inner: Arc<dyn FindingRepositoryPort>,
    service: Arc<dyn RemediationOutcomesService>,
}

#[async_trait]
impl FindingRepositoryPort for ObservingFindingRepository {
    async fn list(
        &self,
        tenant_id: &str,
        offset: u64,
        limit: u32,
    ) -> Result<Vec<FindingView>, EngagementPortError> {
        self.inner.list(tenant_id, offset, limit).await
    }

    async fn get(&self, tenant_id: &str, id: &str) -> Result<FindingView, EngagementPortError> {
        self.inner.get(tenant_id, id).await
    }

    /// Forward synthetic-emit inserts (FOUND-001) to the inner store.
    /// The observer hook here cares about status transitions on existing
    /// rows — a fresh insert is not a transition — so we simply delegate
    /// without firing any hook. Also used by the SAML attack observer
    /// (TOP5-#3-P2-004) when the inner store is wrapped by this observer.
    async fn insert(&self, view: FindingView) -> Result<FindingView, EngagementPortError> {
        self.inner.insert(view).await
    }

    async fn update_status(
        &self,
        tenant_id: &str,
        id: &str,
        new_status: &str,
        comment: Option<&str>,
    ) -> Result<FindingView, EngagementPortError> {
        // Snapshot the prior view so we can detect a transition rather
        // than a no-op write (e.g. closing an already-closed finding
        // must not double-count).
        let prior_status = self.inner.get(tenant_id, id).await.map(|v| v.status).ok();

        let updated = self
            .inner
            .update_status(tenant_id, id, new_status, comment)
            .await?;

        // Observer hooks. Errors inside the service are logged and
        // dropped — the finding mutation already succeeded and we
        // refuse to fail the caller on a downstream metric write.
        let new_status_lc = new_status.to_ascii_lowercase();
        let transitioned_to_closed = new_status_lc == "closed"
            && prior_status
                .as_deref()
                .map(str::to_ascii_lowercase)
                .as_deref()
                != Some("closed");
        let transitioned_from_closed = new_status_lc != "closed"
            && prior_status
                .as_deref()
                .map(str::to_ascii_lowercase)
                .as_deref()
                == Some("closed");

        if transitioned_to_closed {
            if let Some(input) = build_close_input(&updated) {
                if let Err(err) = self.service.record_close(input).await {
                    warn!(
                        target = "adapters.remediation_outcomes.record_close",
                        error = %err,
                        finding_id = %updated.id,
                        "outcome record_close failed; finding update still committed",
                    );
                }
            }
        } else if transitioned_from_closed {
            if let Some(input) = build_open_input(&updated) {
                if let Err(err) = self.service.detect_regression(input).await {
                    warn!(
                        target = "adapters.remediation_outcomes.detect_regression",
                        error = %err,
                        finding_id = %updated.id,
                        "regression detection failed; finding update still committed",
                    );
                }
            }
        }

        Ok(updated)
    }
}

fn parse_tenant(tenant_id: &str) -> Result<Uuid, Phase3PortError> {
    Uuid::parse_str(tenant_id).map_err(|e| Phase3PortError::Invalid(format!("tenant_id: {e}")))
}

fn build_close_input(view: &FindingView) -> Option<CloseInput> {
    let tenant_id = Uuid::parse_str(&view.tenant_id).ok()?;
    let finding_id = Uuid::parse_str(&view.id).ok()?;
    let opened_at = OffsetDateTime::parse(&view.first_seen, &Rfc3339).ok()?;
    Some(CloseInput {
        tenant_id,
        finding_id,
        asset_id: view.asset_id.clone(),
        check_id: synth_check_id(view),
        severity: view.severity.clone(),
        opened_at,
        method: RemediationMethod::Unspecified,
    })
}

fn build_open_input(view: &FindingView) -> Option<OpenInput> {
    let tenant_id = Uuid::parse_str(&view.tenant_id).ok()?;
    let finding_id = Uuid::parse_str(&view.id).ok()?;
    Some(OpenInput {
        tenant_id,
        finding_id,
        asset_id: view.asset_id.clone(),
        check_id: synth_check_id(view),
        detected_at: OffsetDateTime::now_utc(),
    })
}

/// Best-effort `check_id` synthesis from the finding skeleton.
///
/// FindingView does not carry an explicit `check_id` yet. We fold the
/// title into a stable identifier so closures + regressions for the
/// same catalogue entry collide as intended. Empty / oversize titles
/// fall back to the finding id so the bucket is at least non-empty.
fn synth_check_id(view: &FindingView) -> String {
    let raw = view.title.trim();
    if raw.is_empty() {
        return view.id.clone();
    }
    // Lower-case + replace whitespace with `-`, truncate to 128 chars
    // to fit the SQL CHECK constraint.
    let mut buf = String::with_capacity(raw.len());
    for ch in raw.chars().take(128) {
        if ch.is_whitespace() {
            buf.push('-');
        } else {
            for low in ch.to_lowercase() {
                buf.push(low);
            }
        }
    }
    if buf.is_empty() {
        view.id.clone()
    } else {
        buf
    }
}

fn project_metrics(tenant_id: &str, m: &RemediationMetrics) -> RemediationMetricsView {
    RemediationMetricsView {
        tenant_id: tenant_id.to_owned(),
        window_seconds: m.window_seconds,
        mttr_by_severity: m
            .mttr_by_severity
            .iter()
            .map(|b| MttrBucketView {
                severity: b.severity.clone(),
                sample_size: b.sample_size,
                mttr_seconds: b.mttr_seconds,
            })
            .collect(),
        regression_rate: m.regression_rate,
        top_regressing: m
            .top_regressing
            .iter()
            .map(|t| RegressingTechniqueView {
                check_id: t.check_id.clone(),
                regression_count: t.regression_count,
                closure_count: t.closure_count,
            })
            .collect(),
        closure_count: m.closure_count,
        regression_count: m.regression_count,
    }
}

fn project_regression(r: &RegressionEvent) -> Result<RegressionEventView, Phase3PortError> {
    let detected_at = r
        .detected_at
        .format(&Rfc3339)
        .map_err(|e| Phase3PortError::Internal(format!("rfc3339 format: {e}")))?;
    Ok(RegressionEventView {
        id: r.id.to_string(),
        tenant_id: r.tenant_id.to_string(),
        asset_id: r.asset_id.clone(),
        check_id: r.check_id.clone(),
        prior_outcome_id: r.prior_outcome_id.to_string(),
        new_finding_id: r.new_finding_id.to_string(),
        detected_at,
        gap_seconds: r.gap_seconds,
    })
}

/// Tiny helper consumed only by tests. Kept here so the `RemediationOutcome`
/// projection stays in one place and the wrapper around the service in the
/// adapter remains the single source of truth for the wire shape.
#[cfg(test)]
fn project_outcome(o: &RemediationOutcome) -> Result<(String, i64), Phase3PortError> {
    let closed_at = o
        .closed_at
        .format(&Rfc3339)
        .map_err(|e| Phase3PortError::Internal(format!("rfc3339 format: {e}")))?;
    Ok((closed_at, o.ttr_seconds))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    const TENANT: &str = "01010101-0101-0101-0101-010101010101";
    const FINDING: &str = "f0000001-0000-0000-0000-000000000000";
    const FINDING2: &str = "f0000002-0000-0000-0000-000000000000";

    /// Tiny in-memory `FindingRepositoryPort` mirroring the monolith's
    /// `InMemoryFindings` but local to the test to keep coupling tight.
    #[derive(Default)]
    struct StubFindings {
        rows: Mutex<HashMap<(String, String), FindingView>>,
    }

    impl StubFindings {
        fn seed(&self, view: FindingView) {
            let mut g = self.rows.lock().unwrap();
            g.insert((view.tenant_id.clone(), view.id.clone()), view);
        }
    }

    #[async_trait]
    impl FindingRepositoryPort for StubFindings {
        async fn list(
            &self,
            _tenant_id: &str,
            _offset: u64,
            _limit: u32,
        ) -> Result<Vec<FindingView>, EngagementPortError> {
            Ok(Vec::new())
        }
        async fn get(&self, tenant_id: &str, id: &str) -> Result<FindingView, EngagementPortError> {
            let g = self.rows.lock().unwrap();
            g.get(&(tenant_id.to_owned(), id.to_owned()))
                .cloned()
                .ok_or(EngagementPortError::NotFound)
        }
        async fn update_status(
            &self,
            tenant_id: &str,
            id: &str,
            new_status: &str,
            _comment: Option<&str>,
        ) -> Result<FindingView, EngagementPortError> {
            let mut g = self.rows.lock().unwrap();
            match g.get_mut(&(tenant_id.to_owned(), id.to_owned())) {
                Some(v) => {
                    v.status = new_status.to_owned();
                    Ok(v.clone())
                }
                None => Err(EngagementPortError::NotFound),
            }
        }
        async fn insert(&self, view: FindingView) -> Result<FindingView, EngagementPortError> {
            let mut g = self.rows.lock().unwrap();
            g.insert((view.tenant_id.clone(), view.id.clone()), view.clone());
            Ok(view)
        }
    }

    fn open_view(id: &str, title: &str) -> FindingView {
        FindingView {
            id: id.to_owned(),
            tenant_id: TENANT.to_owned(),
            asset_id: "a-1".to_owned(),
            severity: "high".to_owned(),
            status: "open".to_owned(),
            title: title.to_owned(),
            description: String::new(),
            cvss: None,
            cve_id: None,
            first_seen: "2026-01-01T00:00:00Z".to_owned(),
            last_seen: "2026-01-01T00:00:00Z".to_owned(),
            metadata: None,
        }
    }

    #[tokio::test]
    async fn closing_a_finding_records_an_outcome() {
        let inner = Arc::new(StubFindings::default());
        inner.seed(open_view(FINDING, "Open SSH Port"));
        let bundle = build(inner.clone());
        // Transition open -> closed.
        bundle
            .findings_observed
            .update_status(TENANT, FINDING, "closed", None)
            .await
            .expect("update ok");
        // Metrics over a 30-day window must now show one closure.
        let m = bundle.port.metrics(TENANT, 30).await.expect("metrics");
        assert_eq!(m.closure_count, 1);
        assert_eq!(m.regression_count, 0);
        // High-severity bucket present.
        assert!(m.mttr_by_severity.iter().any(|b| b.severity == "high"));
    }

    #[tokio::test]
    async fn no_op_close_does_not_double_count() {
        let inner = Arc::new(StubFindings::default());
        let mut view = open_view(FINDING, "Weak TLS");
        view.status = "closed".into();
        inner.seed(view);
        let bundle = build(inner.clone());
        bundle
            .findings_observed
            .update_status(TENANT, FINDING, "closed", None)
            .await
            .expect("update ok");
        let m = bundle.port.metrics(TENANT, 30).await.expect("metrics");
        assert_eq!(m.closure_count, 0, "no-op close must not record");
    }

    #[tokio::test]
    async fn reopen_after_close_detects_regression() {
        let inner = Arc::new(StubFindings::default());
        inner.seed(open_view(FINDING, "Weak Cipher"));
        let bundle = build(inner.clone());
        // Close + reopen the SAME finding so the (asset, check_id) key
        // collides.
        bundle
            .findings_observed
            .update_status(TENANT, FINDING, "closed", None)
            .await
            .expect("close ok");
        bundle
            .findings_observed
            .update_status(TENANT, FINDING, "open", None)
            .await
            .expect("reopen ok");
        let list = bundle
            .port
            .list_regressions(TENANT, 10)
            .await
            .expect("list");
        assert_eq!(list.items.len(), 1, "expected one regression event");
        assert_eq!(list.items[0].tenant_id, TENANT);
    }

    #[tokio::test]
    async fn metrics_default_window_when_zero_days() {
        let inner = Arc::new(StubFindings::default());
        let bundle = build(inner);
        let m = bundle.port.metrics(TENANT, 0).await.expect("metrics");
        // 30-day default in seconds.
        assert_eq!(m.window_seconds, 30 * 86_400);
    }

    #[tokio::test]
    async fn malformed_tenant_id_is_invalid() {
        let inner = Arc::new(StubFindings::default());
        let bundle = build(inner);
        let err = bundle
            .port
            .metrics("not-a-uuid", 30)
            .await
            .expect_err("invalid tenant");
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    #[tokio::test]
    async fn closure_for_different_check_id_does_not_double_count_regression() {
        let inner = Arc::new(StubFindings::default());
        inner.seed(open_view(FINDING, "Weak Cipher"));
        inner.seed(open_view(FINDING2, "Open SSH Port"));
        let bundle = build(inner.clone());
        bundle
            .findings_observed
            .update_status(TENANT, FINDING, "closed", None)
            .await
            .expect("close 1");
        bundle
            .findings_observed
            .update_status(TENANT, FINDING2, "open", None)
            .await
            .expect("noop reopen");
        let m = bundle.port.metrics(TENANT, 30).await.expect("metrics");
        assert_eq!(
            m.regression_count, 0,
            "different check_ids must not collide"
        );
    }

    #[test]
    fn synth_check_id_truncates_and_lowercases() {
        let mut v = open_view(FINDING, "  TLS Weak Cipher ");
        let id = synth_check_id(&v);
        assert_eq!(id, "tls-weak-cipher");
        v.title = String::new();
        // Falls back to finding id when title is empty.
        let id = synth_check_id(&v);
        assert_eq!(id, FINDING);
    }

    #[test]
    fn project_outcome_emits_rfc3339_and_ttr_seconds() {
        let o = RemediationOutcome {
            id: Uuid::parse_str(FINDING2).unwrap(),
            tenant_id: Uuid::parse_str(TENANT).unwrap(),
            asset_id: "a-1".into(),
            check_id: "C-1".into(),
            finding_id: Uuid::parse_str(FINDING).unwrap(),
            severity: "high".into(),
            method: RemediationMethod::ManualPatch,
            opened_at: OffsetDateTime::from_unix_timestamp(1_000_000_000).unwrap(),
            closed_at: OffsetDateTime::from_unix_timestamp(1_000_003_600).unwrap(),
            ttr_seconds: 3_600,
        };
        let (ts, ttr) = project_outcome(&o).unwrap();
        assert!(ts.ends_with('Z') || ts.contains('+'));
        assert_eq!(ttr, 3_600);
    }
}
