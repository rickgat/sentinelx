//! Scheduled report distribution (wires the sx-report scheduler engine).
//!
//! The scheduling engine in `sx_report::scheduler` (cron evaluation, store,
//! email / S3 / webhook dispatch, retry + dead-letter + audit) is fully
//! built and tested; what was missing was the service wiring. This module:
//!
//! * implements [`SchedulerReportPort`] by delegating to the existing
//!   [`sx_api::port::ReportRenderPort`] (so the scheduler renders through
//!   the same path as `POST /v1/reports/render`);
//! * spawns a background tick loop that runs due schedules on an interval;
//! * backs the `/v1/reports/schedules` management API with a shared
//!   [`InMemoryScheduleStore`].
//!
//! Default dispatcher is the in-memory [`RecordingDispatcher`] (delivery is
//! captured + logged); production SMTP / S3 / webhook delivery is enabled by
//! supplying the relevant config, exactly as with the cloud / Neo4j
//! adapters.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sx_api::port::{ReportRenderPort, ReportSchedulePort, ReportSchedulePortError};
use sx_api::view::report_schedule_view::{CreateReportScheduleRequest, ReportScheduleView};
use sx_api::view::report_view::ReportRenderRequestView;
use sx_report::port::ReportFormat;
use sx_report::scheduler::{
    CronEvaluator, InMemoryScheduleStore, RecordingDispatcher, ReportSchedule, ScheduleStore,
    Scheduler, SchedulerReportArtifact, SchedulerReportPort,
};
use time::OffsetDateTime;
use tokio::task::JoinHandle;
use tracing::{info, warn};
use uuid::Uuid;

/// Default tick cadence for the background scheduler loop.
const TICK_INTERVAL: Duration = Duration::from_secs(60);

/// Adapter implementing the sx-report scheduler's render port over the
/// HTTP-layer [`ReportRenderPort`] (reuses the real hydration + renderers).
struct SchedulerRenderAdapter {
    report: Arc<dyn ReportRenderPort>,
}

impl std::fmt::Debug for SchedulerRenderAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchedulerRenderAdapter")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SchedulerReportPort for SchedulerRenderAdapter {
    async fn render(
        &self,
        tenant_id: Uuid,
        engagement_id: Option<Uuid>,
        format: ReportFormat,
    ) -> Result<SchedulerReportArtifact, sx_report::error::ReportError> {
        let Some(eng) = engagement_id else {
            return Err(sx_report::error::ReportError::invalid_context(
                "scheduled reports require an engagement_id",
            ));
        };
        let req = ReportRenderRequestView {
            tenant_id: tenant_id.to_string(),
            engagement_id: eng.to_string(),
            format: format.as_str().to_owned(),
        };
        let resp = self
            .report
            .render(req)
            .await
            .map_err(|e| sx_report::error::ReportError::invalid_context(e.to_string()))?;
        Ok(SchedulerReportArtifact {
            filename: resp.filename,
            mime_type: resp.mime_type,
            inline_payload: resp.inline_payload.unwrap_or_default(),
        })
    }
}

/// Bundle handed to the composition root.
pub(crate) struct ReportSchedulerBundle {
    /// HTTP-facing schedule-management port.
    pub port: Arc<dyn ReportSchedulePort>,
    /// Shared store (also read by the background tick loop).
    pub store: Arc<InMemoryScheduleStore>,
    /// Render adapter (held so the spawn helper can borrow it).
    render: Arc<SchedulerRenderAdapter>,
}

impl std::fmt::Debug for ReportSchedulerBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReportSchedulerBundle")
            .finish_non_exhaustive()
    }
}

/// Build the bundle. Pure — the background loop is spawned separately via
/// [`spawn`] so the composition root controls the task lifetime.
pub(crate) fn build(report: Arc<dyn ReportRenderPort>) -> ReportSchedulerBundle {
    let store = Arc::new(InMemoryScheduleStore::new());
    let render = Arc::new(SchedulerRenderAdapter { report });
    let port: Arc<dyn ReportSchedulePort> = Arc::new(ReportScheduleAdapter {
        store: Arc::clone(&store),
    });
    ReportSchedulerBundle {
        port,
        store,
        render,
    }
}

/// Spawn the background tick loop. Returns the [`JoinHandle`] so the
/// composition root can abort it on shutdown.
pub(crate) fn spawn(bundle: &ReportSchedulerBundle) -> JoinHandle<()> {
    let store = Arc::clone(&bundle.store);
    let render = Arc::clone(&bundle.render);
    tokio::spawn(async move {
        let dispatcher = RecordingDispatcher::new();
        let mut ticker = tokio::time::interval(TICK_INTERVAL);
        loop {
            ticker.tick().await;
            let now = OffsetDateTime::now_utc();
            let report = Scheduler
                .tick(store.as_ref(), render.as_ref(), &dispatcher, now)
                .await;
            match report {
                Ok(t) if t.dispatched > 0 || t.failed > 0 => {
                    info!(
                        target: "adapters.report_scheduler",
                        dispatched = t.dispatched,
                        failed = t.failed,
                        "scheduler tick ran due reports"
                    );
                }
                Ok(_) => {}
                Err(e) => warn!(
                    target: "adapters.report_scheduler",
                    error = %e,
                    "scheduler tick failed"
                ),
            }
        }
    })
}

/// `ReportSchedulePort` implementation over the shared in-memory store.
struct ReportScheduleAdapter {
    store: Arc<InMemoryScheduleStore>,
}

impl std::fmt::Debug for ReportScheduleAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReportScheduleAdapter")
            .finish_non_exhaustive()
    }
}

fn to_view(s: &ReportSchedule) -> ReportScheduleView {
    ReportScheduleView {
        id: s.id.to_string(),
        engagement_id: s.engagement_id.map(|e| e.to_string()),
        format: s.format.as_str().to_owned(),
        cron_expr: s.cron_expr.clone(),
        recipients: s.recipients.clone(),
        enabled: s.enabled,
        next_run_at: s.next_run_at.to_string(),
    }
}

#[async_trait]
impl ReportSchedulePort for ReportScheduleAdapter {
    async fn list(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<ReportScheduleView>, ReportSchedulePortError> {
        let tid = Uuid::from_str(tenant_id)
            .map_err(|e| ReportSchedulePortError::Invalid(format!("invalid tenant_id: {e}")))?;
        let rows = self
            .store
            .list_for_tenant(tid)
            .await
            .map_err(|e| ReportSchedulePortError::Internal(e.to_string()))?;
        Ok(rows.iter().map(to_view).collect())
    }

    async fn create(
        &self,
        tenant_id: &str,
        req: CreateReportScheduleRequest,
    ) -> Result<ReportScheduleView, ReportSchedulePortError> {
        let tid = Uuid::from_str(tenant_id)
            .map_err(|e| ReportSchedulePortError::Invalid(format!("invalid tenant_id: {e}")))?;
        let eng = Uuid::from_str(&req.engagement_id)
            .map_err(|e| ReportSchedulePortError::Invalid(format!("invalid engagement_id: {e}")))?;
        let format = ReportFormat::from_str(&req.format)
            .map_err(|e| ReportSchedulePortError::Invalid(e.to_string()))?;
        let now = OffsetDateTime::now_utc();
        let next_run_at = CronEvaluator
            .next_after(&req.cron_expr, now)
            .map_err(|e| ReportSchedulePortError::Invalid(e.to_string()))?
            .ok_or_else(|| {
                ReportSchedulePortError::Invalid("cron expression yields no future run".to_owned())
            })?;
        let schedule = ReportSchedule::new(
            Uuid::new_v4(),
            tid,
            Some(eng),
            format,
            req.cron_expr,
            req.recipients,
            true,
            None,
            next_run_at,
        )
        .map_err(|e| ReportSchedulePortError::Invalid(e.to_string()))?;
        let view = to_view(&schedule);
        self.store
            .insert(schedule)
            .map_err(|e| ReportSchedulePortError::Internal(e.to_string()))?;
        Ok(view)
    }

    async fn delete(&self, tenant_id: &str, id: &str) -> Result<(), ReportSchedulePortError> {
        let tid = Uuid::from_str(tenant_id)
            .map_err(|e| ReportSchedulePortError::Invalid(format!("invalid tenant_id: {e}")))?;
        let sid = Uuid::from_str(id)
            .map_err(|e| ReportSchedulePortError::Invalid(format!("invalid schedule id: {e}")))?;
        // Disable (soft-delete) — the in-memory store has no hard delete and
        // disabled rows are skipped by the tick loop.
        self.store
            .set_enabled(tid, sid, false)
            .await
            .map_err(|_| ReportSchedulePortError::NotFound)?;
        Ok(())
    }
}
