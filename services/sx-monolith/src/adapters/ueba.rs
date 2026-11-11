//! UEBA adapter — wires `sx_soc::InMemoryUebaService` behind the
//! [`sx_api::port::UebaPort`] HTTP read trait and exposes the underlying
//! service so the SOC adapter can call `apply` / `check` on every event
//! it accepts.
//!
//! ## Topology
//!
//! ```text
//!     POST /v1/soc/events
//!             │
//!             ▼
//!     ┌──────────────┐
//!     │ SocAdapter   │ ── parses UebaEvent from raw Value, fans out to:
//!     └──────────────┘
//!         │       │
//!         │       ├──► InMemoryUebaService::apply  (fold into baseline)
//!         │       └──► InMemoryUebaService::check  (detect anomaly)
//!         │                  │ if Some(anomaly)
//!         │                  └──► BufferAlertSink::forward (emit SOC alert)
//!         ▼
//!     mpsc::Sender ── existing correlator pipeline
//! ```
//!
//! ## Read path
//!
//! The two `GET /v1/ueba/*` endpoints call into [`UebaAdapter`] which
//! projects [`sx_soc::UebaService`] outputs onto the HTTP view types.

use std::sync::Arc;

use async_trait::async_trait;
use sx_api::port::{UebaAdminPort, UebaAdminPortError, UebaPort, UebaPortError};
use sx_api::view::ueba_admin_view::{
    BaselineStateCode, BaselineStateView as AdminStateView, FrozenSnapshotView,
};
use sx_api::view::ueba_view::{UebaAnomalyDimView, UebaAnomalyView, UebaBaselineView};
use sx_soc::ueba::service::{AnomalyRecord, UebaService};
use sx_soc::{InMemoryUebaService, UebaEvent, UserBehaviorBaseline};
use sx_ueba::{
    BaselineState, BaselineStateView as InnerStateView, FreezeAwareUebaService,
    FreezeAwareUebaServiceImpl, FreezeError,
};
use time::format_description::well_known::Rfc3339;

/// Hard cap the adapter enforces on `list_anomalies(limit)` so callers
/// cannot exhaust memory with a single `?limit=usize::MAX` request.
const ADAPTER_MAX_LIMIT: usize = 1_000;

/// Bundle of UEBA handles handed to the composition root.
///
/// * `service` — the underlying `InMemoryUebaService` (used by the SOC
///   adapter to call `apply` / `check` on every event it ingests).
/// * `port` — the [`UebaPort`] trait object installed onto
///   [`sx_api::AppState`] for read endpoints.
/// * `admin_port` — the [`UebaAdminPort`] trait object backing the
///   HIGH-010 freeze-mode endpoints. Wraps the same in-memory service
///   so freeze decisions are honoured by the SOC ingest path without
///   extra plumbing.
/// * `freeze_aware` — the [`FreezeAwareUebaService`] handle the SOC
///   adapter consults to gate `apply` / `check`. Holds the per-user
///   lifecycle state map.
#[derive(Clone)]
pub(crate) struct UebaBundle {
    /// Shared in-memory service. `Clone` is cheap — it is an `Arc<Mutex<…>>`
    /// internally.
    pub service: InMemoryUebaService,
    /// HTTP read port.
    pub port: Arc<dyn UebaPort>,
    /// HIGH-010 — freeze-mode admin port.
    pub admin_port: Arc<dyn UebaAdminPort>,
    /// HIGH-010 — freeze-aware decorator used by the SOC ingest path so
    /// `apply` / `check` honour the per-user state machine.
    ///
    /// `allow(dead_code)`: the SOC adapter wiring lands in a follow-up
    /// PR (`freeze_aware_dispatch` is exported below); the field is held
    /// today so the composition root can take a `FreezeAwareUebaService`
    /// handle without going through the admin port indirection.
    #[allow(dead_code)]
    pub freeze_aware: Arc<dyn FreezeAwareUebaService>,
}

/// Build the UEBA bundle.
pub(crate) fn build() -> UebaBundle {
    let service = InMemoryUebaService::new();
    let port: Arc<dyn UebaPort> = Arc::new(UebaAdapter {
        svc: service.clone(),
    });
    let inner_for_freeze: Arc<dyn UebaService> = Arc::new(service.clone());
    let freeze_impl = FreezeAwareUebaServiceImpl::new(inner_for_freeze);
    // Wrap once in `Arc<FreezeAwareUebaServiceImpl>` then erase to two
    // trait-object handles. Both handles share the same per-user state
    // store because `FreezeAwareUebaServiceImpl::Clone` is shallow over
    // the inner Arc fields.
    let freeze_impl_arc = Arc::new(freeze_impl);
    let freeze_aware: Arc<dyn FreezeAwareUebaService> = freeze_impl_arc.clone();
    let admin_port: Arc<dyn UebaAdminPort> = Arc::new(UebaAdminAdapter {
        svc: freeze_impl_arc,
    });
    UebaBundle {
        service,
        port,
        admin_port,
        freeze_aware,
    }
}

/// HTTP-facing adapter — projects in-process types onto wire DTOs.
#[derive(Clone)]
pub(crate) struct UebaAdapter {
    svc: InMemoryUebaService,
}

impl std::fmt::Debug for UebaAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UebaAdapter").finish_non_exhaustive()
    }
}

#[async_trait]
impl UebaPort for UebaAdapter {
    async fn get_baseline(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<UebaBaselineView, UebaPortError> {
        if tenant_id.is_empty() {
            return Err(UebaPortError::Invalid("tenant_id is empty".into()));
        }
        if user_id.is_empty() {
            return Err(UebaPortError::Invalid("user_id is empty".into()));
        }
        let baseline = self
            .svc
            .get_baseline(Some(tenant_id), user_id)
            .await
            .ok_or(UebaPortError::NotFound)?;
        Ok(project_baseline(&baseline))
    }

    async fn list_anomalies(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<UebaAnomalyView>, UebaPortError> {
        if tenant_id.is_empty() {
            return Err(UebaPortError::Invalid("tenant_id is empty".into()));
        }
        let clamped = limit.min(ADAPTER_MAX_LIMIT);
        let rows = self.svc.list_anomalies(Some(tenant_id), clamped).await;
        Ok(rows.iter().map(project_anomaly).collect())
    }
}

/// Project a [`UserBehaviorBaseline`] onto the wire DTO.
fn project_baseline(b: &UserBehaviorBaseline) -> UebaBaselineView {
    UebaBaselineView {
        tenant_id: b.tenant_id.clone(),
        user_id: b.user_id.clone(),
        login_hour_counts: b.login_hours_histogram.to_vec(),
        ip_prefixes: b.ip_prefixes.clone(),
        accessed_assets: b.accessed_assets.clone(),
        updated_at: b.updated_at.and_then(|t| t.format(&Rfc3339).ok()),
    }
}

/// Project an [`AnomalyRecord`] onto the wire DTO.
fn project_anomaly(rec: &AnomalyRecord) -> UebaAnomalyView {
    UebaAnomalyView {
        id: rec.id.clone(),
        tenant_id: rec.tenant_id.clone(),
        user_id: rec.user_id.clone(),
        event_id: rec.event_id.clone(),
        score: rec.anomaly.score,
        dimensions: rec
            .anomaly
            .dimensions
            .iter()
            .map(|d| UebaAnomalyDimView {
                dimension: d.dimension.clone(),
                score: d.score,
                reason: d.reason.clone(),
            })
            .collect(),
        severity: rec.anomaly.severity.as_str().to_owned(),
        detected_at: rec
            .detected_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z")),
    }
}

// ---------------------------------------------------------------------------
// HIGH-010 — UEBA admin (freeze-mode) adapter
// ---------------------------------------------------------------------------

/// Admin adapter — projects [`FreezeAwareUebaService`] errors onto
/// [`UebaAdminPortError`] and the internal [`BaselineStateView`](sx_ueba::BaselineStateView)
/// onto the HTTP wire DTO.
#[derive(Clone)]
pub(crate) struct UebaAdminAdapter {
    svc: Arc<FreezeAwareUebaServiceImpl>,
}

impl std::fmt::Debug for UebaAdminAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UebaAdminAdapter").finish_non_exhaustive()
    }
}

#[async_trait]
impl UebaAdminPort for UebaAdminAdapter {
    async fn freeze(
        &self,
        tenant_id: &str,
        user_id: &str,
        actor: Option<&str>,
        reason: Option<&str>,
    ) -> Result<AdminStateView, UebaAdminPortError> {
        let view = self
            .svc
            .freeze(tenant_id, user_id, actor, reason)
            .await
            .map_err(map_freeze_error)?;
        Ok(project_state_view(view))
    }

    async fn unfreeze(
        &self,
        tenant_id: &str,
        user_id: &str,
        actor: Option<&str>,
        reason: Option<&str>,
    ) -> Result<AdminStateView, UebaAdminPortError> {
        let view = self
            .svc
            .unfreeze(tenant_id, user_id, actor, reason)
            .await
            .map_err(map_freeze_error)?;
        Ok(project_state_view(view))
    }

    async fn snapshot(
        &self,
        tenant_id: &str,
        user_id: &str,
    ) -> Result<AdminStateView, UebaAdminPortError> {
        let view = self
            .svc
            .snapshot(tenant_id, user_id)
            .await
            .map_err(map_freeze_error)?;
        Ok(project_state_view(view))
    }
}

/// Translate `FreezeError` → `UebaAdminPortError`.
fn map_freeze_error(err: FreezeError) -> UebaAdminPortError {
    match err {
        FreezeError::NoBaseline { .. } => UebaAdminPortError::NotFound,
        FreezeError::InvalidTransition { detail, .. } => {
            UebaAdminPortError::InvalidTransition(detail)
        }
        FreezeError::Invalid(m) => UebaAdminPortError::Invalid(m),
    }
}

/// Translate the inner `BaselineStateView` onto the HTTP wire shape.
fn project_state_view(view: InnerStateView) -> AdminStateView {
    let state = match view.state {
        BaselineState::Learning => BaselineStateCode::Learning,
        BaselineState::Active => BaselineStateCode::Active,
        BaselineState::Frozen => BaselineStateCode::Frozen,
    };
    AdminStateView {
        tenant_id: view.tenant_id,
        user_id: view.user_id,
        state,
        snapshot: view.snapshot.map(|s| FrozenSnapshotView {
            login_hour_counts: s.login_hour_counts,
            ip_prefixes: s.ip_prefixes,
            accessed_assets: s.accessed_assets,
            frozen_at: s.frozen_at,
        }),
    }
}

/// Convenience: route a `UebaEvent` through the freeze-aware service.
/// Exposed so the SOC adapter (which owns the event ingest pipeline) can
/// call freeze-aware `check` / `apply` without re-implementing the gating.
#[allow(dead_code)] // wired in a follow-up SOC-adapter PR; preserved here
                    // so the freeze-aware bundle is fully usable today.
pub(crate) async fn freeze_aware_dispatch(
    fa: &Arc<dyn FreezeAwareUebaService>,
    event: &UebaEvent,
) -> Option<AnomalyRecord> {
    let anomaly = fa.check(event).await;
    fa.apply(event.clone()).await;
    anomaly
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sx_soc::UebaEvent;
    use time::macros::datetime;

    #[tokio::test]
    async fn get_baseline_returns_not_found_for_unknown_user() {
        let bundle = build();
        let err = bundle
            .port
            .get_baseline("t-1", "ghost")
            .await
            .expect_err("should be NotFound");
        assert!(matches!(err, UebaPortError::NotFound));
    }

    #[tokio::test]
    async fn get_baseline_returns_view_after_apply() {
        let bundle = build();
        let mut evt = UebaEvent::new("alice", datetime!(2027-01-01 9:00:00 UTC));
        evt.tenant_id = Some("t-1".into());
        evt.event_id = Some("e1".into());
        evt.source_ip = Some("10.20.30.40".into());
        bundle.service.apply(evt).await;
        let view = bundle
            .port
            .get_baseline("t-1", "alice")
            .await
            .expect("should be found");
        assert_eq!(view.user_id, "alice");
        assert_eq!(view.login_hour_counts.len(), 24);
        assert_eq!(view.login_hour_counts[9], 1);
        assert!(view.ip_prefixes.contains_key("10.20.0.0/16"));
    }

    #[tokio::test]
    async fn list_anomalies_clamps_to_adapter_max() {
        let bundle = build();
        // Seed one anomaly so the projection path is exercised.
        let mut evt = UebaEvent::new("alice", datetime!(2027-01-01 9:00:00 UTC));
        evt.tenant_id = Some("t-1".into());
        evt.event_id = Some("e1".into());
        evt.source_ip = Some("198.51.100.1".into());
        let _ = bundle.service.check(&evt).await;
        // limit much larger than ADAPTER_MAX_LIMIT is accepted.
        let rows = bundle
            .port
            .list_anomalies("t-1", usize::MAX)
            .await
            .expect("ok");
        assert!(!rows.is_empty());
        assert!(rows.len() <= ADAPTER_MAX_LIMIT);
    }

    #[tokio::test]
    async fn invalid_tenant_or_user_rejected() {
        let bundle = build();
        assert!(matches!(
            bundle.port.get_baseline("", "alice").await,
            Err(UebaPortError::Invalid(_))
        ));
        assert!(matches!(
            bundle.port.get_baseline("t-1", "").await,
            Err(UebaPortError::Invalid(_))
        ));
        assert!(matches!(
            bundle.port.list_anomalies("", 10).await,
            Err(UebaPortError::Invalid(_))
        ));
    }
}
