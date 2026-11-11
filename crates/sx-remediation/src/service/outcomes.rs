//! Remediation outcome tracking — MTTR, regression detection, metrics
//! aggregation.
//!
//! ## Purpose
//!
//! When a finding moves `open` → `closed` the outcome service stamps the
//! closure with a timestamp and a remediation method. If a fresh finding
//! later appears for the same `(asset_id, check_id)` pair within a
//! configurable window (30 days by default), the service classifies the
//! new finding as a **regression** of the prior closure.
//!
//! Metrics derived from this stream:
//!
//! - **MTTR per severity** — mean time-to-remediate (open → closed),
//!   grouped by the closure's severity bucket.
//! - **Regression rate per `check_id`** — fraction of closures that
//!   re-opened inside the window.
//! - **Top regressing techniques** — `check_id` ordered by regression
//!   count descending.
//!
//! ## Storage
//!
//! [`InMemoryRemediationOutcomesService`] is the dev / demo path: it
//! keeps two [`dashmap::DashMap`]s keyed by
//! `(tenant_id, asset_id, check_id)` — one stack of outcomes per key,
//! one stack of regression events per key. The Postgres-backed
//! implementation lands behind the same trait.
//!
//! ## Concurrency
//!
//! All operations are wait-free at the shard level via `DashMap`. Per-key
//! stacks are append-only so a writer never blocks a reader for very long.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::RemediationError;

/// Default lookback window for regression detection — 30 days.
pub const DEFAULT_REGRESSION_WINDOW: Duration = Duration::from_secs(60 * 60 * 24 * 30);

/// How a finding was driven to closure.
///
/// Strings on the wire are kebab-case so JSON callers can construct
/// values without an enum. The `as_str` lifecycle is stable across
/// versions — schema migrations append new variants but never rename
/// existing ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RemediationMethod {
    /// Operator approved an autonomy-generated patch / PR.
    AutoPatch,
    /// Operator manually patched the asset out-of-band.
    ManualPatch,
    /// Risk accepted by the tenant (compensating controls, business
    /// override).
    RiskAccepted,
    /// Closed as false-positive after triage.
    FalsePositive,
    /// Mitigated by a configuration change (firewall rule, role tweak).
    ConfigChange,
    /// Closure recorded without a categorised method — defaults when
    /// callers don't tag.
    Unspecified,
}

impl RemediationMethod {
    /// Stable wire string. Used by the SQL layer column.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AutoPatch => "auto-patch",
            Self::ManualPatch => "manual-patch",
            Self::RiskAccepted => "risk-accepted",
            Self::FalsePositive => "false-positive",
            Self::ConfigChange => "config-change",
            Self::Unspecified => "unspecified",
        }
    }

    /// Parse a wire string into a method.
    ///
    /// Unknown values map to [`Self::Unspecified`] — the operator's audit
    /// trail still reflects the original input via the storage layer.
    #[must_use]
    pub fn parse(value: &str) -> Self {
        match value {
            "auto-patch" => Self::AutoPatch,
            "manual-patch" => Self::ManualPatch,
            "risk-accepted" => Self::RiskAccepted,
            "false-positive" => Self::FalsePositive,
            "config-change" => Self::ConfigChange,
            _ => Self::Unspecified,
        }
    }
}

/// A single closed-finding record. Open → closed transitions append one
/// of these.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationOutcome {
    /// Stable id for the outcome row (uuid v7).
    pub id: Uuid,
    /// Tenant the closure belongs to.
    pub tenant_id: Uuid,
    /// Asset the closure was recorded against.
    pub asset_id: String,
    /// Check / technique identifier (`check_id` from the scanner, MITRE
    /// technique id from BAS, etc).
    pub check_id: String,
    /// Finding id that closed.
    pub finding_id: Uuid,
    /// Severity at the moment of closure (`info`/`low`/`medium`/`high`/
    /// `critical`).
    pub severity: String,
    /// How the closure was driven.
    pub method: RemediationMethod,
    /// First-seen timestamp of the finding — used to compute TTR.
    pub opened_at: OffsetDateTime,
    /// Closure timestamp.
    pub closed_at: OffsetDateTime,
    /// Wall-clock time-to-remediate in whole seconds. Bounded by the
    /// signed-i64 range of `BIGINT` so the SQL layer never silently
    /// truncates.
    pub ttr_seconds: i64,
}

/// A regression detection — a new finding for an `(asset_id, check_id)`
/// that previously had a recorded closure inside the window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionEvent {
    /// Stable id for the regression row (uuid v7).
    pub id: Uuid,
    /// Tenant the regression belongs to.
    pub tenant_id: Uuid,
    /// Asset the regression was recorded against.
    pub asset_id: String,
    /// Check / technique identifier that reappeared.
    pub check_id: String,
    /// Outcome row id that this regression supersedes.
    pub prior_outcome_id: Uuid,
    /// Finding id that opened (the new occurrence).
    pub new_finding_id: Uuid,
    /// When the regression was detected.
    pub detected_at: OffsetDateTime,
    /// Time delta between the prior closure and the new finding, in
    /// whole seconds.
    pub gap_seconds: i64,
}

/// Per-severity MTTR aggregate.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MttrBucket {
    /// Severity label (`info`/`low`/`medium`/`high`/`critical`).
    pub severity: String,
    /// Number of closures that contributed to the mean.
    pub sample_size: u64,
    /// Mean time-to-remediate in seconds. `0` when `sample_size == 0`.
    pub mttr_seconds: i64,
}

/// Per-`check_id` regression count.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegressingTechnique {
    /// `check_id` that regressed.
    pub check_id: String,
    /// Number of regression events observed for this `check_id` inside
    /// the metrics window.
    pub regression_count: u64,
    /// Number of closures observed for this `check_id` inside the
    /// metrics window.
    pub closure_count: u64,
}

/// Top-level metrics envelope returned by [`RemediationOutcomesService::metrics`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemediationMetrics {
    /// Tenant the snapshot belongs to.
    pub tenant_id: Uuid,
    /// Window the snapshot covers, in whole seconds.
    pub window_seconds: i64,
    /// MTTR aggregates ordered by severity (critical → info).
    pub mttr_by_severity: Vec<MttrBucket>,
    /// Total closures vs total regressions in the window — top-level
    /// regression rate is `regressions / max(closures, 1)`.
    pub regression_rate: f64,
    /// Top regressing `check_id` ordered by `regression_count`
    /// descending, capped at [`TOP_REGRESSING_LIMIT`].
    pub top_regressing: Vec<RegressingTechnique>,
    /// Closure count that fed `regression_rate` — kept for explicit UI
    /// rendering.
    pub closure_count: u64,
    /// Regression count that fed `regression_rate`.
    pub regression_count: u64,
}

/// Maximum number of top-regressing entries returned in metrics.
pub const TOP_REGRESSING_LIMIT: usize = 10;

/// Skeleton of the finding the caller passes into [`record_close`].
#[derive(Debug, Clone)]
pub struct CloseInput {
    /// Tenant id the finding belongs to.
    pub tenant_id: Uuid,
    /// Finding id moving to `closed`.
    pub finding_id: Uuid,
    /// Asset id the finding is bound to.
    pub asset_id: String,
    /// Check / technique identifier.
    pub check_id: String,
    /// Severity captured at closure.
    pub severity: String,
    /// First-seen timestamp — used to compute TTR.
    pub opened_at: OffsetDateTime,
    /// Operator-supplied remediation method.
    pub method: RemediationMethod,
}

/// Skeleton of the finding the caller passes into
/// [`detect_regression`].
#[derive(Debug, Clone)]
pub struct OpenInput {
    /// Tenant id the finding belongs to.
    pub tenant_id: Uuid,
    /// Finding id that was just created.
    pub finding_id: Uuid,
    /// Asset id the finding is bound to.
    pub asset_id: String,
    /// Check / technique identifier.
    pub check_id: String,
    /// Detection timestamp (typically `now`).
    pub detected_at: OffsetDateTime,
}

/// Service contract — the API + composition root only ever sees this
/// trait.
#[async_trait]
pub trait RemediationOutcomesService: Send + Sync {
    /// Record a finding closure. Returns the persisted outcome row.
    ///
    /// # Errors
    /// [`RemediationError::Internal`] when the underlying store fails.
    async fn record_close(&self, input: CloseInput)
        -> Result<RemediationOutcome, RemediationError>;

    /// Detect a regression for a newly opened finding.
    ///
    /// Returns `Ok(Some(_))` when a prior closure for the same
    /// `(asset_id, check_id)` exists inside the configured window.
    /// Returns `Ok(None)` when no regression is detected.
    ///
    /// # Errors
    /// [`RemediationError::Internal`] when the underlying store fails.
    async fn detect_regression(
        &self,
        input: OpenInput,
    ) -> Result<Option<RegressionEvent>, RemediationError>;

    /// Aggregate metrics for the tenant over the supplied window.
    ///
    /// # Errors
    /// [`RemediationError::Internal`] when the underlying store fails.
    async fn metrics(
        &self,
        tenant_id: Uuid,
        window: Duration,
    ) -> Result<RemediationMetrics, RemediationError>;

    /// List regression events for the tenant, newest-first, capped at
    /// `limit`.
    ///
    /// # Errors
    /// [`RemediationError::Internal`] when the underlying store fails.
    async fn list_regressions(
        &self,
        tenant_id: Uuid,
        limit: usize,
    ) -> Result<Vec<RegressionEvent>, RemediationError>;
}

/// In-memory implementation suitable for dev / demo / unit tests.
///
/// Two `DashMap`s back the state — one per outcome history, one per
/// regression history. Both are keyed by the canonical
/// `(tenant_id, asset_id, check_id)` triple so cross-tenant accesses
/// cannot collide by construction.
#[derive(Debug, Default)]
pub struct InMemoryRemediationOutcomesService {
    /// Closure stack per `(tenant_id, asset_id, check_id)`.
    outcomes: DashMap<OutcomeKey, Vec<RemediationOutcome>>,
    /// Regression stack per `(tenant_id, asset_id, check_id)`.
    regressions: DashMap<OutcomeKey, Vec<RegressionEvent>>,
    /// Lookback window applied by [`detect_regression`].
    window: Duration,
}

/// Composite key used by both maps.
type OutcomeKey = (Uuid, String, String);

impl InMemoryRemediationOutcomesService {
    /// Build a fresh service with the default 30-day window.
    #[must_use]
    pub fn new() -> Self {
        Self {
            outcomes: DashMap::new(),
            regressions: DashMap::new(),
            window: DEFAULT_REGRESSION_WINDOW,
        }
    }

    /// Build a service with a custom lookback window. Used by tests
    /// that need to exercise the boundary without sleeping for 30 days.
    #[must_use]
    pub fn with_window(window: Duration) -> Self {
        Self {
            outcomes: DashMap::new(),
            regressions: DashMap::new(),
            window,
        }
    }

    /// Wrap as a trait object for the composition root.
    #[must_use]
    pub fn shared(self) -> Arc<dyn RemediationOutcomesService> {
        Arc::new(self)
    }

    fn key(tenant_id: Uuid, asset_id: &str, check_id: &str) -> OutcomeKey {
        (tenant_id, asset_id.to_owned(), check_id.to_owned())
    }

    /// Saturating wall-clock duration to whole seconds. Negative
    /// deltas clamp to 0 so the metric never goes negative when clock
    /// skew is in play.
    fn delta_seconds(later: OffsetDateTime, earlier: OffsetDateTime) -> i64 {
        let delta = later - earlier;
        delta.whole_seconds().max(0)
    }
}

#[async_trait]
impl RemediationOutcomesService for InMemoryRemediationOutcomesService {
    async fn record_close(
        &self,
        input: CloseInput,
    ) -> Result<RemediationOutcome, RemediationError> {
        let closed_at = OffsetDateTime::now_utc();
        let ttr_seconds = Self::delta_seconds(closed_at, input.opened_at);
        let outcome = RemediationOutcome {
            id: Uuid::now_v7(),
            tenant_id: input.tenant_id,
            asset_id: input.asset_id.clone(),
            check_id: input.check_id.clone(),
            finding_id: input.finding_id,
            severity: input.severity,
            method: input.method,
            opened_at: input.opened_at,
            closed_at,
            ttr_seconds,
        };
        let key = Self::key(input.tenant_id, &input.asset_id, &input.check_id);
        self.outcomes.entry(key).or_default().push(outcome.clone());
        Ok(outcome)
    }

    async fn detect_regression(
        &self,
        input: OpenInput,
    ) -> Result<Option<RegressionEvent>, RemediationError> {
        let key = Self::key(input.tenant_id, &input.asset_id, &input.check_id);
        let Some(history) = self.outcomes.get(&key) else {
            return Ok(None);
        };
        let Some(prior) = history.last().cloned() else {
            return Ok(None);
        };
        drop(history);

        let gap_seconds = Self::delta_seconds(input.detected_at, prior.closed_at);
        // Window-bound check: convert window to i64 seconds with
        // saturating semantics so a misconfigured giant window never
        // overflows.
        let window_secs = i64::try_from(self.window.as_secs()).unwrap_or(i64::MAX);
        if gap_seconds > window_secs {
            return Ok(None);
        }

        let event = RegressionEvent {
            id: Uuid::now_v7(),
            tenant_id: input.tenant_id,
            asset_id: input.asset_id.clone(),
            check_id: input.check_id.clone(),
            prior_outcome_id: prior.id,
            new_finding_id: input.finding_id,
            detected_at: input.detected_at,
            gap_seconds,
        };
        self.regressions.entry(key).or_default().push(event.clone());
        Ok(Some(event))
    }

    async fn metrics(
        &self,
        tenant_id: Uuid,
        window: Duration,
    ) -> Result<RemediationMetrics, RemediationError> {
        let now = OffsetDateTime::now_utc();
        let window_secs = i64::try_from(window.as_secs()).unwrap_or(i64::MAX);
        let horizon = now - time::Duration::seconds(window_secs);

        // Collect every outcome and regression that falls inside the
        // window AND belongs to the tenant. Stacks are append-only so a
        // snapshot iterator is sufficient.
        let mut closures: Vec<RemediationOutcome> = Vec::new();
        for entry in &self.outcomes {
            if entry.key().0 != tenant_id {
                continue;
            }
            for o in entry.value() {
                if o.closed_at >= horizon {
                    closures.push(o.clone());
                }
            }
        }

        let mut regressions: Vec<RegressionEvent> = Vec::new();
        for entry in &self.regressions {
            if entry.key().0 != tenant_id {
                continue;
            }
            for r in entry.value() {
                if r.detected_at >= horizon {
                    regressions.push(r.clone());
                }
            }
        }

        let mttr_by_severity = aggregate_mttr(&closures);
        let top_regressing = top_regressing(&closures, &regressions);
        let closure_count = closures.len() as u64;
        let regression_count = regressions.len() as u64;
        let regression_rate = if closure_count == 0 {
            0.0
        } else {
            #[allow(clippy::cast_precision_loss)]
            let num = regression_count as f64;
            #[allow(clippy::cast_precision_loss)]
            let den = closure_count as f64;
            num / den
        };

        Ok(RemediationMetrics {
            tenant_id,
            window_seconds: window_secs,
            mttr_by_severity,
            regression_rate,
            top_regressing,
            closure_count,
            regression_count,
        })
    }

    async fn list_regressions(
        &self,
        tenant_id: Uuid,
        limit: usize,
    ) -> Result<Vec<RegressionEvent>, RemediationError> {
        let mut acc: Vec<RegressionEvent> = Vec::new();
        for entry in &self.regressions {
            if entry.key().0 != tenant_id {
                continue;
            }
            for r in entry.value() {
                acc.push(r.clone());
            }
        }
        acc.sort_by(|a, b| b.detected_at.cmp(&a.detected_at));
        acc.truncate(limit);
        Ok(acc)
    }
}

/// Aggregate closures into per-severity MTTR buckets, sorted from
/// `critical` → `info`. Severities with no closures in the window are
/// omitted so the dashboard does not render zero-rows.
fn aggregate_mttr(closures: &[RemediationOutcome]) -> Vec<MttrBucket> {
    use std::collections::HashMap;
    let mut sums: HashMap<String, (i128, u64)> = HashMap::new();
    for c in closures {
        let entry = sums.entry(c.severity.clone()).or_insert((0_i128, 0_u64));
        entry.0 = entry.0.saturating_add(i128::from(c.ttr_seconds));
        entry.1 = entry.1.saturating_add(1);
    }
    let mut buckets: Vec<MttrBucket> = sums
        .into_iter()
        .map(|(sev, (sum, count))| {
            let mttr = if count == 0 {
                0_i64
            } else {
                // Integer division is acceptable here — MTTR is a
                // whole-seconds metric and the consumer renders into
                // days/hours.
                #[allow(clippy::integer_division)]
                let mean = sum / i128::from(count);
                i64::try_from(mean).unwrap_or(i64::MAX)
            };
            MttrBucket {
                severity: sev,
                sample_size: count,
                mttr_seconds: mttr,
            }
        })
        .collect();
    buckets.sort_by_key(|b| severity_rank(&b.severity));
    buckets
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        "info" => 4,
        _ => 5,
    }
}

/// Build the top-`check_id` regression ranking. Sorted by regression
/// count descending, then `check_id` ascending for determinism.
fn top_regressing(
    closures: &[RemediationOutcome],
    regressions: &[RegressionEvent],
) -> Vec<RegressingTechnique> {
    use std::collections::HashMap;
    let mut counts: HashMap<String, (u64, u64)> = HashMap::new();
    for c in closures {
        let e = counts.entry(c.check_id.clone()).or_insert((0_u64, 0_u64));
        e.1 = e.1.saturating_add(1); // closures
    }
    for r in regressions {
        let e = counts.entry(r.check_id.clone()).or_insert((0_u64, 0_u64));
        e.0 = e.0.saturating_add(1); // regressions
    }
    let mut techniques: Vec<RegressingTechnique> = counts
        .into_iter()
        .map(
            |(check_id, (regression_count, closure_count))| RegressingTechnique {
                check_id,
                regression_count,
                closure_count,
            },
        )
        .filter(|t| t.regression_count > 0)
        .collect();
    techniques.sort_by(|a, b| {
        b.regression_count
            .cmp(&a.regression_count)
            .then_with(|| a.check_id.cmp(&b.check_id))
    });
    techniques.truncate(TOP_REGRESSING_LIMIT);
    techniques
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn t(uuid: u128) -> Uuid {
        Uuid::from_u128(uuid)
    }

    fn close_input(
        tenant: Uuid,
        asset: &str,
        check: &str,
        severity: &str,
        opened_at: OffsetDateTime,
    ) -> CloseInput {
        CloseInput {
            tenant_id: tenant,
            finding_id: Uuid::now_v7(),
            asset_id: asset.into(),
            check_id: check.into(),
            severity: severity.into(),
            opened_at,
            method: RemediationMethod::ManualPatch,
        }
    }

    #[tokio::test]
    async fn record_close_stamps_ttr_in_seconds() {
        let svc = InMemoryRemediationOutcomesService::new();
        let tenant = t(0x1);
        let opened = OffsetDateTime::now_utc() - time::Duration::minutes(10);
        let out = svc
            .record_close(close_input(tenant, "a-1", "C001", "high", opened))
            .await
            .unwrap();
        assert!(out.ttr_seconds >= 600);
        assert_eq!(out.method, RemediationMethod::ManualPatch);
        assert_eq!(out.severity, "high");
    }

    #[tokio::test]
    async fn detect_regression_inside_window_flags() {
        let svc = InMemoryRemediationOutcomesService::with_window(Duration::from_secs(60 * 60));
        let tenant = t(0x2);
        let opened = OffsetDateTime::now_utc() - time::Duration::minutes(30);
        svc.record_close(close_input(tenant, "a-7", "C-XYZ", "medium", opened))
            .await
            .unwrap();
        let new = OpenInput {
            tenant_id: tenant,
            finding_id: Uuid::now_v7(),
            asset_id: "a-7".into(),
            check_id: "C-XYZ".into(),
            detected_at: OffsetDateTime::now_utc(),
        };
        let r = svc.detect_regression(new).await.unwrap();
        assert!(r.is_some(), "expected regression event inside 1h window");
    }

    #[tokio::test]
    async fn detect_regression_outside_window_skips() {
        let svc = InMemoryRemediationOutcomesService::with_window(Duration::from_secs(60));
        let tenant = t(0x3);
        // Closure happened 2 minutes ago, window is 1 minute → outside.
        let opened = OffsetDateTime::now_utc() - time::Duration::minutes(5);
        let closure = svc
            .record_close(close_input(tenant, "a-9", "C-OLD", "low", opened))
            .await
            .unwrap();
        // Force the closed_at into the past by re-inserting manually.
        {
            let mut entry = svc
                .outcomes
                .get_mut(&(tenant, "a-9".into(), "C-OLD".into()))
                .unwrap();
            entry.last_mut().unwrap().closed_at = closure.closed_at - time::Duration::minutes(2);
        }
        let new = OpenInput {
            tenant_id: tenant,
            finding_id: Uuid::now_v7(),
            asset_id: "a-9".into(),
            check_id: "C-OLD".into(),
            detected_at: OffsetDateTime::now_utc(),
        };
        let r = svc.detect_regression(new).await.unwrap();
        assert!(r.is_none(), "expected no regression outside the window");
    }

    #[tokio::test]
    async fn metrics_aggregates_per_severity_and_top_regressing() {
        let svc = InMemoryRemediationOutcomesService::with_window(Duration::from_secs(60 * 60));
        let tenant = t(0x4);

        // 3 critical closures (TTR ~60, ~120, ~180 mins).
        for i in 0..3 {
            let opened =
                OffsetDateTime::now_utc() - time::Duration::minutes(60 + i64::from(i * 60));
            svc.record_close(close_input(tenant, "a-c", "C-CRIT", "critical", opened))
                .await
                .unwrap();
        }
        // 1 high closure on a different check_id.
        svc.record_close(close_input(
            tenant,
            "a-h",
            "C-HI",
            "high",
            OffsetDateTime::now_utc() - time::Duration::minutes(45),
        ))
        .await
        .unwrap();

        // Regression on C-CRIT (re-open).
        let new = OpenInput {
            tenant_id: tenant,
            finding_id: Uuid::now_v7(),
            asset_id: "a-c".into(),
            check_id: "C-CRIT".into(),
            detected_at: OffsetDateTime::now_utc(),
        };
        let r = svc.detect_regression(new).await.unwrap();
        assert!(r.is_some());

        let m = svc
            .metrics(tenant, Duration::from_secs(60 * 60 * 24))
            .await
            .unwrap();
        assert_eq!(m.closure_count, 4);
        assert_eq!(m.regression_count, 1);
        // Mttr bucket order: critical first (rank 0), then high.
        assert_eq!(m.mttr_by_severity.first().unwrap().severity, "critical");
        assert_eq!(m.mttr_by_severity.first().unwrap().sample_size, 3);
        // Top regressing: only C-CRIT.
        assert_eq!(m.top_regressing.len(), 1);
        assert_eq!(m.top_regressing.first().unwrap().check_id, "C-CRIT");
        // Rate = 1 / 4
        assert!((m.regression_rate - 0.25).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn list_regressions_newest_first_and_limit() {
        let svc = InMemoryRemediationOutcomesService::new();
        let tenant = t(0x5);
        // Seed two closures + two regressions.
        for check in ["X", "Y"] {
            let opened = OffsetDateTime::now_utc() - time::Duration::minutes(10);
            svc.record_close(close_input(tenant, "a", check, "low", opened))
                .await
                .unwrap();
            svc.detect_regression(OpenInput {
                tenant_id: tenant,
                finding_id: Uuid::now_v7(),
                asset_id: "a".into(),
                check_id: check.into(),
                detected_at: OffsetDateTime::now_utc(),
            })
            .await
            .unwrap();
        }
        let list = svc.list_regressions(tenant, 1).await.unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn remediation_method_round_trip_serialises() {
        for m in [
            RemediationMethod::AutoPatch,
            RemediationMethod::ManualPatch,
            RemediationMethod::RiskAccepted,
            RemediationMethod::FalsePositive,
            RemediationMethod::ConfigChange,
            RemediationMethod::Unspecified,
        ] {
            let s = m.as_str();
            assert_eq!(RemediationMethod::parse(s), m);
        }
        assert_eq!(
            RemediationMethod::parse("not-a-method"),
            RemediationMethod::Unspecified,
        );
    }
}
