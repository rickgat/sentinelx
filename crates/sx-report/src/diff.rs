//! Differential reports — week-over-week (or arbitrary window) diffs.
//!
//! Given an engagement and a `[since, until]` UTC window, the diff service
//! classifies findings into three buckets:
//!
//! - **NEW**       — first observed inside the window (`first_seen ∈ [since, until]`).
//! - **RESOLVED**  — currently `closed`/`accepted` and last touched inside the window.
//! - **REGRESSED** — first observed before the window but currently open/triaged
//!   and last touched inside the window (re-opened or re-detected).
//!
//! Plus a `severity_drift` map: per [`Severity`] bucket, the count of "open"
//! findings *before* the window started and the count *after* the window
//! closed. Counts come from the same finding list to keep the diff
//! self-consistent.
//!
//! ## Why a port and an in-memory service
//!
//! The diff is computed in-process — the data already lives behind the
//! existing finding repository port. The `ReportDiffService` trait lets the
//! API layer accept any implementation (in-memory, batched against
//! Postgres, …) without binding to a single backend, mirroring the pattern
//! used by [`crate::port::Renderer`].

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sx_core::value_object::ids::{EngagementId, FindingId, TenantId};
use sx_core::value_object::severity::Severity;
use time::OffsetDateTime;
use tracing::instrument;

use crate::error::ReportError;

/// Maximum window the diff service will compute over.
///
/// 365 days matches the controller-side guard and prevents accidentally
/// scanning multi-year archives in a single request.
pub const MAX_DIFF_WINDOW_DAYS: i64 = 365;

/// Per-port maximum number of finding rows the diff service will pull from
/// the finding repository before bailing. A defence-in-depth cap so a
/// misconfigured backend cannot exhaust memory.
pub const MAX_FINDINGS_SCANNED: usize = 100_000;

/// Page size used to scan the finding repository.
pub const SCAN_PAGE_SIZE: u32 = 500;

/// Snapshot of a single finding row consumed by the diff engine.
///
/// Deliberately *not* the rendering-shaped [`crate::model::ReportFinding`].
/// The diff doesn't need free-form description / references; it only needs
/// the lifecycle timestamps + classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingSnapshot {
    /// Stable finding identifier.
    pub id: FindingId,
    /// Engagement scope (used to filter, when supplied at the port layer).
    pub engagement_id: Option<EngagementId>,
    /// Severity bucket at observation time.
    pub severity: Severity,
    /// Short title.
    pub title: String,
    /// Lifecycle status, lower-snake-cased
    /// (`open`, `triaged`, `accepted`, `closed`).
    pub status: String,
    /// First-seen timestamp.
    pub first_seen: OffsetDateTime,
    /// Last-seen timestamp.
    pub last_seen: OffsetDateTime,
}

impl FindingSnapshot {
    /// True when the snapshot is considered open (i.e. not closed/accepted).
    #[must_use]
    pub fn is_open(&self) -> bool {
        !matches!(self.status.as_str(), "closed" | "accepted")
    }

    /// True when the snapshot is considered resolved (closed or accepted).
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        !self.is_open()
    }
}

/// A finding row projected onto the diff response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffFinding {
    /// Finding id.
    pub id: FindingId,
    /// Severity bucket.
    pub severity: Severity,
    /// Short title (for display).
    pub title: String,
    /// First-seen timestamp.
    pub first_seen: OffsetDateTime,
    /// Last-seen timestamp.
    pub last_seen: OffsetDateTime,
    /// Lifecycle status at the time of the diff.
    pub status: String,
}

impl From<&FindingSnapshot> for DiffFinding {
    fn from(s: &FindingSnapshot) -> Self {
        Self {
            id: s.id,
            severity: s.severity,
            title: s.title.clone(),
            first_seen: s.first_seen,
            last_seen: s.last_seen,
            status: s.status.clone(),
        }
    }
}

/// Per-severity drift datum.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityDriftEntry {
    /// Count of open findings at `since` (before the window).
    pub before: u32,
    /// Count of open findings at `until` (after the window).
    pub after: u32,
}

impl SeverityDriftEntry {
    /// Net change in open finding count for this severity.
    #[must_use]
    pub const fn delta(self) -> i64 {
        self.after as i64 - self.before as i64
    }
}

/// Top-line metrics derived from the diff buckets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffMetrics {
    /// `added.len() - resolved.len()` — positive means the engagement grew
    /// its open-finding inventory over the window.
    pub net_change_count: i64,
    /// `reopened.len()` — count of findings that were closed but came back.
    pub regression_count: u32,
}

/// Resulting payload of [`ReportDiffService::compute_diff`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportDiff {
    /// Tenant scope.
    pub tenant_id: TenantId,
    /// Engagement scope.
    pub engagement_id: EngagementId,
    /// Window lower bound (inclusive).
    pub since: OffsetDateTime,
    /// Window upper bound (inclusive).
    pub until: OffsetDateTime,
    /// Findings whose `first_seen` falls inside the window.
    pub added: Vec<DiffFinding>,
    /// Findings that look closed/accepted *and* were last touched in window.
    pub resolved: Vec<DiffFinding>,
    /// Findings first observed before the window that resurfaced (open +
    /// last touched in window).
    pub reopened: Vec<DiffFinding>,
    /// Per-severity before/after counts.
    pub severity_drift: HashMap<Severity, SeverityDriftEntry>,
    /// Derived metrics.
    pub metrics: DiffMetrics,
}

/// Read-side port the diff engine consumes.
///
/// Implementations are responsible for tenant scoping; the diff engine
/// trusts the snapshots it receives.
#[async_trait]
pub trait FindingsSnapshotPort: Send + Sync {
    /// Return *all* findings for `tenant_id` (optionally filtered by
    /// `engagement_id`). Implementations are encouraged to page internally;
    /// the diff engine consumes the full list at once.
    async fn snapshot(
        &self,
        tenant_id: &TenantId,
        engagement_id: Option<&EngagementId>,
    ) -> Result<Vec<FindingSnapshot>, ReportError>;
}

/// Engagement existence/scope port — used to fail fast when the engagement
/// is unknown before scanning the finding table.
#[async_trait]
pub trait EngagementExistsPort: Send + Sync {
    /// Return `true` if `engagement_id` exists under `tenant_id`.
    async fn exists(
        &self,
        tenant_id: &TenantId,
        engagement_id: &EngagementId,
    ) -> Result<bool, ReportError>;
}

/// Public diff service trait.
#[async_trait]
pub trait ReportDiffService: Send + Sync {
    /// Compute the diff for `(tenant_id, engagement_id)` over the
    /// `[since, until]` UTC window.
    ///
    /// # Errors
    ///
    /// - [`ReportError::InvalidContext`] when `since >= until`, the window
    ///   exceeds [`MAX_DIFF_WINDOW_DAYS`], or the engagement is unknown.
    /// - [`ReportError::Internal`] when an underlying port fails.
    async fn compute_diff(
        &self,
        tenant_id: TenantId,
        engagement_id: EngagementId,
        since: OffsetDateTime,
        until: OffsetDateTime,
    ) -> Result<ReportDiff, ReportError>;
}

/// In-memory [`ReportDiffService`] backed by two ports.
///
/// The implementation pulls every finding via [`FindingsSnapshotPort`] and
/// runs the bucketing in pure Rust. There is no I/O after the initial
/// snapshot fetch, which keeps the diff deterministic for a given snapshot.
pub struct InMemoryReportDiffService {
    findings: Arc<dyn FindingsSnapshotPort>,
    engagements: Arc<dyn EngagementExistsPort>,
}

impl std::fmt::Debug for InMemoryReportDiffService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryReportDiffService").finish()
    }
}

impl InMemoryReportDiffService {
    /// Build a new service from the two adapter ports.
    #[must_use]
    pub fn new(
        findings: Arc<dyn FindingsSnapshotPort>,
        engagements: Arc<dyn EngagementExistsPort>,
    ) -> Self {
        Self {
            findings,
            engagements,
        }
    }
}

/// Validate `[since, until]` — `since < until` and window is bounded by
/// [`MAX_DIFF_WINDOW_DAYS`].
fn validate_window(since: OffsetDateTime, until: OffsetDateTime) -> Result<(), ReportError> {
    if since >= until {
        return Err(ReportError::invalid_context(format!(
            "since ({since}) must be strictly before until ({until})"
        )));
    }
    let span = until - since;
    if span > time::Duration::days(MAX_DIFF_WINDOW_DAYS) {
        return Err(ReportError::invalid_context(format!(
            "window exceeds maximum of {MAX_DIFF_WINDOW_DAYS} days"
        )));
    }
    Ok(())
}

#[async_trait]
impl ReportDiffService for InMemoryReportDiffService {
    #[instrument(skip(self), fields(tenant_id = %tenant_id, engagement_id = %engagement_id))]
    async fn compute_diff(
        &self,
        tenant_id: TenantId,
        engagement_id: EngagementId,
        since: OffsetDateTime,
        until: OffsetDateTime,
    ) -> Result<ReportDiff, ReportError> {
        validate_window(since, until)?;

        if !self.engagements.exists(&tenant_id, &engagement_id).await? {
            return Err(ReportError::invalid_context(format!(
                "engagement {engagement_id} not found under tenant {tenant_id}"
            )));
        }

        let snapshots = self
            .findings
            .snapshot(&tenant_id, Some(&engagement_id))
            .await?;
        let diff = compute_diff_in_memory(tenant_id, engagement_id, since, until, &snapshots);
        Ok(diff)
    }
}

/// Pure-function diff computation. Public for unit testing — the trait
/// implementation simply funnels here after fetching snapshots.
#[must_use]
pub fn compute_diff_in_memory(
    tenant_id: TenantId,
    engagement_id: EngagementId,
    since: OffsetDateTime,
    until: OffsetDateTime,
    snapshots: &[FindingSnapshot],
) -> ReportDiff {
    let mut added: Vec<DiffFinding> = Vec::new();
    let mut resolved: Vec<DiffFinding> = Vec::new();
    let mut reopened: Vec<DiffFinding> = Vec::new();

    let mut drift: HashMap<Severity, SeverityDriftEntry> = HashMap::new();

    let in_window = |t: OffsetDateTime| t >= since && t <= until;

    for snap in snapshots {
        // Filter: if `engagement_id` is recorded on the snapshot, it must
        // match. Snapshots that don't carry it (port-impl detail) are kept.
        if let Some(eid) = snap.engagement_id {
            if eid != engagement_id {
                continue;
            }
        }

        // Severity drift — count "open" rows before vs after.
        let entry = drift.entry(snap.severity).or_default();
        // "Before": open at the moment `since` ticks over — i.e. first_seen
        // strictly before since AND (status was still open OR closed after
        // since).
        if snap.first_seen < since && (snap.is_open() || snap.last_seen >= since) {
            entry.before = entry.before.saturating_add(1);
        }
        // "After": currently open as of the window end (last_seen <= until).
        if snap.is_open() && snap.first_seen <= until {
            entry.after = entry.after.saturating_add(1);
        }

        let added_in_window = in_window(snap.first_seen);
        let touched_in_window = in_window(snap.last_seen);

        if added_in_window {
            added.push(DiffFinding::from(snap));
            // A row that first appeared *and* is already resolved inside the
            // same window is still recorded as resolved so the resolved
            // column shows the full "closed-this-week" set.
            if snap.is_resolved() && touched_in_window {
                resolved.push(DiffFinding::from(snap));
            }
            continue;
        }

        if snap.is_resolved() && touched_in_window {
            resolved.push(DiffFinding::from(snap));
            continue;
        }

        // Reopened/regressed: first seen before the window, still open, and
        // last touched inside the window. Excludes brand-new findings.
        if snap.is_open() && touched_in_window && snap.first_seen < since {
            reopened.push(DiffFinding::from(snap));
        }
    }

    // Sort lists for determinism (severity desc, then by id).
    let sort_key = |f: &DiffFinding| (std::cmp::Reverse(f.severity), f.id);
    added.sort_by_key(sort_key);
    resolved.sort_by_key(sort_key);
    reopened.sort_by_key(sort_key);

    let added_i64 = i64::try_from(added.len()).unwrap_or(i64::MAX);
    let resolved_i64 = i64::try_from(resolved.len()).unwrap_or(i64::MAX);
    let net_change_count = added_i64.saturating_sub(resolved_i64);
    let regression_count = u32::try_from(reopened.len()).unwrap_or(u32::MAX);
    let metrics = DiffMetrics {
        net_change_count,
        regression_count,
    };

    ReportDiff {
        tenant_id,
        engagement_id,
        since,
        until,
        added,
        resolved,
        reopened,
        severity_drift: drift,
        metrics,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn snap(
        sev: Severity,
        status: &str,
        first_seen: OffsetDateTime,
        last_seen: OffsetDateTime,
    ) -> FindingSnapshot {
        FindingSnapshot {
            id: FindingId::new(),
            engagement_id: None,
            severity: sev,
            title: "t".to_owned(),
            status: status.to_owned(),
            first_seen,
            last_seen,
        }
    }

    #[test]
    fn validate_window_rejects_inverted_range() {
        let now = OffsetDateTime::now_utc();
        let earlier = now - time::Duration::days(1);
        assert!(validate_window(now, earlier).is_err());
        assert!(validate_window(now, now).is_err());
    }

    #[test]
    fn validate_window_rejects_oversized_range() {
        let since = datetime!(2025-01-01 00:00:00 UTC);
        let until = since + time::Duration::days(MAX_DIFF_WINDOW_DAYS + 1);
        assert!(validate_window(since, until).is_err());
    }

    #[test]
    fn validate_window_accepts_at_limit() {
        let since = datetime!(2025-01-01 00:00:00 UTC);
        let until = since + time::Duration::days(MAX_DIFF_WINDOW_DAYS);
        assert!(validate_window(since, until).is_ok());
    }

    #[test]
    fn diff_classifies_added_resolved_regressed() {
        let since = datetime!(2026-05-23 00:00:00 UTC);
        let until = datetime!(2026-05-30 00:00:00 UTC);

        // NEW: first_seen inside window.
        let new1 = snap(
            Severity::High,
            "open",
            datetime!(2026-05-25 12:00:00 UTC),
            datetime!(2026-05-25 12:00:00 UTC),
        );
        // RESOLVED: closed, last_seen inside window, first_seen before window.
        let resolved1 = snap(
            Severity::Critical,
            "closed",
            datetime!(2026-05-01 09:00:00 UTC),
            datetime!(2026-05-26 09:00:00 UTC),
        );
        // REGRESSED: first_seen before window, still open, last_seen in window.
        let regressed1 = snap(
            Severity::Medium,
            "open",
            datetime!(2026-05-01 09:00:00 UTC),
            datetime!(2026-05-27 09:00:00 UTC),
        );
        // Untouched (outside window) — must NOT appear.
        let untouched = snap(
            Severity::Low,
            "open",
            datetime!(2026-04-01 09:00:00 UTC),
            datetime!(2026-04-10 09:00:00 UTC),
        );

        let snapshots = vec![new1, resolved1, regressed1, untouched];
        let diff = compute_diff_in_memory(
            TenantId::new(),
            EngagementId::new(),
            since,
            until,
            &snapshots,
        );

        assert_eq!(diff.added.len(), 1);
        assert_eq!(diff.added[0].severity, Severity::High);

        assert_eq!(diff.resolved.len(), 1);
        assert_eq!(diff.resolved[0].severity, Severity::Critical);

        assert_eq!(diff.reopened.len(), 1);
        assert_eq!(diff.reopened[0].severity, Severity::Medium);

        assert_eq!(diff.metrics.net_change_count, 0);
        assert_eq!(diff.metrics.regression_count, 1);

        // Drift: medium was open before AND after; critical was open before
        // but closed after; low untouched (open both sides).
        let med = diff.severity_drift.get(&Severity::Medium).copied().unwrap();
        assert_eq!(med.before, 1);
        assert_eq!(med.after, 1);
        let crit = diff
            .severity_drift
            .get(&Severity::Critical)
            .copied()
            .unwrap();
        assert_eq!(crit.before, 1);
        assert_eq!(crit.after, 0);
        let low = diff.severity_drift.get(&Severity::Low).copied().unwrap();
        assert_eq!(low.before, 1);
        assert_eq!(low.after, 1);
    }

    #[test]
    fn diff_ignores_other_engagements() {
        let since = datetime!(2026-05-23 00:00:00 UTC);
        let until = datetime!(2026-05-30 00:00:00 UTC);

        let target_eid = EngagementId::new();
        let other_eid = EngagementId::new();

        let mut mine = snap(
            Severity::High,
            "open",
            datetime!(2026-05-25 12:00:00 UTC),
            datetime!(2026-05-25 12:00:00 UTC),
        );
        mine.engagement_id = Some(target_eid);

        let mut theirs = snap(
            Severity::High,
            "open",
            datetime!(2026-05-25 12:00:00 UTC),
            datetime!(2026-05-25 12:00:00 UTC),
        );
        theirs.engagement_id = Some(other_eid);

        let diff =
            compute_diff_in_memory(TenantId::new(), target_eid, since, until, &[mine, theirs]);
        assert_eq!(diff.added.len(), 1);
    }

    #[test]
    fn diff_handles_empty_snapshot() {
        let since = datetime!(2026-05-23 00:00:00 UTC);
        let until = datetime!(2026-05-30 00:00:00 UTC);

        let diff = compute_diff_in_memory(TenantId::new(), EngagementId::new(), since, until, &[]);
        assert_eq!(diff.added.len(), 0);
        assert_eq!(diff.resolved.len(), 0);
        assert_eq!(diff.reopened.len(), 0);
        assert_eq!(diff.metrics.net_change_count, 0);
        assert_eq!(diff.metrics.regression_count, 0);
        assert!(diff.severity_drift.is_empty());
    }

    #[test]
    fn diff_metrics_net_change_positive_when_more_added_than_resolved() {
        let since = datetime!(2026-05-23 00:00:00 UTC);
        let until = datetime!(2026-05-30 00:00:00 UTC);
        let inside = datetime!(2026-05-25 12:00:00 UTC);
        let snapshots = vec![
            snap(Severity::High, "open", inside, inside),
            snap(Severity::High, "open", inside, inside),
            snap(Severity::High, "open", inside, inside),
        ];
        let diff = compute_diff_in_memory(
            TenantId::new(),
            EngagementId::new(),
            since,
            until,
            &snapshots,
        );
        assert_eq!(diff.added.len(), 3);
        assert_eq!(diff.metrics.net_change_count, 3);
    }

    // --- Integration with InMemoryReportDiffService -----------------------

    struct StubFindings(Vec<FindingSnapshot>);
    #[async_trait]
    impl FindingsSnapshotPort for StubFindings {
        async fn snapshot(
            &self,
            _tenant_id: &TenantId,
            _engagement_id: Option<&EngagementId>,
        ) -> Result<Vec<FindingSnapshot>, ReportError> {
            Ok(self.0.clone())
        }
    }

    struct StubEngagementExists(bool);
    #[async_trait]
    impl EngagementExistsPort for StubEngagementExists {
        async fn exists(
            &self,
            _tenant_id: &TenantId,
            _engagement_id: &EngagementId,
        ) -> Result<bool, ReportError> {
            Ok(self.0)
        }
    }

    #[tokio::test]
    async fn service_rejects_unknown_engagement() {
        let svc = InMemoryReportDiffService::new(
            Arc::new(StubFindings(vec![])),
            Arc::new(StubEngagementExists(false)),
        );
        let res = svc
            .compute_diff(
                TenantId::new(),
                EngagementId::new(),
                datetime!(2026-05-23 00:00:00 UTC),
                datetime!(2026-05-30 00:00:00 UTC),
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn service_rejects_inverted_window() {
        let svc = InMemoryReportDiffService::new(
            Arc::new(StubFindings(vec![])),
            Arc::new(StubEngagementExists(true)),
        );
        let res = svc
            .compute_diff(
                TenantId::new(),
                EngagementId::new(),
                datetime!(2026-05-30 00:00:00 UTC),
                datetime!(2026-05-23 00:00:00 UTC),
            )
            .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn service_returns_diff_when_engagement_exists() {
        let inside = datetime!(2026-05-25 12:00:00 UTC);
        let snapshots = vec![snap(Severity::High, "open", inside, inside)];
        let svc = InMemoryReportDiffService::new(
            Arc::new(StubFindings(snapshots)),
            Arc::new(StubEngagementExists(true)),
        );
        let diff = svc
            .compute_diff(
                TenantId::new(),
                EngagementId::new(),
                datetime!(2026-05-23 00:00:00 UTC),
                datetime!(2026-05-30 00:00:00 UTC),
            )
            .await
            .unwrap();
        assert_eq!(diff.added.len(), 1);
    }
}
