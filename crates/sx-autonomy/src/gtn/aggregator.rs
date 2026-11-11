//! Global Threat Network — k-anonymous aggregator.
//!
//! [`ThreatAggregator`] collects [`ThreatReport`] events from many tenants
//! and emits an [`AggregatedFinding`] *only* when at least `k` distinct
//! tenants have reported similar indicators inside a rolling time window.
//! "Similar" is defined as either:
//!
//! - identical or near-identical IOC strings (Levenshtein distance
//!   ≤ [`LEVENSHTEIN_THRESHOLD`]), or
//! - a shared CVE id across the reports.
//!
//! # K-anonymity floor
//!
//! The aggregator refuses to emit findings when configured with `k` below
//! [`MIN_K_ANONYMITY`]. This is a hard floor — constructor returns
//! [`AutonomyError::InvalidInput`] for `k < 5`. The k-anonymity guarantee
//! is the whole point of the active GTN mode; lowering it would defeat
//! the privacy contract.
//!
//! # Forgetting
//!
//! Reports older than the configured rolling `window` are evicted from the
//! aggregator state on every call to [`ThreatAggregator::ingest`] and
//! [`ThreatAggregator::collect`]. Eviction is conservative: a report whose
//! `observed_at + window` is strictly less than `now` is gone. This is the
//! cheapest correct policy and avoids stale clusters dragging down emits.
//!
//! # Wire-shape guarantee
//!
//! [`AggregatedFinding`] never carries a tenant id, only a `tenant_count`.
//! Internally the aggregator holds tenant ids long enough to enforce
//! distinct-tenant counting, then drops them at the emission boundary.

use std::collections::{HashMap, HashSet};

use sx_core::value_object::ids::{CveId, TenantId};
use time::{Duration as TimeDuration, OffsetDateTime};

use crate::error::AutonomyError;
use crate::gtn::summary::{AggregatedFinding, Severity};

/// Hard lower bound on k.
///
/// The aggregator refuses to construct with a smaller value — the active
/// GTN mode is built on the assumption that no single tenant can be
/// re-identified from an emission, and `k < 5` would put us inside the
/// long tail of "could plausibly be one tenant".
pub const MIN_K_ANONYMITY: u32 = 5;

/// Levenshtein distance threshold for cluster merging.
///
/// Two IOC strings whose distance is `<=` this value are treated as the
/// same cluster anchor. Empirically chosen to allow trivial typo or
/// casing variants without merging genuinely-distinct indicators.
pub const LEVENSHTEIN_THRESHOLD: usize = 3;

/// One tenant-supplied threat observation.
///
/// At least one of `indicator` or `cve_id` must be non-empty — otherwise
/// the report cannot anchor to a cluster and [`ThreatAggregator::ingest`]
/// rejects it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatReport {
    /// Tenant that submitted the report. Used only to count *distinct*
    /// tenants and is dropped before any [`AggregatedFinding`] is emitted.
    pub tenant_id: TenantId,
    /// Free-form indicator (URL, host, file path, hash). Optional when
    /// `cve_id` is set.
    pub indicator: Option<String>,
    /// Optional CVE id reference. Reports sharing a CVE id cluster
    /// regardless of indicator similarity.
    pub cve_id: Option<CveId>,
    /// Severity bucket reported by the tenant. The cluster's emitted
    /// severity is the maximum across contributing reports.
    pub severity: Severity,
    /// Tenant-side timestamp of the observation. Drives the rolling
    /// window forget policy.
    pub observed_at: OffsetDateTime,
}

impl ThreatReport {
    /// Construct a report.
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        indicator: Option<String>,
        cve_id: Option<CveId>,
        severity: Severity,
        observed_at: OffsetDateTime,
    ) -> Self {
        Self {
            tenant_id,
            indicator,
            cve_id,
            severity,
            observed_at,
        }
    }

    /// Canonical anchor string used by the clustering pass. Prefers the
    /// CVE id when present so cross-indicator merges work.
    fn anchor(&self) -> String {
        self.cve_id.as_ref().map_or_else(
            || {
                self.indicator
                    .as_ref()
                    .map_or_else(String::new, |ind| ind.trim().to_ascii_lowercase())
            },
            |cve| cve.as_str().to_owned(),
        )
    }

    fn has_payload(&self) -> bool {
        self.cve_id.is_some()
            || self
                .indicator
                .as_ref()
                .is_some_and(|s| !s.trim().is_empty())
    }
}

/// One cluster of similar reports kept in the aggregator state.
#[derive(Debug, Clone)]
struct Cluster {
    /// Anchor string used to merge new reports.
    anchor: String,
    /// Optional shared CVE id (set the moment any contributing report
    /// carries a CVE id).
    cve_id: Option<CveId>,
    /// Distinct tenant ids that contributed.
    tenants: HashSet<TenantId>,
    /// Highest severity seen.
    severity: Severity,
    /// Earliest contributing report's `observed_at`.
    first_seen: OffsetDateTime,
    /// Latest contributing report's `observed_at`.
    last_seen: OffsetDateTime,
    /// All `(tenant_id, observed_at)` pairs we still hold. Used to drop
    /// stale tenant contributions when the window slides forward.
    contributions: Vec<(TenantId, OffsetDateTime)>,
}

impl Cluster {
    fn from_report(r: &ThreatReport) -> Self {
        let mut tenants = HashSet::new();
        tenants.insert(r.tenant_id);
        Self {
            anchor: r.anchor(),
            cve_id: r.cve_id.clone(),
            tenants,
            severity: r.severity,
            first_seen: r.observed_at,
            last_seen: r.observed_at,
            contributions: vec![(r.tenant_id, r.observed_at)],
        }
    }

    fn absorb(&mut self, r: &ThreatReport) {
        if self.cve_id.is_none() {
            self.cve_id.clone_from(&r.cve_id);
        }
        self.tenants.insert(r.tenant_id);
        self.severity = self.severity.max(r.severity);
        if r.observed_at < self.first_seen {
            self.first_seen = r.observed_at;
        }
        if r.observed_at > self.last_seen {
            self.last_seen = r.observed_at;
        }
        self.contributions.push((r.tenant_id, r.observed_at));
    }

    /// Drop contributions older than `cutoff`. Returns `true` when the
    /// cluster is now empty and should be removed from the aggregator.
    fn forget_before(&mut self, cutoff: OffsetDateTime) -> bool {
        self.contributions.retain(|(_, ts)| *ts >= cutoff);
        if self.contributions.is_empty() {
            return true;
        }
        // Recompute distinct tenants + temporal envelope from what's
        // still inside the window.
        self.tenants.clear();
        let mut first = self.last_seen;
        let mut last = self.first_seen;
        for (tid, ts) in &self.contributions {
            self.tenants.insert(*tid);
            if *ts < first {
                first = *ts;
            }
            if *ts > last {
                last = *ts;
            }
        }
        self.first_seen = first;
        self.last_seen = last;
        false
    }

    fn emit(&self) -> AggregatedFinding {
        let indicator = self
            .cve_id
            .as_ref()
            .map_or_else(|| self.anchor.clone(), |c| c.as_str().to_owned());
        AggregatedFinding::new(
            indicator,
            u32::try_from(self.tenants.len()).unwrap_or(u32::MAX),
            self.severity,
            self.first_seen,
            self.last_seen,
        )
    }
}

/// K-anonymous threat aggregator.
///
/// Construct with [`ThreatAggregator::new`], feed reports through
/// [`ThreatAggregator::ingest`], and pull emittable findings with
/// [`ThreatAggregator::collect`].
#[derive(Debug)]
pub struct ThreatAggregator {
    window: TimeDuration,
    k_anonymity: u32,
    /// CVE-keyed cluster index — reports sharing a CVE id always merge
    /// into the same cluster regardless of indicator text.
    by_cve: HashMap<String, usize>,
    /// Storage for the clusters. We hold a `Vec` and index into it from
    /// `by_cve` because Levenshtein matching needs a linear scan anyway.
    clusters: Vec<Cluster>,
}

impl ThreatAggregator {
    /// Construct a new aggregator.
    ///
    /// # Errors
    /// - [`AutonomyError::InvalidInput`] when `k_anonymity` is below
    ///   [`MIN_K_ANONYMITY`].
    /// - [`AutonomyError::InvalidInput`] when `window` is zero or negative.
    pub fn new(window: TimeDuration, k_anonymity: u32) -> Result<Self, AutonomyError> {
        if k_anonymity < MIN_K_ANONYMITY {
            return Err(AutonomyError::invalid_input(format!(
                "k_anonymity must be >= {MIN_K_ANONYMITY} (got {k_anonymity})"
            )));
        }
        if window <= TimeDuration::ZERO {
            return Err(AutonomyError::invalid_input(
                "aggregator window must be positive",
            ));
        }
        Ok(Self {
            window,
            k_anonymity,
            by_cve: HashMap::new(),
            clusters: Vec::new(),
        })
    }

    /// The configured k-anonymity floor.
    #[must_use]
    pub const fn k_anonymity(&self) -> u32 {
        self.k_anonymity
    }

    /// The configured rolling window.
    #[must_use]
    pub const fn window(&self) -> TimeDuration {
        self.window
    }

    /// Ingest one report. No emission happens here — emission is observed
    /// via [`ThreatAggregator::collect`].
    ///
    /// # Errors
    /// [`AutonomyError::InvalidInput`] when the report carries neither a
    /// CVE id nor a non-empty indicator.
    // The owned `ThreatReport` lets callers move the report into the
    // aggregator and forget it; internally we only need a reference.
    #[allow(clippy::needless_pass_by_value)]
    pub fn ingest(
        &mut self,
        report: ThreatReport,
        now: OffsetDateTime,
    ) -> Result<(), AutonomyError> {
        if !report.has_payload() {
            return Err(AutonomyError::invalid_input(
                "report must carry either an indicator or a CVE id",
            ));
        }
        self.evict_stale(now);
        self.merge(&report);
        Ok(())
    }

    /// Drain the aggregator of all currently-emittable findings (clusters
    /// whose distinct-tenant count is `>= k`). The aggregator state itself
    /// is left unchanged — callers may collect repeatedly as new reports
    /// arrive.
    pub fn collect(&mut self, now: OffsetDateTime) -> Vec<AggregatedFinding> {
        self.evict_stale(now);
        let k = self.k_anonymity as usize;
        self.clusters
            .iter()
            .filter(|c| c.tenants.len() >= k)
            .map(Cluster::emit)
            .collect()
    }

    /// Number of clusters currently held. Test-only introspection.
    #[cfg(test)]
    pub(crate) const fn cluster_count(&self) -> usize {
        self.clusters.len()
    }

    fn evict_stale(&mut self, now: OffsetDateTime) {
        let cutoff = now - self.window;
        let mut i = 0;
        while i < self.clusters.len() {
            let drop_cluster = self
                .clusters
                .get_mut(i)
                .is_some_and(|c| c.forget_before(cutoff));
            if drop_cluster {
                let removed = self.clusters.swap_remove(i);
                if let Some(cve) = &removed.cve_id {
                    self.by_cve.remove(cve.as_str());
                }
                // Re-point the swapped-in cluster's CVE index entry, if any.
                if let Some(swapped_cve) = self.clusters.get(i).and_then(|c| c.cve_id.clone()) {
                    self.by_cve.insert(swapped_cve.as_str().to_owned(), i);
                }
                // Don't bump `i` — index `i` now holds a fresh cluster.
            } else {
                i += 1;
            }
        }
    }

    fn merge(&mut self, report: &ThreatReport) {
        // 1) CVE-keyed merge wins immediately.
        if let Some(cve) = &report.cve_id {
            if let Some(idx) = self.by_cve.get(cve.as_str()).copied() {
                if let Some(c) = self.clusters.get_mut(idx) {
                    c.absorb(report);
                    return;
                }
            }
        }
        // 2) Levenshtein-by-anchor merge.
        let anchor = report.anchor();
        if !anchor.is_empty() {
            for (idx, c) in self.clusters.iter_mut().enumerate() {
                if levenshtein(&c.anchor, &anchor) <= LEVENSHTEIN_THRESHOLD {
                    c.absorb(report);
                    if let Some(cve) = c.cve_id.clone() {
                        self.by_cve.insert(cve.as_str().to_owned(), idx);
                    }
                    return;
                }
            }
        }
        // 3) New cluster.
        let cluster = Cluster::from_report(report);
        let idx = self.clusters.len();
        if let Some(cve) = cluster.cve_id.clone() {
            self.by_cve.insert(cve.as_str().to_owned(), idx);
        }
        self.clusters.push(cluster);
    }
}

/// Iterative two-row Levenshtein implementation.
///
/// Operates on byte slices — IOC anchors are ASCII-lowercased before
/// reaching this point, so byte distance and char distance coincide
/// for the indicator set the aggregator actually clusters.
// The two-row DP body indexes `prev`/`curr` and `a_bytes`/`b_bytes` by
// loop counters that are provably in-range; lifting those reads to
// `.get(..).copied().unwrap_or(usize::MAX)` would only obscure intent.
#[allow(clippy::indexing_slicing)]
fn levenshtein(a: &str, b: &str) -> usize {
    if a == b {
        return 0;
    }
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    let (a_bytes, b_bytes) = if a_bytes.len() < b_bytes.len() {
        (b_bytes, a_bytes)
    } else {
        (a_bytes, b_bytes)
    };
    let n = a_bytes.len();
    let m = b_bytes.len();
    if m == 0 {
        return n;
    }
    let mut prev: Vec<usize> = (0..=m).collect();
    let mut curr: Vec<usize> = vec![0; m + 1];
    for (i, ca) in a_bytes.iter().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b_bytes.iter().enumerate() {
            let cost = usize::from(ca != cb);
            let del = prev[j + 1] + 1;
            let ins = curr[j] + 1;
            let sub = prev[j] + cost;
            curr[j + 1] = del.min(ins).min(sub);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[m]
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use time::Duration as TimeDuration;

    fn ts_offset(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000 + seconds).unwrap()
    }

    fn cve(s: &str) -> CveId {
        CveId::new(s).unwrap()
    }

    #[test]
    fn rejects_k_below_floor() {
        let err = ThreatAggregator::new(TimeDuration::hours(24), 4).unwrap_err();
        assert!(matches!(err, AutonomyError::InvalidInput(_)));
    }

    #[test]
    fn accepts_k_at_floor() {
        let agg = ThreatAggregator::new(TimeDuration::hours(24), MIN_K_ANONYMITY).unwrap();
        assert_eq!(agg.k_anonymity(), MIN_K_ANONYMITY);
    }

    #[test]
    fn rejects_zero_window() {
        let err = ThreatAggregator::new(TimeDuration::ZERO, 5).unwrap_err();
        assert!(matches!(err, AutonomyError::InvalidInput(_)));
    }

    #[test]
    fn ingest_rejects_empty_payload() {
        let mut agg = ThreatAggregator::new(TimeDuration::hours(24), 5).unwrap();
        let r = ThreatReport::new(TenantId::new(), None, None, Severity::Low, ts_offset(0));
        let err = agg.ingest(r, ts_offset(0)).unwrap_err();
        assert!(matches!(err, AutonomyError::InvalidInput(_)));
    }

    #[test]
    fn emits_nothing_when_below_k() {
        let mut agg = ThreatAggregator::new(TimeDuration::hours(24), 5).unwrap();
        let now = ts_offset(0);
        // Only 4 distinct tenants — below k=5.
        for _ in 0..4 {
            let r = ThreatReport::new(
                TenantId::new(),
                Some("http://evil.example/x".into()),
                None,
                Severity::High,
                now,
            );
            agg.ingest(r, now).unwrap();
        }
        let emits = agg.collect(now);
        assert!(emits.is_empty(), "k-1 should emit nothing, got {emits:?}");
    }

    #[test]
    fn emits_when_k_reached_via_indicator() {
        let mut agg = ThreatAggregator::new(TimeDuration::hours(24), 5).unwrap();
        let now = ts_offset(0);
        for _ in 0..5 {
            let r = ThreatReport::new(
                TenantId::new(),
                Some("http://evil.example/abc".into()),
                None,
                Severity::High,
                now,
            );
            agg.ingest(r, now).unwrap();
        }
        let emits = agg.collect(now);
        assert_eq!(emits.len(), 1, "expected one aggregated finding");
        let f = emits.first().unwrap();
        assert_eq!(f.tenant_count, 5);
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn combines_reports_by_shared_cve() {
        let mut agg = ThreatAggregator::new(TimeDuration::hours(24), 5).unwrap();
        let now = ts_offset(0);
        // Five tenants, each with a completely different indicator
        // string, but all reporting the same CVE id. The aggregator
        // MUST merge them.
        let indicators = [
            "http://a.example/x",
            "https://b.invalid",
            "/var/log/c",
            "host-d-1234",
            "sha256:abcdef",
        ];
        for ind in indicators {
            let r = ThreatReport::new(
                TenantId::new(),
                Some(ind.into()),
                Some(cve("CVE-2025-0001")),
                Severity::Critical,
                now,
            );
            agg.ingest(r, now).unwrap();
        }
        let emits = agg.collect(now);
        assert_eq!(emits.len(), 1, "CVE-keyed cluster should merge");
        let f = emits.first().unwrap();
        assert_eq!(f.tenant_count, 5);
        assert_eq!(f.indicator, "CVE-2025-0001");
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn near_identical_indicators_cluster_via_levenshtein() {
        let mut agg = ThreatAggregator::new(TimeDuration::hours(24), 5).unwrap();
        let now = ts_offset(0);
        // All within Levenshtein distance <= 3 of "evil-host-01".
        let variants = [
            "evil-host-01",
            "evil-host-02",
            "evil-host-03",
            "evil-host-04",
            "evil-host-05",
        ];
        for v in variants {
            let r = ThreatReport::new(TenantId::new(), Some(v.into()), None, Severity::Medium, now);
            agg.ingest(r, now).unwrap();
        }
        let emits = agg.collect(now);
        assert_eq!(emits.len(), 1, "Levenshtein cluster should merge");
        assert_eq!(emits.first().unwrap().tenant_count, 5);
    }

    #[test]
    fn forgets_reports_older_than_window() {
        let mut agg = ThreatAggregator::new(TimeDuration::hours(1), 5).unwrap();
        let old = ts_offset(0);
        // Five tenants ingest at t=0.
        for _ in 0..5 {
            let r = ThreatReport::new(
                TenantId::new(),
                Some("indicator-x".into()),
                None,
                Severity::High,
                old,
            );
            agg.ingest(r, old).unwrap();
        }
        // collect right away — five distinct tenants → emit.
        let emits_now = agg.collect(old);
        assert_eq!(emits_now.len(), 1);

        // Now collect with a `now` two hours later — all five reports
        // fall outside the 1h window and the cluster evaporates.
        let later = old + TimeDuration::hours(2);
        let emits_later = agg.collect(later);
        assert!(
            emits_later.is_empty(),
            "stale reports must not emit: {emits_later:?}"
        );
        assert_eq!(agg.cluster_count(), 0, "empty cluster must be evicted");
    }

    #[test]
    fn distinct_tenants_only_count_once() {
        let mut agg = ThreatAggregator::new(TimeDuration::hours(24), 5).unwrap();
        let now = ts_offset(0);
        let single = TenantId::new();
        // Same tenant reports 10 times → counts as 1 distinct tenant.
        for _ in 0..10 {
            let r = ThreatReport::new(single, Some("indicator-y".into()), None, Severity::Low, now);
            agg.ingest(r, now).unwrap();
        }
        let emits = agg.collect(now);
        assert!(emits.is_empty(), "1 tenant must never trip k-anonymity");
    }

    #[test]
    fn finding_does_not_expose_tenant_ids() {
        let mut agg = ThreatAggregator::new(TimeDuration::hours(24), 5).unwrap();
        let now = ts_offset(0);
        let tenants: Vec<TenantId> = (0..5).map(|_| TenantId::new()).collect();
        for tid in &tenants {
            let r = ThreatReport::new(
                *tid,
                Some("opaque-indicator".into()),
                None,
                Severity::Low,
                now,
            );
            agg.ingest(r, now).unwrap();
        }
        let emits = agg.collect(now);
        assert_eq!(emits.len(), 1);
        let json = serde_json::to_string(emits.first().unwrap()).unwrap();
        // Tenant ids MUST NOT appear in the wire format.
        for tid in &tenants {
            assert!(
                !json.contains(&tid.to_string()),
                "tenant id leaked into finding: {json}"
            );
        }
        assert!(json.contains("\"tenant_count\":5"));
    }

    #[test]
    fn levenshtein_basic() {
        assert_eq!(levenshtein("abc", "abc"), 0);
        assert_eq!(levenshtein("abc", "abd"), 1);
        assert_eq!(levenshtein("abc", "xyz"), 3);
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("kitten", "sitting"), 3);
    }

    #[test]
    fn distinct_indicators_do_not_merge() {
        let mut agg = ThreatAggregator::new(TimeDuration::hours(24), 5).unwrap();
        let now = ts_offset(0);
        // Two clusters of 4 tenants each — different indicators, no CVE.
        // Neither cluster should emit at k=5.
        for _ in 0..4 {
            let r1 = ThreatReport::new(
                TenantId::new(),
                Some("aaaaaaaaaa".into()),
                None,
                Severity::Low,
                now,
            );
            agg.ingest(r1, now).unwrap();
            let r2 = ThreatReport::new(
                TenantId::new(),
                Some("zzzzzzzzzz".into()),
                None,
                Severity::Low,
                now,
            );
            agg.ingest(r2, now).unwrap();
        }
        let emits = agg.collect(now);
        assert!(emits.is_empty(), "two below-k clusters must not emit");
        assert_eq!(agg.cluster_count(), 2);
    }
}
