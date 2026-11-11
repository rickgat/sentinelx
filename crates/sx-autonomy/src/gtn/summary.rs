//! Aggregated finding produced by the Global Threat Network aggregator.
//!
//! [`AggregatedFinding`] is the only artifact emitted by
//! [`crate::gtn::aggregator::ThreatAggregator`]. Tenant identities are
//! deliberately collapsed to a count — the wire shape guarantees that no
//! single tenant can be reverse-engineered out of an emission. This is the
//! k-anonymous side of the "active mode" GTN: counts only, never ids.
//!
//! # Fields
//!
//! - `indicator` — the canonical indicator that clustered the contributing
//!   reports. Either the IOC string (URL/host/path) or a CVE id string.
//! - `tenant_count` — number of *distinct* tenants whose reports clustered
//!   onto `indicator`. Guaranteed `>= k` by the aggregator (k-anonymity
//!   floor, configurable but never below `MIN_K_ANONYMITY`).
//! - `severity` — the highest severity observed among contributing reports.
//! - `first_seen` / `last_seen` — temporal envelope of the contributing
//!   reports.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// Coarse severity of an aggregated finding.
///
/// Mirrors the standard `CVSS`-style buckets without depending on the rest
/// of the platform's severity types — this keeps the GTN aggregator
/// independent of richer risk-scoring code paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational — no measurable impact.
    Info,
    /// Low — minor or theoretical risk.
    Low,
    /// Medium — notable risk, no widespread compromise expected.
    Medium,
    /// High — significant risk; remediation should be prompt.
    High,
    /// Critical — active or imminent compromise.
    Critical,
}

impl Severity {
    /// Returns the higher of `self` and `other`.
    #[must_use]
    pub const fn max(self, other: Self) -> Self {
        // The derived `Ord` impl orders by declaration position, so the
        // raw `u8` discriminant matches the semantic ranking. Going via
        // discriminant keeps this usable in `const` contexts.
        let l = self as u8;
        let r = other as u8;
        if l >= r {
            self
        } else {
            other
        }
    }
}

/// K-anonymous aggregated finding emitted by the GTN aggregator.
///
/// `tenant_count` is the only tenant-derived field on the wire. Raw
/// tenant ids are dropped at the aggregator boundary and never reach
/// downstream consumers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregatedFinding {
    /// Canonical indicator (IOC string or CVE id) that clustered the
    /// contributing reports.
    pub indicator: String,
    /// Number of distinct tenants that contributed to this cluster.
    /// Guaranteed `>= k` by the aggregator.
    pub tenant_count: u32,
    /// Highest severity observed across contributing reports.
    pub severity: Severity,
    /// Earliest report timestamp in the cluster.
    pub first_seen: OffsetDateTime,
    /// Most recent report timestamp in the cluster.
    pub last_seen: OffsetDateTime,
}

impl AggregatedFinding {
    /// Build a new finding.
    #[must_use]
    pub fn new(
        indicator: impl Into<String>,
        tenant_count: u32,
        severity: Severity,
        first_seen: OffsetDateTime,
        last_seen: OffsetDateTime,
    ) -> Self {
        Self {
            indicator: indicator.into(),
            tenant_count,
            severity,
            first_seen,
            last_seen,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_correctly() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn severity_max_picks_higher() {
        assert_eq!(Severity::Low.max(Severity::High), Severity::High);
        assert_eq!(Severity::Critical.max(Severity::Info), Severity::Critical);
        assert_eq!(Severity::Medium.max(Severity::Medium), Severity::Medium);
    }

    #[test]
    fn finding_serialises_without_tenant_ids() {
        let now = OffsetDateTime::now_utc();
        let f = AggregatedFinding::new("CVE-2025-1234", 7, Severity::High, now, now);
        let json = serde_json::to_string(&f).unwrap();
        assert!(json.contains("\"tenant_count\":7"));
        // Field name `tenant_count` is the only tenant-derived surface.
        assert!(!json.contains("tenant_id"));
        assert!(!json.contains("tenant_hash"));
    }
}
