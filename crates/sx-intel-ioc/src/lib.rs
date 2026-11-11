//! # `sx-intel-ioc`
//!
//! Threat-intelligence indicator-of-compromise (IOC) store for `SentinelX`.
//!
//! Two pieces ship in this crate:
//!
//! 1. A [`bloom::ShardedBloomFilter`] for high-throughput `is_known_ioc(...)`
//!    lookups in expected-`O(1)` time. The filter is sharded across 16
//!    independent sub-filters (one mutex each) so write/read traffic
//!    parallelises naturally.
//! 2. A [`clickhouse::ClickHouseLink`] trait describing the cold-storage
//!    projection sink for findings + audit events, the
//!    [`clickhouse::NoopClickHouseLink`] stub used in tests / non-prod, and a
//!    production [`clickhouse_http::HttpClickHouseLink`] HTTP / `JSONEachRow`
//!    client, and the idempotent
//!    [`clickhouse_migrations::ClickHouseMigrator`] schema runner. Batching
//!    and retry decorators are tracked separately — see the
//!    `TODO` in [`clickhouse`].
//!
//! ## Indicator model
//!
//! [`Indicator`] is a tiny value object covering the three IOC flavours the
//! Phase-1 ingestion pipeline produces: IPs, domains, and file hashes. The
//! string form is whatever the upstream feed publishes — we do not normalise
//! IPs (e.g. IPv6 forms) or down-case domains here, because the upstream
//! ingestion layer owns canonicalisation.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod bloom;
pub mod clickhouse;
pub mod clickhouse_batched;
pub mod clickhouse_http;
pub mod clickhouse_migrations;

use std::sync::Arc;

use serde::{Deserialize, Serialize};

pub use crate::bloom::{
    BloomParams, ShardedBloomFilter, DEFAULT_CAPACITY, DEFAULT_FPR, SHARD_COUNT,
};
pub use crate::clickhouse::{
    AuditProjection, ClickHouseError, ClickHouseLink, FindingProjection, NoopClickHouseLink,
};
pub use crate::clickhouse_batched::{BatchingClickHouseLink, BatchingConfig, OnError};
pub use crate::clickhouse_http::{ClickHouseConfig, HttpClickHouseLink};
pub use crate::clickhouse_migrations::{ClickHouseMigrator, MigrationError};

/// Categorical kind of an indicator-of-compromise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorKind {
    /// IPv4 or IPv6 address in textual form.
    Ip,
    /// Fully-qualified domain name.
    Domain,
    /// File hash (sha256 hex, md5 hex, ...) — opaque string at this layer.
    Hash,
}

/// A single indicator-of-compromise entry as ingested from a threat feed.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Indicator {
    /// Classification of the [`Self::value`] payload.
    pub kind: IndicatorKind,
    /// The actual indicator string — IP literal, FQDN, or hash hex.
    pub value: String,
}

impl Indicator {
    /// Build an indicator from its kind + raw string.
    #[must_use]
    pub const fn new(kind: IndicatorKind, value: String) -> Self {
        Self { kind, value }
    }

    /// Build an IP indicator. No validation — upstream is responsible.
    #[must_use]
    pub const fn ip(value: String) -> Self {
        Self::new(IndicatorKind::Ip, value)
    }

    /// Build a domain indicator.
    #[must_use]
    pub const fn domain(value: String) -> Self {
        Self::new(IndicatorKind::Domain, value)
    }

    /// Build a file-hash indicator.
    #[must_use]
    pub const fn hash(value: String) -> Self {
        Self::new(IndicatorKind::Hash, value)
    }

    /// Borrow the textual value used as the bloom-filter key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.value
    }
}

/// Composite IOC store: bloom filter for hot lookups + a [`ClickHouseLink`]
/// for cold-storage projection.
///
/// The store is `Send + Sync` and cheap to clone — both fields are reference
/// counted under the hood. Typical usage is to construct one per process and
/// share an `Arc<IocStore>` across worker tasks.
#[derive(Debug, Clone)]
pub struct IocStore {
    /// Shared bloom filter — internally sharded for concurrent access.
    pub bloom: Arc<ShardedBloomFilter>,
    /// Sink for cold-storage projections.
    pub materialised: Arc<dyn ClickHouseLink>,
}

impl IocStore {
    /// Build a store with the default 10M / 1% bloom and a noop `ClickHouse`
    /// link. Suitable for tests and non-prod environments.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self {
            bloom: Arc::new(ShardedBloomFilter::with_defaults()),
            materialised: Arc::new(NoopClickHouseLink),
        }
    }

    /// Build a store with explicit dependencies.
    #[must_use]
    pub fn new(bloom: Arc<ShardedBloomFilter>, materialised: Arc<dyn ClickHouseLink>) -> Self {
        Self {
            bloom,
            materialised,
        }
    }

    /// Insert an indicator into the bloom filter.
    ///
    /// The cold-storage projection is *not* updated here; callers wishing to
    /// persist the indicator should use [`Self::materialised`] explicitly
    /// (the projection schema is finding-centric, not IOC-centric).
    pub fn insert(&self, indicator: &Indicator) {
        self.bloom.insert(indicator.key());
    }

    /// Probe an arbitrary key — IP literal, domain string, or hash hex —
    /// against the bloom filter.
    ///
    /// Returns `true` if the key may have been inserted (with at most the
    /// configured FPR of false positives), `false` if it certainly was not.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.bloom.contains(key)
    }

    /// Convenience wrapper that probes by [`Indicator`] (uses the same key
    /// space as [`Self::insert`]).
    #[must_use]
    pub fn contains_indicator(&self, indicator: &Indicator) -> bool {
        self.bloom.contains(indicator.key())
    }
}

impl Default for IocStore {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn insert_indicator_adds_to_bloom() {
        let store = IocStore::with_defaults();
        let ind = Indicator::domain("evil.example.com".to_string());
        assert!(
            !store.contains_indicator(&ind),
            "fresh store should not contain the indicator yet",
        );
        store.insert(&ind);
        assert!(
            store.contains_indicator(&ind),
            "after insert, contains_indicator should report true",
        );
    }

    #[test]
    fn contains_via_indicator_kind() {
        let store = IocStore::with_defaults();
        let ip = Indicator::ip("203.0.113.42".to_string());
        let domain = Indicator::domain("phish.invalid".to_string());
        let hash = Indicator::hash(
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".to_string(),
        );
        store.insert(&ip);
        store.insert(&domain);
        store.insert(&hash);

        assert!(store.contains("203.0.113.42"));
        assert!(store.contains("phish.invalid"));
        assert!(store.contains("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",));

        // Kind variants are distinguished only by string value at the bloom
        // layer; querying via Indicator wrappers must still resolve.
        assert!(store.contains_indicator(&ip));
        assert!(store.contains_indicator(&domain));
        assert!(store.contains_indicator(&hash));
    }

    #[test]
    fn noop_clickhouse_link_accepts_batches() {
        let store = IocStore::with_defaults();
        // Round-trip through the trait object to make sure the type is
        // dyn-compatible and the noop sink swallows batches without error.
        let link = &store.materialised;
        let findings = vec![FindingProjection {
            id: "11111111-1111-1111-1111-111111111111".to_string(),
            tenant_id: "22222222-2222-2222-2222-222222222222".to_string(),
            severity: "high".to_string(),
            cvss: 8.4,
            ts_epoch_secs: 1_700_000_000,
        }];
        let audit = vec![AuditProjection {
            tenant_id: "22222222-2222-2222-2222-222222222222".to_string(),
            seq: 42,
            action: "finding.update".to_string(),
            actor: "system:scanner".to_string(),
            ts_epoch_secs: 1_700_000_000,
        }];
        mini_block_on(async {
            link.write_findings(&findings).await.unwrap();
            link.write_audit(&audit).await.unwrap();
        });
    }

    /// Single-poll executor — we don't take a tokio dev-dependency just for
    /// this one assertion, and every noop future here resolves on first poll.
    fn mini_block_on<F: std::future::Future>(fut: F) -> F::Output {
        use std::pin::Pin;
        use std::sync::Arc as StdArc;
        use std::task::{Context, Poll, Wake, Waker};

        struct Noop;
        impl Wake for Noop {
            fn wake(self: StdArc<Self>) {}
        }
        let waker: Waker = StdArc::new(Noop).into();
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(fut);
        loop {
            match Pin::as_mut(&mut fut).poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => {
                    // Noop futures resolve on first poll; we should never get
                    // here under the test workload, but if we did the loop
                    // would spin instead of deadlocking the test runner.
                }
            }
        }
    }
}
