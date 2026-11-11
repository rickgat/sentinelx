//! `IntelCheckPort` adapter — wraps an [`sx_intel_ioc::IocStore`] and
//! exposes it through the HTTP-facing trait declared in
//! [`sx_api::port::IntelCheckPort`].
//!
//! ## Layering
//!
//! - The composition root (`adapters::build_app_state`) calls
//!   [`build`] which constructs an `IocStore` with the default sharded
//!   bloom geometry (16 shards, 10M capacity, 1% FPR) and seeds it with
//!   a small canned list of known-bad indicators (see [`CANNED_SEED`]).
//! - The adapter holds the store behind an `Arc`; concurrent
//!   `POST /v1/intel/check` traffic fan-outs across the 16 bloom shards
//!   for natural parallelism.
//!
//! ## STIX / TAXII feeds
//!
//! The `sx-intel-feeds` crate is wired in here as a dependency so the
//! ingestion code path can be plumbed without touching the API crate.
//! Live periodic TAXII fetch is intentionally deferred: a future
//! follow-up will read `Settings.intel.feeds.taxii_endpoint` and
//! spawn a `tokio::task::JoinHandle` that pages observables off the
//! collection and inserts them via [`sx_intel_ioc::IocStore::insert`].
//! At this iteration the adapter ships with the canned seed only.
//!
//! ## Kind mapping
//!
//! | Wire `kind`     | Treated as                | Stored as          |
//! |-----------------|---------------------------|--------------------|
//! | `ipv4` / `ipv6` | [`IndicatorKind::Ip`]     | raw value string   |
//! | `domain`        | [`IndicatorKind::Domain`] | raw value string   |
//! | `url`           | [`IndicatorKind::Domain`] | raw value string   |
//! | `hash:sha256`   | [`IndicatorKind::Hash`]   | lowercased hex     |
//!
//! Hashes are lowercased before the bloom probe so the demo seed (which
//! uses lowercase hex) matches incoming queries regardless of case. All
//! other values are passed through verbatim — upstream feeds are
//! expected to publish canonical forms.

use std::sync::Arc;

use async_trait::async_trait;
use sx_api::port::{IntelCheckPort, Phase3PortError};
use sx_api::view::intel_view::{IntelCheckRequest, IntelCheckResponse};
use sx_intel_ioc::{Indicator, IndicatorKind, IocStore, ShardedBloomFilter};

/// Source label attached to every indicator inserted by the canned seed.
///
/// Real STIX/TAXII ingest will replace this with the upstream feed name.
const CANNED_SEED_SOURCE: &str = "sentinelx-canned";

/// Last-seen timestamp attached to every canned-seed hit. Real ingestion
/// pipelines propagate the STIX `modified` / `valid_from` field; the
/// demo seed uses a stable epoch-anchored marker so test assertions are
/// deterministic.
const CANNED_SEED_LAST_SEEN: &str = "1970-01-01T00:00:00Z";

/// Canned seed — 10 known-bad indicators inserted into the bloom filter
/// on adapter boot so the `/v1/intel/check` endpoint is demonstrably
/// useful before any real STIX/TAXII feed is configured.
///
/// The exact values are intentionally synthetic (RFC 5737 / RFC 3849
/// documentation ranges, `example.com` family, deterministic SHA-256
/// digests) so they will never collide with real-world traffic.
const CANNED_SEED: &[(IndicatorKindTag, &str)] = &[
    // IPv4 — documentation prefixes (RFC 5737).
    (IndicatorKindTag::Ip, "198.51.100.7"),
    (IndicatorKindTag::Ip, "203.0.113.42"),
    // IPv6 — documentation prefix (RFC 3849).
    (IndicatorKindTag::Ip, "2001:db8::dead:beef"),
    // Domains — RFC 6761 reserved + documentation.
    (IndicatorKindTag::Domain, "evil.example"),
    (IndicatorKindTag::Domain, "phish.example.com"),
    (IndicatorKindTag::Domain, "c2.malicious.invalid"),
    // URLs — also stored as Domain (the bloom only cares about the key).
    (IndicatorKindTag::Domain, "https://bad.example/payload"),
    // SHA-256 hashes — deterministic literals so tests can assert hits.
    (
        IndicatorKindTag::Hash,
        "0000000000000000000000000000000000000000000000000000000000000001",
    ),
    (
        IndicatorKindTag::Hash,
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    ),
    (
        IndicatorKindTag::Hash,
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    ),
];

/// Local tag used in [`CANNED_SEED`] — kept private so the public surface
/// of the adapter never leaks `sx-intel-ioc` enum variants.
#[derive(Debug, Clone, Copy)]
enum IndicatorKindTag {
    Ip,
    Domain,
    Hash,
}

impl IndicatorKindTag {
    const fn into_ioc(self) -> IndicatorKind {
        match self {
            Self::Ip => IndicatorKind::Ip,
            Self::Domain => IndicatorKind::Domain,
            Self::Hash => IndicatorKind::Hash,
        }
    }
}

/// Bundle exposing the `IntelCheckPort` trait object the composition root
/// stuffs into [`sx_api::AppState`].
#[derive(Clone)]
pub(crate) struct IntelCheckBundle {
    /// Trait-object handle to the indicator-check port. Cheap to clone.
    pub(crate) check: Arc<dyn IntelCheckPort>,
    /// Shared sharded bloom filter — exposed so the TAXII feed orchestrator
    /// (see [`super::intel_feeds_job`]) can insert freshly-ingested
    /// indicators into the same hot-path filter the HTTP `/v1/intel/check`
    /// endpoint reads from. Cheap to clone — internally reference counted.
    pub(crate) bloom: Arc<ShardedBloomFilter>,
}

impl std::fmt::Debug for IntelCheckBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntelCheckBundle").finish_non_exhaustive()
    }
}

/// Build a fresh adapter with the default 10M / 1% FPR bloom and the
/// canned seed pre-loaded.
///
/// Pure (no I/O) — safe to call synchronously from
/// `build_app_state`.
pub(crate) fn build() -> IntelCheckBundle {
    let bloom = Arc::new(ShardedBloomFilter::with_defaults());
    let store = Arc::new(IocStore::new(
        Arc::clone(&bloom),
        Arc::new(sx_intel_ioc::NoopClickHouseLink),
    ));
    seed_canned(&store);
    let check: Arc<dyn IntelCheckPort> = Arc::new(IntelCheckAdapter { store });
    IntelCheckBundle { check, bloom }
}

/// Insert every entry in [`CANNED_SEED`] into `store`. Hashes are
/// lowercased so probes are case-insensitive.
fn seed_canned(store: &IocStore) {
    for &(tag, value) in CANNED_SEED {
        let canonical = canonicalise_for_seed(tag, value);
        let indicator = Indicator::new(tag.into_ioc(), canonical);
        store.insert(&indicator);
    }
}

/// Normalise a seed value before insertion so probes match regardless of
/// case for hash digests. Other kinds are stored verbatim.
fn canonicalise_for_seed(tag: IndicatorKindTag, value: &str) -> String {
    match tag {
        IndicatorKindTag::Hash => value.to_ascii_lowercase(),
        IndicatorKindTag::Ip | IndicatorKindTag::Domain => value.to_owned(),
    }
}

/// Concrete `IntelCheckPort` implementation backed by an `IocStore`.
#[derive(Debug)]
struct IntelCheckAdapter {
    store: Arc<IocStore>,
}

#[async_trait]
impl IntelCheckPort for IntelCheckAdapter {
    async fn check(&self, req: IntelCheckRequest) -> Result<IntelCheckResponse, Phase3PortError> {
        let key = canonicalise_query(&req.kind, &req.value)?;
        let known = self.store.contains(&key);
        if known {
            Ok(IntelCheckResponse {
                known: true,
                source: Some(CANNED_SEED_SOURCE.to_owned()),
                last_seen: Some(CANNED_SEED_LAST_SEEN.to_owned()),
            })
        } else {
            Ok(IntelCheckResponse {
                known: false,
                source: None,
                last_seen: None,
            })
        }
    }
}

/// Normalise an incoming `(kind, value)` pair into the bloom key.
///
/// - Hash kinds are lowercased so case differences don't trigger false
///   negatives against the lowercased seed.
/// - Everything else is passed through verbatim.
///
/// Unknown kinds surface as [`Phase3PortError::Invalid`] (mapped to
/// `422 Unprocessable` at the HTTP boundary). The view-layer validator
/// already rejects these — this is defensive depth in case a non-HTTP
/// caller wires the port directly.
fn canonicalise_query(kind: &str, value: &str) -> Result<String, Phase3PortError> {
    match kind {
        "ipv4" | "ipv6" | "domain" | "url" => Ok(value.to_owned()),
        "hash:sha256" => Ok(value.to_ascii_lowercase()),
        other => Err(Phase3PortError::Invalid(format!(
            "unknown indicator kind: {other}"
        ))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Spec: the canned seed contributes at least 10 indicators.
    #[test]
    fn canned_seed_has_at_least_ten_entries() {
        assert!(
            CANNED_SEED.len() >= 10,
            "canned seed must carry at least 10 indicators, got {}",
            CANNED_SEED.len()
        );
    }

    /// Spec: every seeded indicator must be reported as known.
    #[tokio::test]
    async fn check_returns_known_true_for_every_seed_entry() {
        let bundle = build();
        for &(tag, value) in CANNED_SEED {
            let kind = match tag {
                IndicatorKindTag::Ip => kind_for_ip(value),
                IndicatorKindTag::Domain => domain_or_url(value),
                IndicatorKindTag::Hash => "hash:sha256",
            };
            let resp = bundle
                .check
                .check(IntelCheckRequest {
                    kind: kind.to_owned(),
                    value: value.to_owned(),
                })
                .await
                .unwrap();
            assert!(
                resp.known,
                "seeded indicator `{value}` (kind `{kind}`) should be known",
            );
            assert_eq!(resp.source.as_deref(), Some(CANNED_SEED_SOURCE));
            assert_eq!(resp.last_seen.as_deref(), Some(CANNED_SEED_LAST_SEEN));
        }
    }

    /// Spec: indicators that were never seeded must return `known = false`.
    #[tokio::test]
    async fn check_returns_known_false_for_unseen_indicator() {
        let bundle = build();
        let resp = bundle
            .check
            .check(IntelCheckRequest {
                kind: "domain".into(),
                value: "totally-unseen-domain.test".into(),
            })
            .await
            .unwrap();
        assert!(!resp.known);
        assert!(resp.source.is_none());
        assert!(resp.last_seen.is_none());
    }

    /// Spec: hash queries are case-insensitive against the lowercased seed.
    #[tokio::test]
    async fn check_normalises_hash_case() {
        let bundle = build();
        let upper = "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF".to_owned();
        let resp = bundle
            .check
            .check(IntelCheckRequest {
                kind: "hash:sha256".into(),
                value: upper,
            })
            .await
            .unwrap();
        assert!(resp.known, "hash should match regardless of case");
    }

    /// Spec: kind validation rejects garbage at the adapter (defensive
    /// depth — the view-layer validator already rejects these).
    #[test]
    fn canonicalise_query_rejects_garbage_kind() {
        let err = canonicalise_query("garbage", "x").expect_err("garbage kind should be rejected");
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    /// Spec: probe-by-port survives concurrent traffic from 8 tasks.
    #[tokio::test]
    async fn check_handles_concurrent_traffic_from_eight_tasks() {
        let bundle = build();
        let port = Arc::clone(&bundle.check);
        let mut handles = Vec::with_capacity(8);
        for i in 0..8 {
            let port = Arc::clone(&port);
            handles.push(tokio::spawn(async move {
                // Alternate between a known seed and a fresh unseen value
                // so each task exercises both paths.
                let (kind, value, expect) = if i % 2 == 0 {
                    ("domain", "evil.example".to_owned(), true)
                } else {
                    ("domain", format!("task-{i}.unseen.test"), false)
                };
                let resp = port
                    .check(IntelCheckRequest {
                        kind: kind.to_owned(),
                        value,
                    })
                    .await
                    .unwrap();
                assert_eq!(resp.known, expect);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
    }

    /// Hash kind canonicalisation is checked through the public port too.
    #[tokio::test]
    async fn url_query_routes_through_domain_lookup() {
        let bundle = build();
        let resp = bundle
            .check
            .check(IntelCheckRequest {
                kind: "url".into(),
                value: "https://bad.example/payload".into(),
            })
            .await
            .unwrap();
        assert!(resp.known);
    }

    /// `IndicatorKindTag::into_ioc` covers every variant — exhaustive map
    /// from local tag to the shared sx-intel-ioc enum.
    #[test]
    fn indicator_kind_tag_maps_exhaustively() {
        assert_eq!(IndicatorKindTag::Ip.into_ioc(), IndicatorKind::Ip);
        assert_eq!(IndicatorKindTag::Domain.into_ioc(), IndicatorKind::Domain);
        assert_eq!(IndicatorKindTag::Hash.into_ioc(), IndicatorKind::Hash);
    }

    /// Helper: pick `ipv4` vs `ipv6` from a seeded literal so the
    /// every-seed test exercises both kinds.
    fn kind_for_ip(value: &str) -> &'static str {
        if value.contains(':') {
            "ipv6"
        } else {
            "ipv4"
        }
    }

    /// Helper: pick `url` vs `domain` from a seeded literal.
    fn domain_or_url(value: &str) -> &'static str {
        if value.starts_with("http://") || value.starts_with("https://") {
            "url"
        } else {
            "domain"
        }
    }
}
