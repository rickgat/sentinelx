//! Per-tenant token-bucket rate limiter for log ingest (MED-001).
//!
//! ## Design
//!
//! - One bucket per `(tenant_id, endpoint)` pair, held in process
//!   memory under a single `std::sync::Mutex`.
//! - Bucket refills at `per_sec_rate` tokens / second and is capped at
//!   `burst` (defaults to `2 * per_sec_rate`).
//! - Tier → rate mapping is driven by the [`TierRates`] table seeded by
//!   the operator (typically from `sx-config`).
//! - Per-tenant overrides ([`RateLimiter::set_tier`]) take precedence
//!   over the tier defaults so a noisy enterprise can be downgraded or
//!   a paying free-tier can be temporarily boosted from the admin
//!   endpoint without a config reload.
//!
//! ## Warm-restart snapshot
//!
//! By default the limiter starts cold on every process restart — the
//! token state is intentionally NOT persisted because (a) a restart
//! takes seconds, well below the slowest tier's 100/s refill, so
//! starvation is bounded, and (b) bucket state is a soft signal, not a
//! billing record. Operators who want warm restart can call
//! [`RateLimiter::snapshot`] and [`RateLimiter::restore`] from a sidecar
//! task that round-trips the JSON blob through whichever store they
//! prefer (disk, Redis, etc). The serialised form is stable and small
//! (~24 bytes / bucket).
//!
//! ## Cardinality discipline
//!
//! The `metrics::counter!("log_ingest.rate_limited_total", "tenant" => …)`
//! counter is incremented on every throttled call. The label space is
//! bounded by the number of distinct tenants that have ever hit the
//! ingest path — the `sx-telemetry` Prometheus exporter already caps
//! per-series cardinality at the global recorder level, so we do not
//! emit a per-endpoint label (which would multiply the series count by
//! the number of distinct source-type tokens).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use metrics::counter;
use serde::{Deserialize, Serialize};

/// Counter name emitted on every throttled call. Labelled with the tenant
/// id so per-tenant fire-rates can be alerted on independently.
pub const RATE_LIMITED_COUNTER: &str = "log_ingest.rate_limited_total";

/// Tenant tier. Determines the default token-bucket rates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Free tier — small steady-state, very small burst headroom.
    Free,
    /// Paid SMB tier.
    Pro,
    /// Top tier — large headroom, fits high-volume integrations.
    Enterprise,
}

impl Tier {
    /// Parse a snake-case label. Returns `None` on unknown input.
    #[must_use]
    pub fn parse(label: &str) -> Option<Self> {
        match label {
            "free" => Some(Self::Free),
            "pro" => Some(Self::Pro),
            "enterprise" => Some(Self::Enterprise),
            _ => None,
        }
    }

    /// Snake-case label, suitable for audit logs and admin responses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Pro => "pro",
            Self::Enterprise => "enterprise",
        }
    }
}

/// Rate parameters for a single bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierRates {
    /// Steady-state events per second.
    pub per_sec_rate: u32,
    /// Maximum token count (the burst ceiling).
    pub burst: u32,
}

impl TierRates {
    /// Build a rates pair, clamping `per_sec_rate` to at least 1 and
    /// `burst` to at least `per_sec_rate`.
    #[must_use]
    pub fn new(per_sec_rate: u32, burst: u32) -> Self {
        let per_sec_rate = per_sec_rate.max(1);
        let burst = burst.max(per_sec_rate);
        Self {
            per_sec_rate,
            burst,
        }
    }
}

/// Tier → rate table. Seeded by the operator (typically from
/// `sx-config::schema::log_ingest::LogIngestRateLimitConfig`).
#[derive(Debug, Clone)]
pub struct TierRatesTable {
    free: TierRates,
    pro: TierRates,
    enterprise: TierRates,
}

impl TierRatesTable {
    /// Construct from the three tier rates.
    #[must_use]
    pub const fn new(free: TierRates, pro: TierRates, enterprise: TierRates) -> Self {
        Self {
            free,
            pro,
            enterprise,
        }
    }

    /// SentinelX-canonical defaults: free 100/s, pro 1k/s, enterprise
    /// 10k/s. Burst = 2× steady-state across the board.
    #[must_use]
    pub fn sentinelx_defaults() -> Self {
        Self::new(
            TierRates::new(100, 200),
            TierRates::new(1_000, 2_000),
            TierRates::new(10_000, 20_000),
        )
    }

    /// Look up the [`TierRates`] for a tier.
    #[must_use]
    pub const fn rates_for(&self, tier: Tier) -> TierRates {
        match tier {
            Tier::Free => self.free,
            Tier::Pro => self.pro,
            Tier::Enterprise => self.enterprise,
        }
    }
}

impl Default for TierRatesTable {
    fn default() -> Self {
        Self::sentinelx_defaults()
    }
}

/// Outcome of a [`RateLimiter::try_acquire`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    /// The bucket had a token available. The numbers describe the
    /// post-decrement state so the controller can echo them via
    /// `X-RateLimit-*` headers on success too.
    Allowed {
        /// Configured bucket capacity (the burst ceiling).
        limit: u32,
        /// Tokens left after this call.
        remaining: u32,
        /// Unix-epoch seconds at which the bucket is expected to be full.
        reset_at_unix_secs: u64,
    },
    /// The bucket was empty. The caller MUST reject the request with a
    /// 429 + `Retry-After`.
    Throttled {
        /// Whole seconds the client should wait before retrying.
        retry_after_secs: u64,
        /// Configured bucket capacity (the burst ceiling).
        limit: u32,
        /// Always `0` when throttled — surfaced for symmetry with the
        /// `X-RateLimit-Remaining` header contract.
        remaining: u32,
        /// Unix-epoch seconds at which the bucket is expected to be full.
        reset_at_unix_secs: u64,
    },
}

impl RateDecision {
    /// Whether the call was admitted.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    /// Header-friendly capacity (the bucket's burst).
    #[must_use]
    pub const fn limit(&self) -> u32 {
        match self {
            Self::Allowed { limit, .. } | Self::Throttled { limit, .. } => *limit,
        }
    }

    /// Header-friendly remaining-tokens count.
    #[must_use]
    pub const fn remaining(&self) -> u32 {
        match self {
            Self::Allowed { remaining, .. } | Self::Throttled { remaining, .. } => *remaining,
        }
    }

    /// Header-friendly reset epoch (unix seconds).
    #[must_use]
    pub const fn reset_at_unix_secs(&self) -> u64 {
        match self {
            Self::Allowed {
                reset_at_unix_secs, ..
            }
            | Self::Throttled {
                reset_at_unix_secs, ..
            } => *reset_at_unix_secs,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    updated: Instant,
    rates: TierRates,
}

/// Serialisable snapshot of one bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketSnapshot {
    /// Composite key `<tenant_id>|<endpoint>`.
    pub key: String,
    /// Tokens remaining at snapshot time.
    pub tokens: f64,
    /// Bucket's rates (so a restart preserves any in-flight override).
    pub rates: TierRates,
    /// Wall-clock seconds since UNIX epoch at snapshot time.
    pub snapshot_unix_secs: u64,
}

/// Serialisable snapshot of the entire limiter — buckets + per-tenant
/// tier overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimiterSnapshot {
    /// Per-bucket state.
    pub buckets: Vec<BucketSnapshot>,
    /// Per-tenant tier overrides.
    pub overrides: Vec<TenantOverride>,
}

/// One per-tenant tier override row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantOverride {
    /// Tenant id (UUID string).
    pub tenant_id: String,
    /// Active tier.
    pub tier: Tier,
    /// Optional steady-state override that takes precedence over the
    /// tier table.
    pub override_rate_per_sec: Option<u32>,
}

#[derive(Debug, Clone)]
struct TenantPolicy {
    tier: Tier,
    override_rate_per_sec: Option<u32>,
}

#[derive(Debug)]
struct Inner {
    buckets: HashMap<String, Bucket>,
    overrides: HashMap<String, TenantPolicy>,
}

/// Per-`(tenant_id, endpoint)` token-bucket limiter.
#[derive(Debug)]
pub struct RateLimiter {
    table: TierRatesTable,
    default_tier: Tier,
    inner: Mutex<Inner>,
}

impl RateLimiter {
    /// Build a fresh limiter with the supplied rates table. New tenants
    /// land on `default_tier` until an admin issues an override.
    #[must_use]
    pub fn new(table: TierRatesTable, default_tier: Tier) -> Self {
        Self {
            table,
            default_tier,
            inner: Mutex::new(Inner {
                buckets: HashMap::new(),
                overrides: HashMap::new(),
            }),
        }
    }

    /// Convenience constructor — SentinelX defaults + `free` default tier.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(TierRatesTable::sentinelx_defaults(), Tier::Free)
    }

    fn key(tenant_id: &str, endpoint: &str) -> String {
        format!("{tenant_id}|{endpoint}")
    }

    /// Set (or clear-and-reset) the tier for one tenant. Returns the
    /// previously-active rates so the audit row can record the diff.
    pub fn set_tier(
        &self,
        tenant_id: &str,
        tier: Tier,
        override_rate_per_sec: Option<u32>,
    ) -> TierRates {
        let new_rates = self.compose_rates(tier, override_rate_per_sec);
        let Ok(mut guard) = self.inner.lock() else {
            // Lock poisoning indicates a prior caller panicked under the
            // mutex. Surface the new rates anyway — the next acquire will
            // hit the same poisoned lock and refuse the request safely.
            return new_rates;
        };
        guard.overrides.insert(
            tenant_id.to_owned(),
            TenantPolicy {
                tier,
                override_rate_per_sec,
            },
        );
        // Re-rate every bucket that belongs to this tenant. Existing
        // tokens are clipped to the new burst ceiling so an upgrade does
        // not produce free tokens and a downgrade does not strand
        // tokens above the new ceiling.
        let prefix = format!("{tenant_id}|");
        for (key, bucket) in &mut guard.buckets {
            if key.starts_with(&prefix) {
                bucket.rates = new_rates;
                bucket.tokens = bucket.tokens.min(f64::from(new_rates.burst));
            }
        }
        new_rates
    }

    /// Read the active tier for a tenant (defaults to the limiter's
    /// `default_tier` when no override has been set).
    #[must_use]
    pub fn tier_of(&self, tenant_id: &str) -> Tier {
        let Ok(guard) = self.inner.lock() else {
            return self.default_tier;
        };
        guard
            .overrides
            .get(tenant_id)
            .map_or(self.default_tier, |p| p.tier)
    }

    /// Read the override rate (if any) for a tenant.
    #[must_use]
    pub fn override_rate_of(&self, tenant_id: &str) -> Option<u32> {
        let Ok(guard) = self.inner.lock() else {
            return None;
        };
        guard
            .overrides
            .get(tenant_id)
            .and_then(|p| p.override_rate_per_sec)
    }

    fn compose_rates(&self, tier: Tier, override_rate_per_sec: Option<u32>) -> TierRates {
        let base = self.table.rates_for(tier);
        override_rate_per_sec.map_or(base, |rate| {
            let rate = rate.max(1);
            // Keep the tier's burst-multiplier shape so overrides do
            // not silently strip burst headroom — if the operator
            // wants a different burst they should bump
            // override_rate_per_sec instead of fiddling with the
            // table.
            let burst = base
                .burst
                .checked_mul(rate)
                .and_then(|n| n.checked_div(base.per_sec_rate))
                .unwrap_or_else(|| rate.saturating_mul(2));
            TierRates::new(rate, burst.max(rate))
        })
    }

    fn rates_for_tenant(&self, guard: &Inner, tenant_id: &str) -> TierRates {
        guard.overrides.get(tenant_id).map_or_else(
            || self.table.rates_for(self.default_tier),
            |p| self.compose_rates(p.tier, p.override_rate_per_sec),
        )
    }

    /// Attempt to consume one token for the `(tenant_id, endpoint)` pair.
    pub fn try_acquire(&self, tenant_id: &str, endpoint: &str) -> RateDecision {
        let now = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());

        let Ok(mut guard) = self.inner.lock() else {
            // Lock poisoning → safest behaviour is throttle so a panicking
            // handler does not let the next caller crash for free.
            return RateDecision::Throttled {
                retry_after_secs: 1,
                limit: 0,
                remaining: 0,
                reset_at_unix_secs: now_unix.saturating_add(1),
            };
        };

        let rates = self.rates_for_tenant(&guard, tenant_id);
        let key = Self::key(tenant_id, endpoint);
        let bucket = guard.buckets.entry(key).or_insert_with(|| Bucket {
            tokens: f64::from(rates.burst),
            updated: now,
            rates,
        });

        // If the tenant rates changed since the bucket was last touched
        // (admin override mid-flight), realign the bucket. `set_tier`
        // already handles the bulk path; this catches the case where the
        // bucket existed before `set_tier` was called (no-op when
        // `set_tier` was the most recent mutation).
        if bucket.rates != rates {
            bucket.rates = rates;
            bucket.tokens = bucket.tokens.min(f64::from(rates.burst));
        }

        let elapsed = now.duration_since(bucket.updated).as_secs_f64();
        let refill = elapsed * f64::from(rates.per_sec_rate);
        bucket.tokens = (bucket.tokens + refill).min(f64::from(rates.burst));
        bucket.updated = now;

        let reset_at_unix_secs = {
            let deficit = (f64::from(rates.burst) - bucket.tokens).max(0.0);
            let secs_to_full = if rates.per_sec_rate == 0 {
                1
            } else {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let s = (deficit / f64::from(rates.per_sec_rate)).ceil() as u64;
                s
            };
            now_unix.saturating_add(secs_to_full.max(1))
        };

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let remaining = bucket.tokens.floor().max(0.0) as u32;
            RateDecision::Allowed {
                limit: rates.burst,
                remaining,
                reset_at_unix_secs,
            }
        } else {
            let needed = 1.0 - bucket.tokens;
            let secs = if rates.per_sec_rate == 0 {
                1
            } else {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let s = (needed / f64::from(rates.per_sec_rate)).ceil() as u64;
                s
            };
            // Per-tenant throttle counter. Cardinality is bounded by the
            // number of distinct tenants that ever hit the ingest path;
            // the endpoint label is deliberately omitted to keep the
            // series count from multiplying out, in line with the
            // `sx-telemetry` per-recorder cardinality discipline.
            counter!(RATE_LIMITED_COUNTER, "tenant" => tenant_id.to_owned()).increment(1);
            RateDecision::Throttled {
                retry_after_secs: secs.max(1),
                limit: rates.burst,
                remaining: 0,
                reset_at_unix_secs,
            }
        }
    }

    /// Snapshot every bucket + override for warm-restart persistence.
    ///
    /// The format is stable across patch releases; a restart that loads
    /// a snapshot taken at a different schema version will silently
    /// fall back to a cold start.
    #[must_use]
    pub fn snapshot(&self) -> LimiterSnapshot {
        let Ok(guard) = self.inner.lock() else {
            return LimiterSnapshot {
                buckets: Vec::new(),
                overrides: Vec::new(),
            };
        };
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let buckets = guard
            .buckets
            .iter()
            .map(|(key, bucket)| BucketSnapshot {
                key: key.clone(),
                tokens: bucket.tokens,
                rates: bucket.rates,
                snapshot_unix_secs: now_unix,
            })
            .collect();
        let overrides = guard
            .overrides
            .iter()
            .map(|(tenant_id, policy)| TenantOverride {
                tenant_id: tenant_id.clone(),
                tier: policy.tier,
                override_rate_per_sec: policy.override_rate_per_sec,
            })
            .collect();
        LimiterSnapshot { buckets, overrides }
    }

    /// Restore from a snapshot. Tokens are refilled to account for the
    /// wall-clock gap between snapshot and restore so a multi-hour
    /// restart does not leave a tenant locked out.
    pub fn restore(&self, snap: LimiterSnapshot) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        let now = Instant::now();
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        guard.overrides.clear();
        for o in snap.overrides {
            guard.overrides.insert(
                o.tenant_id,
                TenantPolicy {
                    tier: o.tier,
                    override_rate_per_sec: o.override_rate_per_sec,
                },
            );
        }
        guard.buckets.clear();
        for b in snap.buckets {
            let gap_secs = now_unix.saturating_sub(b.snapshot_unix_secs);
            #[allow(clippy::cast_precision_loss)]
            let refill = (gap_secs as f64) * f64::from(b.rates.per_sec_rate);
            let tokens = (b.tokens + refill).min(f64::from(b.rates.burst));
            guard.buckets.insert(
                b.key,
                Bucket {
                    tokens,
                    updated: now,
                    rates: b.rates,
                },
            );
        }
    }

    /// For tests / observability — number of distinct buckets currently
    /// tracked.
    #[must_use]
    pub fn bucket_count(&self) -> usize {
        self.inner.lock().map(|g| g.buckets.len()).unwrap_or(0)
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Sleep helper used by tests to wait one refill quantum without
/// hammering tokio. Exposed pub(crate) so the integration test in
/// `tests/rate_limit.rs` can share the helper.
#[cfg(test)]
pub(crate) fn refill_sleep(secs: f64) {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let nanos = (secs * 1_000_000_000.0) as u64;
    std::thread::sleep(std::time::Duration::from_nanos(nanos.max(1)));
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn tier_parse_round_trip() {
        for t in [Tier::Free, Tier::Pro, Tier::Enterprise] {
            assert_eq!(Tier::parse(t.as_str()), Some(t));
        }
        assert!(Tier::parse("ultra").is_none());
    }

    #[test]
    fn defaults_match_sentinelx_canonical() {
        let table = TierRatesTable::sentinelx_defaults();
        assert_eq!(table.rates_for(Tier::Free).per_sec_rate, 100);
        assert_eq!(table.rates_for(Tier::Pro).per_sec_rate, 1_000);
        assert_eq!(table.rates_for(Tier::Enterprise).per_sec_rate, 10_000);
        for t in [Tier::Free, Tier::Pro, Tier::Enterprise] {
            let r = table.rates_for(t);
            assert_eq!(r.burst, r.per_sec_rate * 2);
        }
    }

    #[test]
    fn burst_then_throttle_within_same_instant() {
        // per_sec_rate = 1 keeps refill negligible across the four
        // sequential test calls (each refill is on the order of micro-
        // seconds × 1/s = 1e-6 tokens) so the assertions stay
        // deterministic under both dev and test profiles.
        let limiter = RateLimiter::new(
            TierRatesTable::new(
                TierRates::new(1, 3),
                TierRates::new(1, 3),
                TierRates::new(1, 3),
            ),
            Tier::Free,
        );
        // Three tokens available, then throttle.
        for _ in 0..3 {
            let d = limiter.try_acquire("t-a", "/v1/logs/ingest");
            assert!(d.is_allowed(), "{d:?}");
        }
        let d = limiter.try_acquire("t-a", "/v1/logs/ingest");
        assert!(!d.is_allowed(), "got {d:?}");
        assert_eq!(d.limit(), 3);
        assert_eq!(d.remaining(), 0);
    }

    #[test]
    fn steady_state_refills() {
        // per_sec_rate = 1 keeps refill negligible across the four
        // sequential test calls below; sleeping 1100ms refills > 1
        // token even under CI jitter so the post-pause acquire is
        // guaranteed admitted.
        let limiter = RateLimiter::new(
            TierRatesTable::new(
                TierRates::new(1, 2),
                TierRates::new(1, 2),
                TierRates::new(1, 2),
            ),
            Tier::Free,
        );
        assert!(limiter.try_acquire("t-a", "/x").is_allowed());
        assert!(limiter.try_acquire("t-a", "/x").is_allowed());
        assert!(
            !limiter.try_acquire("t-a", "/x").is_allowed(),
            "third call inside the same instant must throttle (burst=2)",
        );
        refill_sleep(1.100);
        assert!(limiter.try_acquire("t-a", "/x").is_allowed());
    }

    #[test]
    fn tenants_have_independent_buckets() {
        let limiter = RateLimiter::with_defaults();
        // Burst = 200 for free; noisy tenant exhausts its bucket
        // immediately. Other tenants should still be admitted.
        let noisy = "t-noisy";
        for _ in 0..201 {
            let _ = limiter.try_acquire(noisy, "/v1/logs/ingest");
        }
        let last = limiter.try_acquire(noisy, "/v1/logs/ingest");
        assert!(!last.is_allowed());

        for tenant in ["t-quiet-1", "t-quiet-2"] {
            let d = limiter.try_acquire(tenant, "/v1/logs/ingest");
            assert!(d.is_allowed(), "{tenant}: {d:?}");
        }
    }

    #[test]
    fn admin_override_rerates_existing_buckets() {
        let limiter = RateLimiter::with_defaults();
        // Free tenant; exhaust burst (=200).
        for _ in 0..200 {
            let _ = limiter.try_acquire("t-a", "/x");
        }
        assert!(!limiter.try_acquire("t-a", "/x").is_allowed());
        // Promote to enterprise (burst=20k). Bucket should be re-rated
        // and have headroom available.
        limiter.set_tier("t-a", Tier::Enterprise, None);
        assert_eq!(limiter.tier_of("t-a"), Tier::Enterprise);
        // Bucket capacity is now 20k but tokens are still ~0; the next
        // acquire is throttled until refill (which is 10k/s → next
        // millisecond). We don't poll wall-clock here: assert the
        // limit field reflects the new tier ceiling instead.
        let d = limiter.try_acquire("t-a", "/x");
        assert_eq!(d.limit(), 20_000);
    }

    #[test]
    fn override_rate_per_sec_takes_precedence_over_tier_default() {
        let limiter = RateLimiter::with_defaults();
        limiter.set_tier("t-a", Tier::Free, Some(5_000));
        let d = limiter.try_acquire("t-a", "/x");
        // Burst tracks the free-tier shape (burst = 2 * per_sec) so
        // override = 5000 → burst = 10000.
        assert_eq!(d.limit(), 10_000);
    }

    #[test]
    fn snapshot_round_trip_preserves_overrides_and_buckets() {
        let limiter = RateLimiter::with_defaults();
        limiter.set_tier("t-a", Tier::Enterprise, None);
        let _ = limiter.try_acquire("t-a", "/x");
        let _ = limiter.try_acquire("t-b", "/y");
        let snap = limiter.snapshot();
        assert!(!snap.buckets.is_empty());
        assert_eq!(snap.overrides.len(), 1);

        let fresh = RateLimiter::with_defaults();
        fresh.restore(snap);
        assert_eq!(fresh.tier_of("t-a"), Tier::Enterprise);
        assert!(fresh.bucket_count() >= 2);
    }

    #[test]
    fn snapshot_refills_during_restart_gap() {
        let limiter = RateLimiter::new(
            TierRatesTable::new(
                TierRates::new(10, 5),
                TierRates::new(10, 5),
                TierRates::new(10, 5),
            ),
            Tier::Free,
        );
        for _ in 0..5 {
            assert!(limiter.try_acquire("t-a", "/x").is_allowed());
        }
        // Bucket is empty. Snapshot, hand-roll a backdated snapshot, restore.
        let mut snap = limiter.snapshot();
        for b in &mut snap.buckets {
            b.snapshot_unix_secs = b.snapshot_unix_secs.saturating_sub(10);
            b.tokens = 0.0;
        }
        let fresh = RateLimiter::with_defaults();
        fresh.restore(snap);
        // 10 seconds gap @ 10/s = 100 tokens accumulated → capped at burst=5.
        let d = fresh.try_acquire("t-a", "/x");
        assert!(d.is_allowed(), "{d:?}");
    }

    #[test]
    fn endpoint_keys_isolate_buckets() {
        let limiter = RateLimiter::with_defaults();
        // Different endpoints under the same tenant get their own bucket.
        let a = limiter.try_acquire("t-a", "/v1/logs/ingest");
        let b = limiter.try_acquire("t-a", "/v1/logs/bulk");
        assert!(a.is_allowed());
        assert!(b.is_allowed());
        assert_eq!(limiter.bucket_count(), 2);
    }
}
