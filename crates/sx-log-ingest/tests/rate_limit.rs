//! Integration tests for the per-tenant log-ingest rate limiter (MED-001).
//!
//! These tests run against the public `RateLimiter` surface and assert
//! end-to-end the two properties the spec calls out:
//!
//! 1. **Burst-then-steady** — a fresh bucket admits a full burst then
//!    throttles, and after a wall-clock pause the bucket refills enough
//!    to admit the next call.
//! 2. **Fair-share across tenants** — one noisy tenant cannot starve
//!    other tenants; each `(tenant_id, endpoint)` pair has its own
//!    bucket and the noisy tenant's drained bucket has no effect on the
//!    quiet tenants' buckets.
//!
//! ## Note on rates
//!
//! These tests use `per_sec_rate = 1` deliberately. `TierRates::new`
//! clamps `burst >= per_sec_rate`, so picking `per_sec_rate = 1` lets
//! the test pin the burst ceiling to a small explicit number (3, 5,
//! …) without the clamp surprising the assertions. The trade-off is
//! that the post-pause refill test has to sleep > 1 second, which we
//! accept for determinism.

#![allow(clippy::unwrap_used, clippy::float_cmp)]

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use sx_log_ingest::rate_limit::{RateLimiter, Tier, TierRates, TierRatesTable};

const INGEST_ENDPOINT: &str = "/v1/logs/ingest";

fn small_limiter(per_sec: u32, burst: u32) -> RateLimiter {
    let rates = TierRates::new(per_sec, burst);
    RateLimiter::new(TierRatesTable::new(rates, rates, rates), Tier::Free)
}

#[test]
fn burst_then_steady_refills_after_pause() {
    // per_sec_rate = 1 + burst = 5 means the bucket admits exactly 5
    // calls before throttling, and 1.1s of sleep refills at least 1
    // token (cap = 5) so the post-pause acquire is admitted.
    let limiter = small_limiter(1, 5);
    let tenant = "tenant-burst";

    // Burst admits 5 successive events.
    for n in 0..5 {
        let d = limiter.try_acquire(tenant, INGEST_ENDPOINT);
        assert!(d.is_allowed(), "expected admit #{n}, got {d:?}");
    }

    // Sixth event throttles — bucket is empty.
    let throttled = limiter.try_acquire(tenant, INGEST_ENDPOINT);
    assert!(
        !throttled.is_allowed(),
        "expected throttle, got {throttled:?}"
    );
    assert_eq!(throttled.limit(), 5);
    assert_eq!(throttled.remaining(), 0);

    // Wait long enough for at least one token to refill (1/s => 1s
    // per token; sleep 1.1s to leave headroom under CI jitter).
    thread::sleep(Duration::from_millis(1_100));

    let refilled = limiter.try_acquire(tenant, INGEST_ENDPOINT);
    assert!(
        refilled.is_allowed(),
        "expected admit after refill, got {refilled:?}"
    );
}

#[test]
fn fair_share_noisy_tenant_does_not_starve_quiet_tenants() {
    // Burst = 3 so the noisy tenant can be drained in 4 calls.
    let limiter = small_limiter(1, 3);
    let noisy = "tenant-noisy";
    let quiet1 = "tenant-quiet-1";
    let quiet2 = "tenant-quiet-2";

    // Drain the noisy tenant's bucket (3 admits + 1 throttle).
    for _ in 0..3 {
        let d = limiter.try_acquire(noisy, INGEST_ENDPOINT);
        assert!(d.is_allowed());
    }
    let after = limiter.try_acquire(noisy, INGEST_ENDPOINT);
    assert!(!after.is_allowed(), "noisy bucket should now be empty");

    // Both quiet tenants must STILL get full burst on the same endpoint.
    for tenant in [quiet1, quiet2] {
        for n in 0..3 {
            let d = limiter.try_acquire(tenant, INGEST_ENDPOINT);
            assert!(
                d.is_allowed(),
                "{tenant} call #{n} should be admitted while noisy is starving, got {d:?}"
            );
        }
        let fourth = limiter.try_acquire(tenant, INGEST_ENDPOINT);
        assert!(
            !fourth.is_allowed(),
            "{tenant} fourth call hits its own burst ceiling"
        );
    }

    // And the noisy tenant should STILL be throttled — the quiet
    // tenants' admits did not consume tokens from the noisy bucket.
    let still_starving = limiter.try_acquire(noisy, INGEST_ENDPOINT);
    assert!(
        !still_starving.is_allowed(),
        "noisy bucket should still be empty after quiet activity"
    );
}

#[test]
fn fair_share_three_tenants_share_independent_refill() {
    // After a refill window, all three tenants should each get a
    // fresh token — proves the per-tenant accounting is fully
    // independent.
    let limiter = small_limiter(1, 2);
    let tenants = ["t-a", "t-b", "t-c"];

    // Drain all three.
    for t in tenants {
        for _ in 0..2 {
            assert!(limiter.try_acquire(t, INGEST_ENDPOINT).is_allowed());
        }
        assert!(!limiter.try_acquire(t, INGEST_ENDPOINT).is_allowed());
    }

    // Wait for ~1 token per tenant (1/s -> 1s each; sleep 1.1s).
    thread::sleep(Duration::from_millis(1_100));

    for t in tenants {
        let d = limiter.try_acquire(t, INGEST_ENDPOINT);
        assert!(d.is_allowed(), "{t}: expected post-refill admit, got {d:?}");
    }
}

#[test]
fn endpoint_label_isolates_buckets_within_one_tenant() {
    // Same tenant, two distinct endpoint labels — each gets its own
    // bucket so a noisy single-event endpoint does not starve the
    // bulk endpoint (or vice-versa).
    let limiter = small_limiter(1, 2);
    let tenant = "tenant-multi-endpoint";

    for _ in 0..2 {
        assert!(limiter.try_acquire(tenant, "/v1/logs/ingest").is_allowed());
    }
    assert!(!limiter.try_acquire(tenant, "/v1/logs/ingest").is_allowed());

    // Bulk endpoint must still have a full burst.
    for _ in 0..2 {
        assert!(limiter.try_acquire(tenant, "/v1/logs/bulk").is_allowed());
    }
}

#[test]
fn admin_override_takes_effect_on_next_acquire() {
    let limiter = small_limiter(1, 2);
    let tenant = "tenant-override";

    // Drain on the default tier.
    for _ in 0..2 {
        assert!(limiter.try_acquire(tenant, INGEST_ENDPOINT).is_allowed());
    }
    assert!(!limiter.try_acquire(tenant, INGEST_ENDPOINT).is_allowed());

    // Bump to a much higher rate via override — bucket re-rates,
    // capacity goes up, but tokens are still ~0 so the *limit* field
    // reflects the new ceiling immediately.
    limiter.set_tier(tenant, Tier::Free, Some(10_000));

    let post = limiter.try_acquire(tenant, INGEST_ENDPOINT);
    // The free-tier burst shape is 2× the steady-state on the default
    // table. Our `small_limiter(1, 2)` defines burst:per_sec_rate = 2.
    // The override preserves this shape, so 10_000 → burst 20_000.
    assert_eq!(
        post.limit(),
        20_000,
        "burst ceiling must follow the override; got {post:?}"
    );
}

#[test]
fn snapshot_restore_round_trip_survives_a_fake_restart() {
    let limiter = Arc::new(small_limiter(50, 25));
    let tenant = "tenant-warm-restart";

    // Drain partially.
    for _ in 0..10 {
        assert!(limiter.try_acquire(tenant, INGEST_ENDPOINT).is_allowed());
    }
    let snap = limiter.snapshot();
    assert!(!snap.buckets.is_empty(), "snapshot should capture buckets");

    // Simulate a restart — fresh limiter, then restore.
    let fresh = small_limiter(50, 25);
    fresh.restore(snap);
    assert!(fresh.bucket_count() >= 1);

    // Post-restore the tenant should be able to keep going (refill +
    // remaining tokens combined are enough for at least one call).
    let d = fresh.try_acquire(tenant, INGEST_ENDPOINT);
    assert!(d.is_allowed(), "post-restore tenant must keep flowing");
}
