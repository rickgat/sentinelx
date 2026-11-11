//! Async token-bucket rate limiter used by the NVD fetcher (P0-006).
//!
//! Self-contained: no `governor` dependency. The bucket is parameterised by
//! a capacity (`capacity` tokens) and a refill window (`window`). It hands
//! out one token per call to [`TokenBucket::acquire`], sleeping with
//! [`tokio::time::sleep`] until the next refill if the bucket is empty.
//!
//! Concurrency: a single `Mutex<State>` serialises bucket access. The
//! critical section is O(1) — clamping, refilling, decrementing — so
//! contention is bounded by the number of in-flight fetchers (1 NVD page
//! at a time in practice).
//!
//! NVD enforces two distinct rate limits:
//!
//! | Auth state | Quota |
//! |---|---|
//! | No `apiKey` header | 5 requests / 30 s |
//! | With `apiKey` header | 50 requests / 30 s |
//!
//! Callers pick the appropriate bucket via [`TokenBucket::nvd_unauth`] or
//! [`TokenBucket::nvd_with_key`]. Tests can construct a custom-tuned bucket
//! via [`TokenBucket::new`].
//!
//! ## Why not `governor`?
//!
//! `governor` would bring in `nonzero_ext`, `dashmap`, and `quanta` for a
//! single use-site. A 70-line token bucket has zero new transitive deps and
//! interoperates cleanly with `tokio::time::pause` in tests.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::Instant;

/// Default refill window for the NVD CVE 2.0 API: 30 seconds.
pub const NVD_WINDOW: Duration = Duration::from_secs(30);

/// Unauthenticated NVD quota: 5 requests per 30 s.
pub const NVD_UNAUTH_CAPACITY: u32 = 5;

/// Authenticated NVD quota: 50 requests per 30 s.
pub const NVD_AUTH_CAPACITY: u32 = 50;

#[derive(Debug)]
struct State {
    tokens: f64,
    last_refill: Instant,
}

/// Async token-bucket rate limiter.
///
/// Cheap to clone (interior `Arc<Mutex<_>>`) so multiple call-sites share a
/// single bucket — typically one bucket per upstream API and per process.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    window: Duration,
    state: Arc<Mutex<State>>,
}

impl TokenBucket {
    /// Build a fresh bucket with `capacity` tokens, refilling fully over
    /// `window`. The bucket starts full so the first burst is allowed.
    ///
    /// Degenerate inputs (`capacity == 0`, `window == Duration::ZERO`) are
    /// silently clamped to `(1, 1ms)` rather than panicking — the bucket
    /// is used on a hot path and a misconfiguration shouldn't take down
    /// the fetcher.
    #[must_use]
    pub fn new(capacity: u32, window: Duration) -> Self {
        let capacity = capacity.max(1);
        let window = if window.is_zero() {
            Duration::from_millis(1)
        } else {
            window
        };
        let cap = f64::from(capacity);
        Self {
            capacity: cap,
            window,
            state: Arc::new(Mutex::new(State {
                tokens: cap,
                last_refill: Instant::now(),
            })),
        }
    }

    /// Bucket sized for the unauthenticated NVD quota (5 req / 30 s).
    #[must_use]
    pub fn nvd_unauth() -> Self {
        Self::new(NVD_UNAUTH_CAPACITY, NVD_WINDOW)
    }

    /// Bucket sized for the authenticated NVD quota (50 req / 30 s).
    #[must_use]
    pub fn nvd_with_key() -> Self {
        Self::new(NVD_AUTH_CAPACITY, NVD_WINDOW)
    }

    /// Reserve a single token, sleeping until one is available.
    ///
    /// Refills are proportional: if the bucket has been idle for
    /// `dt` of the `window`, it earns `capacity * dt / window` tokens
    /// (clamped to `capacity`).
    pub async fn acquire(&self) {
        loop {
            let mut state = self.state.lock().await;
            self.refill(&mut state);
            if state.tokens >= 1.0 {
                state.tokens -= 1.0;
                return;
            }
            // How long until we have one full token?
            let deficit = 1.0 - state.tokens;
            let secs = (deficit * self.window.as_secs_f64()) / self.capacity;
            // Floor at 1 ms so we never busy-loop on a 0-Duration wait.
            let wait = Duration::from_secs_f64(secs.max(0.001));
            // Explicitly release the guard before sleeping so other waiters
            // can make progress while this future is parked.
            drop(state);
            tokio::time::sleep(wait).await;
        }
    }

    fn refill(&self, state: &mut State) {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(state.last_refill);
        if elapsed.is_zero() {
            return;
        }
        let added = (self.capacity * elapsed.as_secs_f64()) / self.window.as_secs_f64();
        state.tokens = (state.tokens + added).min(self.capacity);
        state.last_refill = now;
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_cmp
)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn full_bucket_allows_capacity_immediate_acquires() {
        let bucket = TokenBucket::new(3, Duration::from_secs(1));
        let start = Instant::now();
        for _ in 0..3 {
            bucket.acquire().await;
        }
        // No sleep should have happened — paused clock has not advanced.
        assert_eq!(Instant::now().duration_since(start), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn empty_bucket_sleeps_until_refill() {
        let bucket = TokenBucket::new(2, Duration::from_secs(2));
        bucket.acquire().await;
        bucket.acquire().await;
        let start = Instant::now();
        // Third call must sleep ~1s (1 token / 2 capacity * 2s window = 1s).
        bucket.acquire().await;
        let waited = Instant::now().duration_since(start);
        assert!(
            waited >= Duration::from_millis(900),
            "expected to wait ~1s, waited {waited:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn nvd_unauth_is_5_per_30s() {
        let bucket = TokenBucket::nvd_unauth();
        // First 5 are immediate.
        for _ in 0..5 {
            bucket.acquire().await;
        }
        // 6th waits ~6 s (one token / 5 capacity * 30 s = 6 s).
        let start = Instant::now();
        bucket.acquire().await;
        let waited = Instant::now().duration_since(start);
        assert!(
            waited >= Duration::from_secs(5),
            "expected ~6s wait, got {waited:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn zero_capacity_clamps_to_one() {
        let bucket = TokenBucket::new(0, Duration::from_secs(1));
        // One token, served immediately.
        bucket.acquire().await;
        // Second sleeps ~1 s.
        let start = Instant::now();
        bucket.acquire().await;
        assert!(Instant::now().duration_since(start) >= Duration::from_millis(900));
    }

    #[tokio::test(start_paused = true)]
    async fn zero_window_clamps_to_1ms() {
        let bucket = TokenBucket::new(1, Duration::ZERO);
        bucket.acquire().await;
        bucket.acquire().await; // still serves fast (1 ms window).
    }
}
