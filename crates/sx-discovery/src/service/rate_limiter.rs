//! Composite rate limiter — global concurrency cap plus per-target token
//! bucket.
//!
//! ## Design
//!
//! - **Concurrency cap.** A [`tokio::sync::Semaphore`] limits the total
//!   number of in-flight probes the process can have outstanding. Sized
//!   from [`crate::contracts`] / `sx_config::DiscoveryConfig::max_concurrent_probes`.
//! - **Per-target token bucket.** A simple software bucket implemented with
//!   a [`tokio::sync::Mutex`] over a `HashMap<String, BucketState>`. The
//!   key is the target's canonical form (see
//!   [`crate::contracts::ScopeTarget::canonical_key`]). Tokens refill
//!   linearly at `per_target_rps_limit` tokens per second up to the
//!   configured capacity.
//!
//! Both limits are checked on every [`RateLimiter::acquire`] call. The
//! global semaphore is acquired first; if a target bucket has no tokens,
//! the semaphore permit is released and the call returns
//! [`crate::error::DiscoveryError::RateLimited`].

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use crate::error::DiscoveryError;

/// Configuration for the composite rate limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimiterConfig {
    /// Maximum concurrent in-flight probes across the entire process.
    pub max_concurrent_probes: u32,
    /// Token-refill rate per target, in tokens per second.
    pub per_target_rps_limit: u32,
    /// Burst capacity per target. Must be `>= 1`.
    pub per_target_burst: u32,
}

impl RateLimiterConfig {
    /// Validate the configuration. Returns a config error on bad input.
    pub fn check(self) -> Result<Self, DiscoveryError> {
        if self.max_concurrent_probes == 0 {
            return Err(DiscoveryError::config("max_concurrent_probes must be >= 1"));
        }
        if self.per_target_rps_limit == 0 {
            return Err(DiscoveryError::config("per_target_rps_limit must be >= 1"));
        }
        if self.per_target_burst == 0 {
            return Err(DiscoveryError::config("per_target_burst must be >= 1"));
        }
        Ok(self)
    }
}

/// Per-target token bucket state.
#[derive(Debug)]
pub struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    last_refill: Instant,
}

impl TokenBucket {
    /// Build a new full bucket.
    #[must_use]
    pub fn new(capacity: u32, refill_per_sec: u32) -> Self {
        Self {
            tokens: f64::from(capacity),
            capacity: f64::from(capacity),
            refill_per_sec: f64::from(refill_per_sec),
            last_refill: Instant::now(),
        }
    }

    /// Try to consume `n` tokens. Returns `true` on success.
    #[must_use]
    pub fn try_take(&mut self, n: u32, now: Instant) -> bool {
        // Refill first.
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.tokens = elapsed
            .mul_add(self.refill_per_sec, self.tokens)
            .min(self.capacity);
        self.last_refill = now;
        let want = f64::from(n);
        if self.tokens + f64::EPSILON >= want {
            self.tokens -= want;
            true
        } else {
            false
        }
    }
}

/// Composite rate limiter handed to scanners through [`crate::service::scanner::ScanContext`].
#[derive(Debug)]
pub struct RateLimiter {
    cfg: RateLimiterConfig,
    global: Arc<Semaphore>,
    buckets: Mutex<HashMap<String, TokenBucket>>,
}

/// Permit returned by [`RateLimiter::acquire`]; dropping it releases the
/// global concurrency token.
#[derive(Debug)]
pub struct RateLimiterPermit {
    _permit: OwnedSemaphorePermit,
}

impl RateLimiter {
    /// Build a limiter from a validated config.
    pub fn new(cfg: RateLimiterConfig) -> Result<Self, DiscoveryError> {
        let cfg = cfg.check()?;
        let cap = usize::try_from(cfg.max_concurrent_probes)
            .map_err(|_| DiscoveryError::config("max_concurrent_probes overflows usize"))?;
        Ok(Self {
            cfg,
            global: Arc::new(Semaphore::new(cap)),
            buckets: Mutex::new(HashMap::new()),
        })
    }

    /// Acquire `1` token's worth of budget for `target_key`.
    ///
    /// Returns a [`RateLimiterPermit`] whose drop releases the concurrency
    /// permit. Per-target tokens are spent eagerly; they are not refunded
    /// on drop.
    pub async fn acquire(&self, target_key: &str) -> Result<RateLimiterPermit, DiscoveryError> {
        let permit = Arc::clone(&self.global)
            .acquire_owned()
            .await
            .map_err(|e| DiscoveryError::internal(format!("semaphore closed: {e}")))?;
        let granted = {
            let mut buckets = self.buckets.lock().await;
            let bucket = buckets.entry(target_key.to_owned()).or_insert_with(|| {
                TokenBucket::new(self.cfg.per_target_burst, self.cfg.per_target_rps_limit)
            });
            bucket.try_take(1, Instant::now())
        };
        if !granted {
            // Drop permit by letting it go out of scope.
            drop(permit);
            return Err(DiscoveryError::RateLimited);
        }
        Ok(RateLimiterPermit { _permit: permit })
    }

    /// Wait up to `timeout` for a token, polling once per millisecond.
    /// Useful for tests and adapters that want bounded blocking.
    pub async fn acquire_within(
        &self,
        target_key: &str,
        timeout: Duration,
    ) -> Result<RateLimiterPermit, DiscoveryError> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.acquire(target_key).await {
                Ok(p) => return Ok(p),
                Err(DiscoveryError::RateLimited) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn cfg(max_concurrent: u32, rps: u32, burst: u32) -> RateLimiterConfig {
        RateLimiterConfig {
            max_concurrent_probes: max_concurrent,
            per_target_rps_limit: rps,
            per_target_burst: burst,
        }
    }

    #[tokio::test]
    async fn first_acquire_succeeds_within_burst() {
        let lim = RateLimiter::new(cfg(4, 1, 2)).unwrap();
        let _a = lim.acquire("t1").await.unwrap();
        let _b = lim.acquire("t1").await.unwrap();
    }

    #[tokio::test]
    async fn acquire_above_burst_is_rate_limited() {
        let lim = RateLimiter::new(cfg(4, 1, 1)).unwrap();
        let _a = lim.acquire("t1").await.unwrap();
        assert!(matches!(
            lim.acquire("t1").await,
            Err(DiscoveryError::RateLimited)
        ));
    }

    #[tokio::test]
    async fn per_target_isolation() {
        let lim = RateLimiter::new(cfg(4, 1, 1)).unwrap();
        let _a = lim.acquire("t1").await.unwrap();
        // Different target — fresh bucket.
        let _b = lim.acquire("t2").await.unwrap();
    }

    #[tokio::test]
    async fn invalid_config_rejected() {
        let r = RateLimiter::new(cfg(0, 1, 1));
        assert!(matches!(r, Err(DiscoveryError::Config(_))));
    }
}
