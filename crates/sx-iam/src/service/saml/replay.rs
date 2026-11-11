//! Replay-protection cache for SAML 2.0 assertion ids and `InResponseTo`
//! correlation tokens.
//!
//! SAML's safety against replay attacks depends on two complementary
//! mechanisms:
//!
//! 1. **Assertion ID dedup** — every `<Assertion>` carries an `ID`
//!    attribute. After a successful verification the SP remembers the id
//!    for the configured TTL (defaults to 5 minutes per the SAML
//!    deployment profile). A second response carrying the same id is
//!    rejected as a replay regardless of signature validity.
//! 2. **`InResponseTo` matching** — SP-initiated flows embed the SP's
//!    `AuthnRequest@ID` in the response's `InResponseTo` attribute. The
//!    SP keeps the outstanding request id around for the same TTL and
//!    matches it on the ACS leg. An IdP-initiated flow has no
//!    `InResponseTo` and is allowed only when the operator has opted into
//!    it (the ACS use case enforces that separately).
//!
//! Both mechanisms live behind the same [`AssertionReplayCache`] trait so
//! a deployment can plug a Redis-backed implementation later without
//! touching the verification path.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;

/// Outcome of an "insert if absent" operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// Key was inserted — first time it has been seen within the TTL.
    Inserted,
    /// Key already exists — this is a replay.
    Duplicate,
}

/// Cache port for both assertion-id dedup and `InResponseTo` correlation.
///
/// Implementations MUST be thread-safe and MUST honour the TTL given at
/// construction time. Calls cross the use-case / adapter boundary as
/// `async fn` so a Redis implementation can be plugged without touching
/// the SAML verifier.
#[async_trait]
pub trait AssertionReplayCache: Send + Sync + std::fmt::Debug {
    /// Insert `key` if absent. Returns whether the key was first-seen.
    async fn insert_if_absent(&self, key: &str) -> InsertOutcome;

    /// Whether `key` is currently present in the cache.
    async fn contains(&self, key: &str) -> bool;
}

/// In-memory, TTL-bounded replay cache.
///
/// Backed by a single `Mutex<HashMap<String, Instant>>` — sufficient for
/// the MVP slice and for single-node deployments. Production
/// multi-node deployments should swap in a Redis adapter so a replay
/// attempt against one API node cannot succeed against another.
#[derive(Debug)]
pub struct InMemoryReplayCache {
    ttl: Duration,
    inner: Mutex<HashMap<String, Instant>>,
}

impl InMemoryReplayCache {
    /// Build a cache that expires entries after `ttl`.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Drop every expired entry. Called on every public operation so the
    /// map size stays bounded by the request rate × TTL.
    fn purge_expired(&self, now: Instant, map: &mut HashMap<String, Instant>) {
        map.retain(|_, inserted_at| now.duration_since(*inserted_at) < self.ttl);
    }
}

#[async_trait]
impl AssertionReplayCache for InMemoryReplayCache {
    async fn insert_if_absent(&self, key: &str) -> InsertOutcome {
        let now = Instant::now();
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            // A poisoned mutex means another caller panicked while
            // holding the lock. Recover the inner state — refusing to
            // insert would make the SP permanently reject all
            // assertions after a single panic, which is an availability
            // foot-gun. The cache's invariant (no duplicate within
            // TTL) is still preserved because purge_expired + the
            // insert_if_absent contract operates on the recovered map.
            Err(poison) => poison.into_inner(),
        };
        self.purge_expired(now, &mut map);
        if map.contains_key(key) {
            InsertOutcome::Duplicate
        } else {
            map.insert(key.to_owned(), now);
            InsertOutcome::Inserted
        }
    }

    async fn contains(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut map = match self.inner.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        self.purge_expired(now, &mut map);
        map.contains_key(key)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn first_insert_is_first_seen() {
        let c = InMemoryReplayCache::new(Duration::from_secs(60));
        assert_eq!(c.insert_if_absent("a").await, InsertOutcome::Inserted);
    }

    #[tokio::test]
    async fn second_insert_is_duplicate() {
        let c = InMemoryReplayCache::new(Duration::from_secs(60));
        let _ = c.insert_if_absent("a").await;
        assert_eq!(c.insert_if_absent("a").await, InsertOutcome::Duplicate);
    }

    #[tokio::test]
    async fn distinct_keys_are_independent() {
        let c = InMemoryReplayCache::new(Duration::from_secs(60));
        assert_eq!(c.insert_if_absent("a").await, InsertOutcome::Inserted);
        assert_eq!(c.insert_if_absent("b").await, InsertOutcome::Inserted);
    }

    #[tokio::test]
    async fn contains_reflects_inserts() {
        let c = InMemoryReplayCache::new(Duration::from_secs(60));
        assert!(!c.contains("a").await);
        let _ = c.insert_if_absent("a").await;
        assert!(c.contains("a").await);
    }

    #[tokio::test]
    async fn purges_after_ttl() {
        let c = InMemoryReplayCache::new(Duration::from_millis(20));
        let _ = c.insert_if_absent("a").await;
        tokio::time::sleep(Duration::from_millis(40)).await;
        // After TTL, the entry is purged on the next operation and a
        // re-insert is allowed.
        assert_eq!(c.insert_if_absent("a").await, InsertOutcome::Inserted);
    }
}
