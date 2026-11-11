//! TTL caching decorator for [`crate::SecretsProvider`].
//!
//! [`CachedProvider`] wraps another provider and memoises successful
//! `get` results for a configurable duration (default 60 seconds). On a
//! cache miss the backend is consulted exactly once; concurrent callers
//! racing on the same key are coalesced by `moka`'s entry API.
//!
//! ## TTL strategy
//!
//! * **Time-to-live**: 60 seconds by default — short enough to limit the
//!   blast radius of a stale secret after rotation, long enough to spare
//!   the backend in tight loops.
//! * **Capacity**: 1024 entries by default; oldest entries are evicted
//!   first.
//! * **Invalidation on write**: `put` invalidates the cached entry so
//!   subsequent reads pick up the new value rather than continue to
//!   serve the stale one until TTL expiry.
//! * **No negative caching**: errors are never cached. A transient
//!   transport failure must not poison the cache.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use moka::future::Cache;
use secrecy::{ExposeSecret, SecretString};

use crate::error::SecretsError;
use crate::provider::SecretsProvider;

/// Default time-to-live for cached secrets.
pub const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// Default maximum number of entries in the cache.
pub const DEFAULT_CAPACITY: u64 = 1024;

/// A decorator that adds TTL caching around any [`SecretsProvider`].
///
/// `CachedProvider` is cheap to clone — the inner provider and cache are
/// both held behind shared handles.
#[derive(Debug)]
pub struct CachedProvider<P> {
    inner: Arc<P>,
    cache: Cache<String, Arc<CachedSecret>>,
    ttl: Duration,
}

impl<P> Clone for CachedProvider<P> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            cache: self.cache.clone(),
            ttl: self.ttl,
        }
    }
}

/// A single cached secret entry.
///
/// We hold the raw bytes rather than a [`SecretString`] directly so we can
/// hand out fresh copies on every cache hit without leaking the
/// underlying buffer between callers.
#[derive(Debug)]
pub struct CachedSecret {
    bytes: String,
}

impl CachedSecret {
    fn from_secret(secret: &SecretString) -> Self {
        Self {
            bytes: secret.expose_secret().to_owned(),
        }
    }

    fn to_secret(&self) -> SecretString {
        SecretString::new(self.bytes.clone().into_boxed_str())
    }
}

impl<P> CachedProvider<P>
where
    P: SecretsProvider + 'static,
{
    /// Wrap `inner` with default TTL ([`DEFAULT_TTL`]) and capacity
    /// ([`DEFAULT_CAPACITY`]).
    #[must_use]
    pub fn new(inner: P) -> Self {
        Self::with_settings(inner, DEFAULT_TTL, DEFAULT_CAPACITY)
    }

    /// Wrap `inner` with a custom `ttl` and `capacity`.
    #[must_use]
    pub fn with_settings(inner: P, ttl: Duration, capacity: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(capacity)
            .time_to_live(ttl)
            .build();
        Self {
            inner: Arc::new(inner),
            cache,
            ttl,
        }
    }

    /// The configured TTL.
    #[must_use]
    pub const fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Approximate count of entries currently cached.
    ///
    /// `moka`'s entry count is eventually consistent; values surface
    /// promptly after explicit calls to `run_pending_tasks` (which we
    /// call here so the figure is accurate for tests).
    pub async fn approximate_len(&self) -> u64 {
        self.cache.run_pending_tasks().await;
        self.cache.entry_count()
    }

    /// Force-evict every cached entry. Primarily for tests / operator
    /// tooling — production code rarely needs this.
    pub async fn invalidate_all(&self) {
        self.cache.invalidate_all();
        self.cache.run_pending_tasks().await;
    }
}

#[async_trait]
impl<P> SecretsProvider for CachedProvider<P>
where
    P: SecretsProvider + 'static,
{
    async fn get(&self, path: &str) -> Result<SecretString, SecretsError> {
        if let Some(hit) = self.cache.get(path).await {
            return Ok(hit.to_secret());
        }
        // Cache miss — fetch from backend and populate.
        let fetched = self.inner.get(path).await?;
        let entry = Arc::new(CachedSecret::from_secret(&fetched));
        self.cache.insert(path.to_owned(), Arc::clone(&entry)).await;
        Ok(entry.to_secret())
    }

    async fn put(&self, path: &str, value: SecretString) -> Result<(), SecretsError> {
        // Invalidate FIRST so a concurrent reader cannot repopulate the
        // cache with the stale value between our backend write and the
        // invalidate.
        self.cache.invalidate(path).await;
        self.inner.put(path, value).await?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// Test provider that counts the number of backend calls it receives.
    #[derive(Debug, Default)]
    struct CountingProvider {
        gets: AtomicUsize,
        puts: AtomicUsize,
        store: Mutex<HashMap<String, String>>,
    }

    impl CountingProvider {
        fn seed(path: &str, value: &str) -> Self {
            let me = Self::default();
            me.store
                .lock()
                .unwrap()
                .insert(path.to_owned(), value.to_owned());
            me
        }

        fn get_count(&self) -> usize {
            self.gets.load(Ordering::SeqCst)
        }

        fn put_count(&self) -> usize {
            self.puts.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl SecretsProvider for CountingProvider {
        async fn get(&self, path: &str) -> Result<SecretString, SecretsError> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            let guard = self.store.lock().unwrap();
            guard.get(path).map_or_else(
                || Err(SecretsError::NotFound(path.to_owned())),
                |v| Ok(SecretString::new(v.clone().into_boxed_str())),
            )
        }

        async fn put(&self, path: &str, value: SecretString) -> Result<(), SecretsError> {
            self.puts.fetch_add(1, Ordering::SeqCst);
            self.store
                .lock()
                .unwrap()
                .insert(path.to_owned(), value.expose_secret().to_owned());
            Ok(())
        }
    }

    fn secret(s: &str) -> SecretString {
        SecretString::new(s.to_owned().into_boxed_str())
    }

    #[tokio::test]
    async fn cache_hit_avoids_second_backend_call() {
        let backend = CountingProvider::seed("k", "v1");
        let cached = CachedProvider::new(backend);

        let v1 = cached.get("k").await.unwrap();
        let v2 = cached.get("k").await.unwrap();
        assert_eq!(v1.expose_secret(), "v1");
        assert_eq!(v2.expose_secret(), "v1");
        assert_eq!(cached.inner.get_count(), 1, "backend hit exactly once");
    }

    #[tokio::test]
    async fn cache_miss_after_ttl_expiry_calls_backend_again() {
        // `moka` reads wall-clock time internally and ignores
        // `tokio::time::pause`, so we use a short real TTL and a real
        // sleep to exercise expiry deterministically.
        let backend = CountingProvider::seed("k", "v1");
        let cached = CachedProvider::with_settings(backend, Duration::from_millis(50), 1024);

        let _ = cached.get("k").await.unwrap();
        assert_eq!(cached.inner.get_count(), 1);

        // Wait past the TTL. moka evicts lazily so we also nudge the
        // cache to run pending tasks.
        tokio::time::sleep(Duration::from_millis(120)).await;
        cached.cache.run_pending_tasks().await;

        let _ = cached.get("k").await.unwrap();
        assert_eq!(
            cached.inner.get_count(),
            2,
            "backend re-queried after TTL elapsed"
        );
    }

    #[tokio::test]
    async fn put_invalidates_cache_entry() {
        let backend = CountingProvider::seed("k", "v1");
        let cached = CachedProvider::new(backend);

        let first = cached.get("k").await.unwrap();
        assert_eq!(first.expose_secret(), "v1");
        assert_eq!(cached.inner.get_count(), 1);

        cached.put("k", secret("v2")).await.unwrap();
        assert_eq!(cached.inner.put_count(), 1);

        // Next read should miss and refetch v2 from the backend.
        let second = cached.get("k").await.unwrap();
        assert_eq!(second.expose_secret(), "v2");
        assert_eq!(
            cached.inner.get_count(),
            2,
            "cache invalidated by put → backend re-queried"
        );
    }

    #[tokio::test]
    async fn cache_misses_for_unknown_keys_propagate_not_found() {
        let backend = CountingProvider::default();
        let cached = CachedProvider::new(backend);
        let err = cached.get("missing").await.unwrap_err();
        assert!(matches!(err, SecretsError::NotFound(_)));
    }

    #[tokio::test]
    async fn errors_are_not_cached() {
        let backend = CountingProvider::default();
        let cached = CachedProvider::new(backend);

        let _ = cached.get("missing").await.unwrap_err();
        let _ = cached.get("missing").await.unwrap_err();
        assert_eq!(
            cached.inner.get_count(),
            2,
            "errors must not poison the cache"
        );
    }

    #[tokio::test]
    async fn invalidate_all_clears_the_cache() {
        let backend = CountingProvider::seed("k", "v1");
        let cached = CachedProvider::new(backend);

        let _ = cached.get("k").await.unwrap();
        assert_eq!(cached.approximate_len().await, 1);

        cached.invalidate_all().await;
        assert_eq!(cached.approximate_len().await, 0);

        let _ = cached.get("k").await.unwrap();
        assert_eq!(
            cached.inner.get_count(),
            2,
            "backend re-queried after invalidate_all"
        );
    }
}
