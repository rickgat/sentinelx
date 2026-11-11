//! `CallbackSink` port and the default in-memory implementation.

use std::sync::Arc;

use async_trait::async_trait;
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;

use crate::error::CollabError;
use crate::model::callback::Callback;
use crate::model::token::Token;

/// A persistence port for recorded callbacks.
///
/// Implementations MUST be safe to share across receiver tasks and MUST not
/// block the runtime in `append`.  The default Phase-1 implementation is
/// in-memory; a Postgres-backed implementation will live in `sx-storage`.
#[async_trait]
pub trait CallbackSink: Send + Sync + std::fmt::Debug {
    /// Persist a freshly observed callback.
    async fn append(&self, cb: Callback) -> Result<(), CollabError>;

    /// Return every callback recorded for `token` (across all variants).
    async fn find_by_token(&self, token: &Token) -> Result<Vec<Callback>, CollabError>;

    /// Drop every callback older than `now - ttl` and return the count
    /// removed.
    async fn purge_expired(&self, ttl: Duration) -> Result<u64, CollabError>;
}

/// Concrete `Arc<Mutex<Vec<Callback>>>` implementation suitable for tests
/// and Phase-1 deployments where durability is not yet required.
#[derive(Debug, Default, Clone)]
pub struct InMemoryCallbackSink {
    inner: Arc<Mutex<Vec<Callback>>>,
}

impl InMemoryCallbackSink {
    /// Allocate a fresh empty in-memory sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the current contents (for assertions / debug endpoints).
    pub async fn snapshot(&self) -> Vec<Callback> {
        self.inner.lock().await.clone()
    }
}

#[async_trait]
impl CallbackSink for InMemoryCallbackSink {
    async fn append(&self, cb: Callback) -> Result<(), CollabError> {
        let mut guard = self.inner.lock().await;
        guard.push(cb);
        Ok(())
    }

    async fn find_by_token(&self, token: &Token) -> Result<Vec<Callback>, CollabError> {
        let guard = self.inner.lock().await;
        Ok(guard
            .iter()
            .filter(|c| c.token() == token)
            .cloned()
            .collect())
    }

    async fn purge_expired(&self, ttl: Duration) -> Result<u64, CollabError> {
        let cutoff = OffsetDateTime::now_utc() - ttl;
        let mut guard = self.inner.lock().await;
        let before = guard.len();
        guard.retain(|c| c.received_at() > cutoff);
        // `before >= after` so the subtraction never wraps.
        let removed = before - guard.len();
        Ok(removed as u64)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{CallbackSink, InMemoryCallbackSink};
    use crate::model::callback::Callback;
    use crate::model::token::Token;
    use time::{Duration, OffsetDateTime};

    fn dns_at(token: Token, t: OffsetDateTime) -> Callback {
        Callback::Dns {
            token,
            query_type: "A".into(),
            source_ip: None,
            received_at: t,
        }
    }

    #[tokio::test]
    async fn in_memory_sink_append_and_find() {
        let sink = InMemoryCallbackSink::new();
        let tk = Token::new();
        let other = Token::new();
        let now = OffsetDateTime::now_utc();
        sink.append(dns_at(tk.clone(), now)).await.unwrap();
        sink.append(dns_at(other, now)).await.unwrap();
        let hits = sink.find_by_token(&tk).await.unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[tokio::test]
    async fn purge_removes_expired_callbacks() {
        let sink = InMemoryCallbackSink::new();
        let stale = OffsetDateTime::now_utc() - Duration::hours(100);
        let tk = Token::new();
        sink.append(dns_at(tk.clone(), stale)).await.unwrap();
        let removed = sink.purge_expired(Duration::hours(72)).await.unwrap();
        assert_eq!(removed, 1);
        assert!(sink.find_by_token(&tk).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn purge_keeps_fresh_callbacks() {
        let sink = InMemoryCallbackSink::new();
        let fresh = OffsetDateTime::now_utc() - Duration::minutes(5);
        let tk = Token::new();
        sink.append(dns_at(tk.clone(), fresh)).await.unwrap();
        let removed = sink.purge_expired(Duration::hours(72)).await.unwrap();
        assert_eq!(removed, 0);
        assert_eq!(sink.find_by_token(&tk).await.unwrap().len(), 1);
    }
}
