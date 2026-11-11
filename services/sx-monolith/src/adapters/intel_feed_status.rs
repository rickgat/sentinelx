//! Read-side adapter for [`sx_api::port::IntelFeedStatusPort`].
//!
//! Surfaces the configured intel feeds (the canonical static set:
//! `kev`, `epss`, `nvd`, plus the TAXII feed when enabled) so the
//! dashboard's `GET /v1/intel/feeds` endpoint can render a per-feed
//! health table. Persistent per-feed status (last poll, error count,
//! cursor) lives in the `intel_feed_status` table; the in-memory
//! flavour shipped here returns the static feed catalogue with default
//! timestamps so the route is reachable end-to-end without a Postgres
//! dependency in dev mode.
//!
//! A future Postgres-backed implementation lives behind the same trait
//! and wires into `intel_feed_status` rows scoped by `tenant_id`.

use std::sync::Arc;

use async_trait::async_trait;
use sx_api::port::{IntelFeedStatusPort, Phase3PortError};
use sx_api::view::intel_view::FeedStatusView;

/// In-memory feed catalogue used by the dev-mode composition root.
///
/// Carries the canonical built-in feeds (`kev`, `epss`, `nvd`). The
/// `last_poll_at` / `last_success_at` timestamps are `None` until the
/// orchestrator has actually polled — the route still returns the
/// catalogue so the operator can see which feeds exist, with empty
/// timestamps acting as the "not yet polled" signal.
#[derive(Debug, Default, Clone)]
pub(crate) struct InMemoryIntelFeedStatusAdapter;

impl InMemoryIntelFeedStatusAdapter {
    /// Construct the adapter.
    pub(crate) const fn new() -> Self {
        Self
    }

    /// Wrap in an [`Arc`] for sharing across handler state.
    pub(crate) fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }
}

#[async_trait]
impl IntelFeedStatusPort for InMemoryIntelFeedStatusAdapter {
    async fn list_feeds(&self, _tenant_id: &str) -> Result<Vec<FeedStatusView>, Phase3PortError> {
        Ok(vec![
            FeedStatusView {
                name: "kev".to_owned(),
                kind: "kev".to_owned(),
                last_poll_at: None,
                last_success_at: None,
                error_count_24h: 0,
            },
            FeedStatusView {
                name: "epss".to_owned(),
                kind: "epss".to_owned(),
                last_poll_at: None,
                last_success_at: None,
                error_count_24h: 0,
            },
            FeedStatusView {
                name: "nvd".to_owned(),
                kind: "nvd".to_owned(),
                last_poll_at: None,
                last_success_at: None,
                error_count_24h: 0,
            },
        ])
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn list_feeds_returns_canonical_catalogue() {
        let adapter = InMemoryIntelFeedStatusAdapter::new();
        let rows = adapter.list_feeds("t-1").await.unwrap();
        assert_eq!(rows.len(), 3);
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"kev"));
        assert!(names.contains(&"epss"));
        assert!(names.contains(&"nvd"));
    }

    #[tokio::test]
    async fn list_feeds_is_tenant_agnostic_for_canonical_set() {
        let adapter = InMemoryIntelFeedStatusAdapter::new();
        let a = adapter.list_feeds("t-a").await.unwrap();
        let b = adapter.list_feeds("t-b").await.unwrap();
        assert_eq!(a.len(), b.len());
    }
}
