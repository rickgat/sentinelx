//! Log ingestion service — parser dispatch + per-tenant ring buffer.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::error::LogIngestError;
use crate::registry::LogParserRegistry;
use crate::schema::OcsfEvent;

/// Per-tenant ring-buffer capacity. Future ClickHouse persistence will lift
/// this cap; today we use it to keep the memory footprint bounded under
/// adversarial input.
pub const PER_TENANT_CAPACITY: usize = 10_000;

/// In-memory log ingestion service.
///
/// Owns:
/// - A [`LogParserRegistry`] (immutable after construction).
/// - A per-tenant `VecDeque<OcsfEvent>` ring buffer, capped at
///   [`PER_TENANT_CAPACITY`].
///
/// Optionally fans newly-parsed events to a SOC correlation hook (set
/// via [`Self::with_correlation_hook`]) so the autonomous correlator can
/// react to ingested logs alongside operator-submitted events.
#[derive(Clone)]
pub struct LogIngestService {
    registry: Arc<LogParserRegistry>,
    buffers: Arc<Mutex<HashMap<String, VecDeque<OcsfEvent>>>>,
    correlation_hook: Option<Arc<dyn CorrelationHook>>,
    capacity: usize,
}

impl std::fmt::Debug for LogIngestService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogIngestService")
            .field("capacity", &self.capacity)
            .field("source_types", &self.registry.source_types())
            .field("has_correlation_hook", &self.correlation_hook.is_some())
            .finish_non_exhaustive()
    }
}

/// Correlation hook — invoked synchronously per accepted event.
///
/// Lets the SOC correlator observe ingested logs alongside operator-pushed
/// events. Implementations should not block the ingestion path; expensive
/// work should be deferred to a background queue.
pub trait CorrelationHook: Send + Sync + std::fmt::Debug {
    /// Forward one OCSF event.
    fn on_event(&self, event: &OcsfEvent);
}

impl LogIngestService {
    /// Build a service with the supplied registry.
    #[must_use]
    pub fn new(registry: LogParserRegistry) -> Self {
        Self {
            registry: Arc::new(registry),
            buffers: Arc::new(Mutex::new(HashMap::new())),
            correlation_hook: None,
            capacity: PER_TENANT_CAPACITY,
        }
    }

    /// Build a service with the built-in parser registry.
    #[must_use]
    pub fn with_builtins() -> Self {
        Self::new(LogParserRegistry::with_builtins())
    }

    /// Install a correlation hook. Replaces any prior hook.
    #[must_use]
    pub fn with_correlation_hook(mut self, hook: Arc<dyn CorrelationHook>) -> Self {
        self.correlation_hook = Some(hook);
        self
    }

    /// Override the per-tenant ring-buffer capacity (mostly for tests).
    #[must_use]
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity.max(1);
        self
    }

    /// Accessor for the supported source-type tokens.
    #[must_use]
    pub fn supported_source_types(&self) -> Vec<String> {
        self.registry.source_types()
    }

    /// Parse + store a single payload.
    ///
    /// Stamps `metadata.tenant_id` from the caller, fans to the
    /// correlation hook (if any), then pushes onto the per-tenant ring
    /// buffer (evicting the oldest entry on overflow).
    #[allow(clippy::significant_drop_tightening)] // tokio::sync::Mutex guard intentionally scoped
    pub async fn ingest_one(
        &self,
        tenant_id: &str,
        source: &str,
        payload: &str,
    ) -> Result<(), LogIngestError> {
        let parser = self
            .registry
            .get(source)
            .ok_or_else(|| LogIngestError::UnknownSource(source.to_owned()))?;
        let mut event = parser.parse(payload)?;
        tenant_id.clone_into(&mut event.metadata.tenant_id);

        if let Some(hook) = &self.correlation_hook {
            hook.on_event(&event);
        }

        let cap = self.capacity;
        {
            let mut guard = self.buffers.lock().await;
            let buffer = guard
                .entry(tenant_id.to_owned())
                .or_insert_with(|| VecDeque::with_capacity(cap.min(1024)));
            if buffer.len() == cap {
                let _evicted = buffer.pop_front();
            }
            buffer.push_back(event);
        }
        Ok(())
    }

    /// List the most-recent `limit` events for `tenant_id` — newest first.
    #[allow(clippy::significant_drop_tightening)] // tokio::sync::Mutex guard intentionally scoped
    pub async fn list(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<OcsfEvent>, LogIngestError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let out: Vec<OcsfEvent> = {
            let guard = self.buffers.lock().await;
            let Some(buffer) = guard.get(tenant_id) else {
                return Ok(Vec::new());
            };
            buffer.iter().rev().take(limit).cloned().collect()
        };
        Ok(out)
    }

    /// Total events currently buffered for `tenant_id`.
    pub async fn len(&self, tenant_id: &str) -> usize {
        let guard = self.buffers.lock().await;
        guard.get(tenant_id).map_or(0, VecDeque::len)
    }
}

impl Default for LogIngestService {
    fn default() -> Self {
        Self::with_builtins()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::error::ParseError;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const CT: &str = r#"{
        "eventTime": "2026-06-12T10:30:01Z",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "RunInstances",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "203.0.113.5"
    }"#;

    const TENANT: &str = "01010101-0101-0101-0101-010101010101";

    #[tokio::test]
    async fn ingest_then_list_returns_event_in_newest_first_order() {
        let svc = LogIngestService::with_builtins();
        svc.ingest_one(TENANT, "cloudtrail", CT).await.unwrap();
        let items = svc.list(TENANT, 10).await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].metadata.tenant_id, TENANT);
        assert_eq!(items[0].metadata.source_type, "cloudtrail");
    }

    #[tokio::test]
    async fn unknown_source_returns_unknown_source_error() {
        let svc = LogIngestService::with_builtins();
        let err = svc
            .ingest_one(TENANT, "not-a-source", "{}")
            .await
            .unwrap_err();
        assert!(matches!(err, LogIngestError::UnknownSource(s) if s == "not-a-source"));
    }

    #[tokio::test]
    async fn malformed_payload_surfaces_parser_error() {
        let svc = LogIngestService::with_builtins();
        let err = svc
            .ingest_one(TENANT, "cloudtrail", "{nope")
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            LogIngestError::Parser(ParseError::Malformed(_))
        ));
    }

    #[tokio::test]
    async fn list_limit_zero_returns_empty() {
        let svc = LogIngestService::with_builtins();
        svc.ingest_one(TENANT, "cloudtrail", CT).await.unwrap();
        let items = svc.list(TENANT, 0).await.unwrap();
        assert!(items.is_empty());
    }

    #[tokio::test]
    async fn list_for_unseen_tenant_returns_empty() {
        let svc = LogIngestService::with_builtins();
        let items = svc.list(TENANT, 10).await.unwrap();
        assert!(items.is_empty());
    }

    #[tokio::test]
    async fn ring_buffer_evicts_oldest_when_capacity_exceeded() {
        let svc = LogIngestService::with_builtins().with_capacity(2);
        for n in 0..5 {
            let payload = format!(
                r#"{{"eventTime":"2026-06-12T10:30:0{n}Z","eventName":"Op{n}","eventSource":"x","awsRegion":"us-east-1","sourceIPAddress":"203.0.113.{n}"}}"#
            );
            svc.ingest_one(TENANT, "cloudtrail", &payload)
                .await
                .unwrap();
        }
        assert_eq!(svc.len(TENANT).await, 2);
        let items = svc.list(TENANT, 10).await.unwrap();
        assert_eq!(items.len(), 2);
        // Newest first.
        assert!(items[0].raw.contains("Op4"));
        assert!(items[1].raw.contains("Op3"));
    }

    #[tokio::test]
    async fn tenants_are_isolated() {
        let svc = LogIngestService::with_builtins();
        svc.ingest_one("tenant-a", "cloudtrail", CT).await.unwrap();
        svc.ingest_one("tenant-b", "cloudtrail", CT).await.unwrap();
        assert_eq!(svc.len("tenant-a").await, 1);
        assert_eq!(svc.len("tenant-b").await, 1);
        let only_a = svc.list("tenant-a", 10).await.unwrap();
        assert_eq!(only_a[0].metadata.tenant_id, "tenant-a");
    }

    #[derive(Debug, Default)]
    struct CountingHook {
        invocations: AtomicUsize,
    }

    impl CorrelationHook for CountingHook {
        fn on_event(&self, _event: &OcsfEvent) {
            self.invocations.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn correlation_hook_invoked_once_per_event() {
        let hook = Arc::new(CountingHook::default());
        let svc = LogIngestService::with_builtins()
            .with_correlation_hook(Arc::clone(&hook) as Arc<dyn CorrelationHook>);
        svc.ingest_one(TENANT, "cloudtrail", CT).await.unwrap();
        svc.ingest_one(TENANT, "cloudtrail", CT).await.unwrap();
        assert_eq!(hook.invocations.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn supported_source_types_lists_builtins() {
        let svc = LogIngestService::with_builtins();
        let types = svc.supported_source_types();
        assert!(types.contains(&"cloudtrail".to_owned()));
        assert!(types.contains(&"syslog_rfc5424".to_owned()));
        assert!(types.contains(&"suricata_eve".to_owned()));
    }
}
