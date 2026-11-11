//! DLP service orchestrator.
//!
//! Wires the pluggable [`ContentInspector`] trait, the built-in
//! inspector set, and the `InMemoryDlpService` projection that backs
//! `POST /v1/dlp/scan` + `GET /v1/dlp/history`. Raw payloads are never
//! stored — every persisted record carries metadata only (kind, length,
//! match count, redacted previews) so the audit trail cannot itself
//! become a data-loss surface.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::{TenantDetectorConfig, TenantDetectorConfigStore};
use crate::detector::DlpDetector;
use crate::patterns::{
    aws_access_key, aws_secret_key, credit_card, email, gcp_service_account, github_pat, jwt, ner,
    pem_private_key, phone, slack_token, ssn_us, DlpMatch, DlpMatchKind,
};
use crate::MAX_PAYLOAD_BYTES;

/// Type alias for a [`DlpMatch`] that has been scored by the HIGH-004 detector.
///
/// Callers can refer to a "scored" match as the orchestrator stamps
/// `confidence` + `signals` onto every emitted [`DlpMatch`]. This alias
/// keeps the public docs HIGH-004-aware without introducing a second
/// type.
pub type ScoredDlpMatch = DlpMatch;

/// Pluggable inspector contract.
///
/// Implementations MUST be deterministic (same input → same output) and
/// MUST NOT mutate global state — the orchestrator may call inspectors
/// concurrently across requests.
pub trait ContentInspector: Send + Sync {
    /// Stable inspector name, used in metrics labels + diagnostics.
    fn name(&self) -> &'static str;
    /// Scan `text` and return zero or more matches. Implementations must
    /// not panic on adversarial input.
    fn inspect(&self, text: &str) -> Vec<DlpMatch>;
}

/// Adapter that turns a free-function `scan` into a `ContentInspector`.
pub struct FnInspector {
    name: &'static str,
    f: fn(&str) -> Vec<DlpMatch>,
}

impl std::fmt::Debug for FnInspector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FnInspector")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl FnInspector {
    /// Build a new function-backed inspector.
    #[must_use]
    pub const fn new(name: &'static str, f: fn(&str) -> Vec<DlpMatch>) -> Self {
        Self { name, f }
    }
}

impl ContentInspector for FnInspector {
    fn name(&self) -> &'static str {
        self.name
    }
    fn inspect(&self, text: &str) -> Vec<DlpMatch> {
        (self.f)(text)
    }
}

/// Source the scan was initiated from. Surfaces in the audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanSource {
    /// HTTP API (e.g. `POST /v1/dlp/scan`).
    Api,
    /// CLI / batch ingestion.
    Cli,
    /// S3 / object-store fan-out (placeholder, P2 follow-up).
    ObjectStore,
}

/// One match-kind summary inside [`DlpScanResult`]. Counts only; never
/// includes literal matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KindSummary {
    /// Match category.
    pub kind: DlpMatchKind,
    /// How many matches of this category were found.
    pub count: usize,
}

/// Final wire shape returned by [`DlpService::scan_text`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DlpScanResult {
    /// Scan uuid (v7).
    pub id: String,
    /// Owning tenant uuid.
    pub tenant_id: String,
    /// RFC 3339 finish timestamp.
    pub finished_at: String,
    /// Payload length in bytes (not chars).
    pub bytes_scanned: usize,
    /// Total matches across all categories.
    pub total_matches: usize,
    /// Per-category counts, sorted by category name.
    pub summary: Vec<KindSummary>,
    /// Full hit list. Each `DlpMatch::redacted_preview` is safe to log.
    pub matches: Vec<DlpMatch>,
}

/// Audit-friendly metadata record retained in the scan history.
///
/// Never contains the literal payload or full match strings — only the
/// per-category counts and the inspector names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanHistoryEntry {
    /// Scan uuid.
    pub id: String,
    /// Owning tenant uuid.
    pub tenant_id: String,
    /// Origin of the scan request.
    pub source: ScanSource,
    /// RFC 3339 finish timestamp.
    pub finished_at: String,
    /// Payload length in bytes.
    pub bytes_scanned: usize,
    /// Total matches across all categories.
    pub total_matches: usize,
    /// Per-category counts.
    pub summary: Vec<KindSummary>,
}

/// Domain errors returned by [`DlpService`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum DlpError {
    /// Payload exceeded [`crate::MAX_PAYLOAD_BYTES`].
    #[error("payload too large: {0} bytes (max {max})", max = MAX_PAYLOAD_BYTES)]
    PayloadTooLarge(usize),
    /// Tenant id missing or invalid.
    #[error("invalid tenant id")]
    InvalidTenant,
    /// Implementation-specific internal failure.
    #[error("internal: {0}")]
    Internal(String),
}

/// Async DLP scan entry point.
#[async_trait]
pub trait DlpService: Send + Sync {
    /// Scan `text` under `tenant_id`. Records a history entry on success.
    async fn scan_text(
        &self,
        tenant_id: &str,
        source: ScanSource,
        text: &str,
    ) -> Result<DlpScanResult, DlpError>;

    /// List the latest scan-history entries newest-first.
    async fn list_history(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<ScanHistoryEntry>, DlpError>;
}

const HISTORY_CAP: usize = 1000;

/// In-memory `DlpService`. Production deployments are expected to wrap
/// this with a persistent history store, but the in-memory form is the
/// canonical implementation and is used by every test.
pub struct InMemoryDlpService {
    inspectors: Vec<Box<dyn ContentInspector>>,
    history: Mutex<Vec<ScanHistoryEntry>>,
    config_store: Arc<TenantDetectorConfigStore>,
    /// HIGH-004 multi-signal fusion + FP-suppression orchestrator. Owned
    /// by every service instance so the builtin suppression list is
    /// loaded once at startup.
    detector: DlpDetector,
}

impl std::fmt::Debug for InMemoryDlpService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&'static str> = self.inspectors.iter().map(|i| i.name()).collect();
        f.debug_struct("InMemoryDlpService")
            .field("inspectors", &names)
            .finish_non_exhaustive()
    }
}

impl Default for InMemoryDlpService {
    fn default() -> Self {
        Self::with_defaults()
    }
}

impl InMemoryDlpService {
    /// Build a fresh service with the canonical built-in inspector set.
    #[must_use]
    pub fn with_defaults() -> Self {
        let inspectors: Vec<Box<dyn ContentInspector>> = vec![
            Box::new(FnInspector::new("credit_card", credit_card::scan)),
            Box::new(FnInspector::new("ssn_us", ssn_us::scan)),
            Box::new(FnInspector::new("aws_access_key", aws_access_key::scan)),
            Box::new(FnInspector::new("aws_secret_key", aws_secret_key::scan)),
            Box::new(FnInspector::new("github_pat", github_pat::scan)),
            Box::new(FnInspector::new("jwt", jwt::scan)),
            Box::new(FnInspector::new("pem_private_key", pem_private_key::scan)),
            Box::new(FnInspector::new("email", email::scan)),
            Box::new(FnInspector::new("phone", phone::scan)),
            Box::new(FnInspector::new(
                "gcp_service_account",
                gcp_service_account::scan,
            )),
            Box::new(FnInspector::new("slack_token", slack_token::scan)),
            Box::new(FnInspector::new("ner", ner::scan)),
        ];
        Self {
            inspectors,
            history: Mutex::new(Vec::new()),
            config_store: Arc::new(TenantDetectorConfigStore::new()),
            detector: DlpDetector::with_builtin_suppression(),
        }
    }

    /// Build a service with a custom inspector set. Used by tests and by
    /// callers that need to disable categories (e.g. NER off for high
    /// throughput pipelines).
    #[must_use]
    pub fn with_inspectors(inspectors: Vec<Box<dyn ContentInspector>>) -> Self {
        Self {
            inspectors,
            history: Mutex::new(Vec::new()),
            config_store: Arc::new(TenantDetectorConfigStore::new()),
            detector: DlpDetector::with_builtin_suppression(),
        }
    }

    /// Replace the multi-signal detector — used by tests that need a
    /// non-default suppression list or signal set.
    #[must_use]
    pub fn with_detector(mut self, detector: DlpDetector) -> Self {
        self.detector = detector;
        self
    }

    /// Borrow the detector. Useful for tests that want to inspect the
    /// suppression list without going through `scan_text`.
    #[must_use]
    pub const fn detector(&self) -> &DlpDetector {
        &self.detector
    }

    /// Inspector count — used in tests to assert the default wiring.
    #[must_use]
    pub fn inspector_count(&self) -> usize {
        self.inspectors.len()
    }

    /// Borrow the per-tenant detector-config store. The composition
    /// root threads the same `Arc` into the controller surface so
    /// `PUT /v1/dlp/config` writes are observed by the next
    /// `scan_text` call without an extra round-trip.
    #[must_use]
    pub fn config_store(&self) -> Arc<TenantDetectorConfigStore> {
        Arc::clone(&self.config_store)
    }

    /// Inject a shared config store. Used by the composition root to
    /// share one store between the service and the HTTP write surface.
    #[must_use]
    pub fn with_config_store(mut self, store: Arc<TenantDetectorConfigStore>) -> Self {
        self.config_store = store;
        self
    }

    /// Snapshot the tenant's detector config — convenience used by the
    /// HTTP read surface.
    #[must_use]
    pub fn get_tenant_config(&self, tenant_id: &str) -> TenantDetectorConfig {
        self.config_store.get(tenant_id)
    }

    /// Replace the tenant's detector config — convenience used by the
    /// HTTP write surface.
    pub fn put_tenant_config(
        &self,
        tenant_id: &str,
        cfg: TenantDetectorConfig,
    ) -> TenantDetectorConfig {
        self.config_store.put(tenant_id, cfg)
    }

    fn now_rfc3339() -> String {
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
    }

    fn summarise(matches: &[DlpMatch]) -> Vec<KindSummary> {
        // 12 categories — linear scan is fine.
        let mut summary: Vec<KindSummary> = Vec::new();
        for m in matches {
            if let Some(existing) = summary.iter_mut().find(|s| s.kind == m.kind) {
                existing.count = existing.count.saturating_add(1);
            } else {
                summary.push(KindSummary {
                    kind: m.kind,
                    count: 1,
                });
            }
        }
        summary.sort_by(|a, b| a.kind.as_str().cmp(b.kind.as_str()));
        summary
    }
}

#[async_trait]
impl DlpService for InMemoryDlpService {
    async fn scan_text(
        &self,
        tenant_id: &str,
        source: ScanSource,
        text: &str,
    ) -> Result<DlpScanResult, DlpError> {
        if tenant_id.is_empty() {
            return Err(DlpError::InvalidTenant);
        }
        let bytes = text.len();
        if bytes > MAX_PAYLOAD_BYTES {
            tracing::warn!(
                target: "sx_dlp",
                tenant_id = %tenant_id,
                bytes,
                max = MAX_PAYLOAD_BYTES,
                "dlp.scan rejected oversized payload"
            );
            return Err(DlpError::PayloadTooLarge(bytes));
        }

        let tenant_cfg = self.config_store.get(tenant_id);
        let min_confidence = tenant_cfg.effective_min_confidence();

        let mut raw: Vec<DlpMatch> = Vec::new();
        for insp in &self.inspectors {
            raw.extend(insp.inspect(text));
        }
        // Apply per-tenant detector filter first — kinds the tenant has
        // disabled are dropped silently so the audit trail still shows
        // a finished scan with `total_matches` reflecting the filter.
        raw.retain(|m| tenant_cfg.is_enabled(m.kind));

        // HIGH-004 multi-signal fusion. Every retained match runs
        // through the detector for FP-suppression + per-signal scoring
        // + calibrated confidence. Below-threshold findings are dropped.
        let mut matches: Vec<DlpMatch> = Vec::with_capacity(raw.len());
        for mut m in raw {
            let Some(event) = self.detector.evaluate(text, &m) else {
                // Suppressed by the builtin / configured FP list.
                continue;
            };
            if event.confidence + f32::EPSILON < min_confidence {
                continue;
            }
            m.confidence = event.confidence;
            m.signals = event.signals;
            matches.push(m);
        }
        // Sort by offset for deterministic output.
        matches.sort_by_key(|m| m.offset);

        let summary = Self::summarise(&matches);
        let id = Uuid::now_v7().to_string();
        let finished_at = Self::now_rfc3339();

        let entry = ScanHistoryEntry {
            id: id.clone(),
            tenant_id: tenant_id.to_owned(),
            source,
            finished_at: finished_at.clone(),
            bytes_scanned: bytes,
            total_matches: matches.len(),
            summary: summary.clone(),
        };

        let mut guard = self
            .history
            .lock()
            .map_err(|_| DlpError::Internal("history store poisoned".to_owned()))?;
        guard.insert(0, entry);
        if guard.len() > HISTORY_CAP {
            guard.truncate(HISTORY_CAP);
        }
        drop(guard);

        tracing::info!(
            target: "sx_dlp",
            tenant_id = %tenant_id,
            scan_id = %id,
            bytes,
            total_matches = matches.len(),
            "dlp.scan completed"
        );

        Ok(DlpScanResult {
            id,
            tenant_id: tenant_id.to_owned(),
            finished_at,
            bytes_scanned: bytes,
            total_matches: matches.len(),
            summary,
            matches,
        })
    }

    async fn list_history(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<ScanHistoryEntry>, DlpError> {
        if tenant_id.is_empty() {
            return Err(DlpError::InvalidTenant);
        }
        let guard = self
            .history
            .lock()
            .map_err(|_| DlpError::Internal("history store poisoned".to_owned()))?;
        let capped = limit.min(HISTORY_CAP);
        Ok(guard
            .iter()
            .filter(|e| e.tenant_id == tenant_id)
            .take(capped)
            .cloned()
            .collect())
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_empty_tenant() {
        let svc = InMemoryDlpService::with_defaults();
        let res = svc.scan_text("", ScanSource::Api, "hi").await;
        assert!(matches!(res, Err(DlpError::InvalidTenant)));
    }

    #[tokio::test]
    async fn rejects_oversized_payload() {
        let svc = InMemoryDlpService::with_defaults();
        let big = "a".repeat(MAX_PAYLOAD_BYTES + 1);
        let res = svc.scan_text("t1", ScanSource::Api, &big).await;
        assert!(matches!(res, Err(DlpError::PayloadTooLarge(_))));
    }

    #[tokio::test]
    async fn empty_text_returns_no_matches() {
        let svc = InMemoryDlpService::with_defaults();
        let res = svc.scan_text("t1", ScanSource::Api, "").await.unwrap();
        assert_eq!(res.total_matches, 0);
        assert!(res.summary.is_empty());
    }

    #[tokio::test]
    async fn finds_pan_and_emits_summary() {
        let svc = InMemoryDlpService::with_defaults();
        // Luhn-valid PAN NOT on the HIGH-004 builtin suppression list.
        let res = svc
            .scan_text("t1", ScanSource::Api, "card 4539 5787 6362 1486")
            .await
            .unwrap();
        assert!(res.total_matches >= 1);
        let has_cc = res
            .summary
            .iter()
            .any(|s| matches!(s.kind, DlpMatchKind::CreditCard));
        assert!(has_cc);
    }

    #[tokio::test]
    async fn finds_multiple_categories_in_one_payload() {
        let svc = InMemoryDlpService::with_defaults();
        // Use a non-RFC SSN (`123-45-6789` is on the HIGH-004 suppression list).
        let text = "ssn=555-12-3456 email=alice@example.com tok=ghp_ABCDEFGHIJ1234567890abcdef1234567890ABCD";
        let res = svc.scan_text("t1", ScanSource::Api, text).await.unwrap();
        let kinds: Vec<DlpMatchKind> = res.matches.iter().map(|m| m.kind).collect();
        assert!(kinds.contains(&DlpMatchKind::SsnUs));
        assert!(kinds.contains(&DlpMatchKind::Email));
        assert!(kinds.contains(&DlpMatchKind::GithubPat));
    }

    #[tokio::test]
    async fn history_is_scoped_per_tenant() {
        let svc = InMemoryDlpService::with_defaults();
        svc.scan_text("t1", ScanSource::Api, "a@b.com")
            .await
            .unwrap();
        svc.scan_text("t2", ScanSource::Api, "c@d.com")
            .await
            .unwrap();
        let h1 = svc.list_history("t1", 50).await.unwrap();
        let h2 = svc.list_history("t2", 50).await.unwrap();
        assert_eq!(h1.len(), 1);
        assert_eq!(h2.len(), 1);
        assert_eq!(h1[0].tenant_id, "t1");
        assert_eq!(h2[0].tenant_id, "t2");
    }

    #[tokio::test]
    async fn history_orders_newest_first() {
        let svc = InMemoryDlpService::with_defaults();
        let first = svc.scan_text("t1", ScanSource::Api, "first").await.unwrap();
        // Two uuid v7 values monotonically increase per millisecond; the
        // second insert lands at slot 0.
        let second = svc
            .scan_text("t1", ScanSource::Api, "second")
            .await
            .unwrap();
        let h = svc.list_history("t1", 50).await.unwrap();
        assert_eq!(h.len(), 2);
        // The newest-first contract is on insertion order, which we own
        // deterministically — checking the ids round-trips the contract
        // without depending on the clock's subsecond precision.
        assert_eq!(h[0].id, second.id);
        assert_eq!(h[1].id, first.id);
    }

    #[tokio::test]
    async fn history_never_holds_raw_payload() {
        // Defensive contract test — ScanHistoryEntry must not expose the
        // payload; only counts.
        let svc = InMemoryDlpService::with_defaults();
        svc.scan_text("t1", ScanSource::Api, "alice@example.com")
            .await
            .unwrap();
        let h = svc.list_history("t1", 50).await.unwrap();
        let json = serde_json::to_string(&h[0]).unwrap();
        assert!(!json.contains("alice@example.com"));
    }

    #[test]
    fn default_inspector_set_has_twelve_categories() {
        let svc = InMemoryDlpService::with_defaults();
        assert_eq!(svc.inspector_count(), 12);
    }

    #[tokio::test]
    async fn tenant_config_disables_category_for_that_tenant_only() {
        use crate::config::TenantDetectorConfig;
        use std::collections::BTreeSet;

        let svc = InMemoryDlpService::with_defaults();
        // Tenant A has email DISABLED, tenant B is on permissive default.
        let mut enabled = BTreeSet::new();
        let _ = enabled.insert(DlpMatchKind::CreditCard);
        let _ = svc.put_tenant_config(
            "a",
            TenantDetectorConfig {
                enabled,
                min_confidence: crate::config::DEFAULT_MIN_CONFIDENCE,
            },
        );

        let text = "ping alice@example.com please";
        let a = svc.scan_text("a", ScanSource::Api, text).await.unwrap();
        let b = svc.scan_text("b", ScanSource::Api, text).await.unwrap();
        assert!(!a.matches.iter().any(|m| m.kind == DlpMatchKind::Email));
        assert!(b.matches.iter().any(|m| m.kind == DlpMatchKind::Email));
    }

    #[tokio::test]
    async fn tenant_config_empty_enabled_set_returns_zero_matches() {
        use crate::config::TenantDetectorConfig;
        use std::collections::BTreeSet;

        let svc = InMemoryDlpService::with_defaults();
        let _ = svc.put_tenant_config(
            "muted",
            TenantDetectorConfig {
                enabled: BTreeSet::new(),
                min_confidence: crate::config::DEFAULT_MIN_CONFIDENCE,
            },
        );
        let res = svc
            .scan_text(
                "muted",
                ScanSource::Api,
                "alice@example.com 4111 1111 1111 1111",
            )
            .await
            .unwrap();
        assert_eq!(res.total_matches, 0);
    }

    #[tokio::test]
    async fn custom_inspector_set_is_respected() {
        struct OnlyOne;
        impl ContentInspector for OnlyOne {
            fn name(&self) -> &'static str {
                "only_one"
            }
            fn inspect(&self, text: &str) -> Vec<DlpMatch> {
                if text.contains("needle") {
                    vec![DlpMatch {
                        kind: DlpMatchKind::NamedEntity,
                        offset: 0,
                        length: 6,
                        redacted_preview: "needle".into(),
                        ..Default::default()
                    }]
                } else {
                    vec![]
                }
            }
        }
        let svc = InMemoryDlpService::with_inspectors(vec![Box::new(OnlyOne)]);
        assert_eq!(svc.inspector_count(), 1);
        let res = svc
            .scan_text("t1", ScanSource::Api, "x needle y")
            .await
            .unwrap();
        assert_eq!(res.total_matches, 1);
    }

    #[test]
    fn summarise_groups_by_kind() {
        let matches = vec![
            DlpMatch {
                kind: DlpMatchKind::Email,
                offset: 0,
                length: 1,
                redacted_preview: "*".into(),
                ..Default::default()
            },
            DlpMatch {
                kind: DlpMatchKind::Email,
                offset: 1,
                length: 1,
                redacted_preview: "*".into(),
                ..Default::default()
            },
            DlpMatch {
                kind: DlpMatchKind::Phone,
                offset: 2,
                length: 1,
                redacted_preview: "*".into(),
                ..Default::default()
            },
        ];
        let s = InMemoryDlpService::summarise(&matches);
        let email = s
            .iter()
            .find(|k| matches!(k.kind, DlpMatchKind::Email))
            .unwrap();
        let phone = s
            .iter()
            .find(|k| matches!(k.kind, DlpMatchKind::Phone))
            .unwrap();
        assert_eq!(email.count, 2);
        assert_eq!(phone.count, 1);
    }

    #[test]
    fn redaction_round_trip_obscures_the_match() {
        use crate::preview::redact;
        let raw = "AKIAIOSFODNN7EXAMPLE";
        let red = redact(raw);
        // Must keep first 4 + last 2.
        assert!(red.starts_with("AKIA"));
        assert!(red.ends_with("LE"));
        // Must drop the middle.
        assert!(!red.contains("IOSFODNN7EXAMP"));
        // Same length so audit columns line up.
        assert_eq!(red.len(), raw.len());
    }
}
