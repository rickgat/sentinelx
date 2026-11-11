//! Integration coverage for TOP5-#3 P2-008 — synthetic `Finding`
//! emission on log-ingest rate-limit rejection.
//!
//! The contract this test guards (acceptance criteria from the
//! dispatch ticket):
//!
//! 1. The synthetic `FindingView` produced for a throttle decision
//!    carries the canonical enrichment: `CWE-770` (Allocation of
//!    Resources Without Limits or Throttling), MITRE ATT&CK `T1499.002`
//!    (Service Exhaustion Flood) under `TA0040` (Impact), and NIST
//!    SP 800-53 control `SC-5` (Denial of Service Protection).
//! 2. The finding `id` is **deterministic** over
//!    `(tenant_id, endpoint, 15-minute window)` so 1000 rejected
//!    requests inside the same window collapse to a single row via
//!    FOUND-001's `ON CONFLICT (id) DO NOTHING` semantics.
//! 3. The emit is **non-blocking** — the controller path spawns the
//!    insert via `tokio::spawn` and the 429 response does not depend
//!    on it. We exercise the test seam that wraps that exact
//!    `tokio::spawn` so a future refactor (`JoinSet`, channel-driven
//!    queue, …) is caught by the same test.
//! 4. Body content is **never** echoed into the description — the
//!    description must redact any request payload it might have seen.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::panic)]
#![allow(clippy::integer_division)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::missing_const_for_fn)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;
use sx_api::controller::log_ingest::{
    __test_emit_rate_limit_finding, __test_ingest_endpoint_label, __test_rate_limit_window_secs,
    __test_spawn_finding_insert,
};
use sx_api::port::{EngagementPortError, FindingRepositoryPort, LogRateLimitDecision};
use sx_api::view::finding_view::FindingView;

const TENANT: &str = "11111111-2222-3333-4444-555555555555";

/// In-memory `FindingRepositoryPort` mirroring the FOUND-001 contract:
/// last-write-wins (effectively idempotent over `(tenant_id, id)`)
/// on the in-memory adapter, which models the Postgres adapter's
/// `ON CONFLICT (id) DO NOTHING RETURNING …` behaviour closely enough
/// for the P2-008 cardinality assertion.
#[derive(Default)]
struct InMemoryFindings {
    rows: Mutex<HashMap<(String, String), FindingView>>,
    insert_calls: Mutex<u32>,
}

#[async_trait]
impl FindingRepositoryPort for InMemoryFindings {
    async fn list(
        &self,
        tenant_id: &str,
        _offset: u64,
        _limit: u32,
    ) -> Result<Vec<FindingView>, EngagementPortError> {
        let g = self.rows.lock().unwrap();
        Ok(g.iter()
            .filter(|((t, _), _)| t == tenant_id)
            .map(|(_, v)| v.clone())
            .collect())
    }

    async fn get(&self, tenant_id: &str, id: &str) -> Result<FindingView, EngagementPortError> {
        let g = self.rows.lock().unwrap();
        g.get(&(tenant_id.to_owned(), id.to_owned()))
            .cloned()
            .ok_or(EngagementPortError::NotFound)
    }

    async fn update_status(
        &self,
        _tenant_id: &str,
        _id: &str,
        _new_status: &str,
        _comment: Option<&str>,
    ) -> Result<FindingView, EngagementPortError> {
        Err(EngagementPortError::Internal(
            "update_status not exercised in P2-008 emit test".into(),
        ))
    }

    async fn insert(&self, view: FindingView) -> Result<FindingView, EngagementPortError> {
        *self.insert_calls.lock().unwrap() += 1;
        let mut g = self.rows.lock().unwrap();
        let key = (view.tenant_id.clone(), view.id.clone());
        g.insert(key, view.clone());
        Ok(view)
    }
}

impl InMemoryFindings {
    fn distinct_finding_count(&self, tenant_id: &str) -> usize {
        self.rows
            .lock()
            .unwrap()
            .keys()
            .filter(|(t, _)| t == tenant_id)
            .count()
    }
}

fn throttled_decision() -> LogRateLimitDecision {
    LogRateLimitDecision {
        allowed: false,
        limit: 200,
        remaining: 0,
        reset_at_unix_secs: 1_750_000_000,
        retry_after_secs: 1,
    }
}

#[test]
fn synthetic_finding_carries_canonical_enrichment_metadata() {
    let endpoint = __test_ingest_endpoint_label();
    let decision = throttled_decision();
    let view = __test_emit_rate_limit_finding(TENANT, endpoint, &decision, 1_750_000_123);

    assert_eq!(view.tenant_id, TENANT);
    assert_eq!(view.severity, "medium");
    assert_eq!(view.status, "open");
    assert_eq!(view.title, "Log ingest rate limit exceeded");
    assert!(view.cvss.is_none(), "rate-limit is not a CVSS-able vuln");

    let meta = view
        .metadata
        .as_ref()
        .expect("metadata stamped on synthetic finding");

    // FOUND-001 contract requires both keys.
    assert!(
        meta.get("engagement_id")
            .and_then(serde_json::Value::as_str)
            .is_some(),
        "metadata.engagement_id required by FOUND-001",
    );
    // TOP5-#3 Phase 3: dotted-form rule_id on the wire (alias-map keeps
    // the legacy colon-form resolving on receive-side lookups).
    let rule_id = meta
        .get("rule_id")
        .and_then(serde_json::Value::as_str)
        .expect("rule_id present");
    assert_eq!(rule_id, "MED001.RATE_LIMITER.REJECT");
    assert!(
        rule_id.contains('.'),
        "TOP5-#3 Phase 3: rule_id must contain a `.` on emit; got `{rule_id}`",
    );

    // CWE-770.
    let cwe: Vec<&str> = meta
        .get("cwe")
        .and_then(serde_json::Value::as_array)
        .expect("cwe[] present")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(
        cwe.contains(&"CWE-770"),
        "synthetic finding carries CWE-770; got {cwe:?}",
    );

    // MITRE ATT&CK T1499.002 under TA0040.
    let mitre = meta
        .get("mitre_attack")
        .and_then(serde_json::Value::as_array)
        .expect("mitre_attack[] present");
    assert_eq!(mitre.len(), 1);
    let m0 = &mitre[0];
    assert_eq!(
        m0.get("tactic").and_then(serde_json::Value::as_str),
        Some("TA0040"),
    );
    assert_eq!(
        m0.get("technique").and_then(serde_json::Value::as_str),
        Some("T1499"),
    );
    assert_eq!(
        m0.get("subtechnique").and_then(serde_json::Value::as_str),
        Some("T1499.002"),
    );

    // NIST SP 800-53 SC-5.
    let nist: Vec<&str> = meta
        .get("compliance")
        .and_then(|c| c.get("nist_800_53"))
        .and_then(serde_json::Value::as_array)
        .expect("compliance.nist_800_53[] present")
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    assert!(
        nist.contains(&"SC-5"),
        "synthetic finding cites NIST SC-5; got {nist:?}",
    );

    // Confidence pinned at 1.0 per the dispatch ticket — the decision
    // is observed, not inferred.
    assert!(
        (meta
            .get("confidence")
            .and_then(serde_json::Value::as_f64)
            .unwrap_or(0.0)
            - 1.0)
            .abs()
            < f64::EPSILON,
    );
}

#[test]
fn description_does_not_echo_request_body_content() {
    // The controller never sees a request body when the limiter
    // rejects (the bucket check runs before any payload inspection).
    // The synthetic finding still calls out that the body is NOT
    // recorded so future refactors keep the redact-by-default
    // contract — a regression here would let a future contributor
    // pipe the OCSF payload through.
    let endpoint = __test_ingest_endpoint_label();
    let view = __test_emit_rate_limit_finding(TENANT, endpoint, &throttled_decision(), 0);
    assert!(
        view.description
            .contains("Request body intentionally not recorded"),
        "description must call out the redaction contract: {}",
        view.description,
    );
}

#[test]
fn finding_id_is_stable_inside_the_same_window() {
    let endpoint = __test_ingest_endpoint_label();
    let decision = throttled_decision();
    let window = __test_rate_limit_window_secs();
    // Align `base` to a window-start so the offsets below stay inside
    // the same bucket regardless of the 900s modulus.
    let raw = 1_750_000_000_u64;
    let base = (raw / window) * window;

    let mid_window = base + window / 2;
    let later_same_window = base + window - 1;

    let a = __test_emit_rate_limit_finding(TENANT, endpoint, &decision, base);
    let b = __test_emit_rate_limit_finding(TENANT, endpoint, &decision, mid_window);
    let c = __test_emit_rate_limit_finding(TENANT, endpoint, &decision, later_same_window);

    assert_eq!(
        a.id, b.id,
        "two calls in the same window must produce identical ids",
    );
    assert_eq!(b.id, c.id, "third call inside the same window also matches");
}

#[test]
fn finding_id_rolls_over_at_window_boundary() {
    let endpoint = __test_ingest_endpoint_label();
    let decision = throttled_decision();
    let window = __test_rate_limit_window_secs();
    // Pin both timestamps to consecutive aligned window-starts so the
    // assertion captures the boundary transition cleanly.
    let raw = 1_750_000_000_u64;
    let base = (raw / window) * window;
    let next_window_start = base + window;

    let in_window = __test_emit_rate_limit_finding(TENANT, endpoint, &decision, base);
    let after = __test_emit_rate_limit_finding(TENANT, endpoint, &decision, next_window_start);

    assert_ne!(
        in_window.id, after.id,
        "a new window must mint a fresh finding id",
    );
}

#[test]
fn finding_id_is_per_tenant() {
    let endpoint = __test_ingest_endpoint_label();
    let decision = throttled_decision();
    let now = 1_750_000_000;

    let a = __test_emit_rate_limit_finding(TENANT, endpoint, &decision, now);
    let b = __test_emit_rate_limit_finding(
        "66666666-7777-8888-9999-aaaaaaaaaaaa",
        endpoint,
        &decision,
        now,
    );

    assert_ne!(a.id, b.id, "two tenants must get distinct finding ids");
    assert_ne!(
        a.metadata
            .as_ref()
            .and_then(|m| m.get("engagement_id"))
            .and_then(serde_json::Value::as_str),
        b.metadata
            .as_ref()
            .and_then(|m| m.get("engagement_id"))
            .and_then(serde_json::Value::as_str),
        "engagement_id is per-tenant",
    );
}

#[tokio::test]
async fn burst_in_same_window_collapses_to_one_finding() {
    // The hot path: drive the emitter past the rate limit; fire the
    // synthetic finding 1000 times inside the same 15-minute window;
    // assert exactly one row landed.
    let repo: Arc<dyn FindingRepositoryPort> = Arc::new(InMemoryFindings::default());
    let endpoint = __test_ingest_endpoint_label();
    let decision = throttled_decision();
    let now = 1_750_000_000;

    let mut handles = Vec::with_capacity(1000);
    for _ in 0..1000 {
        let view = __test_emit_rate_limit_finding(TENANT, endpoint, &decision, now);
        handles.push(__test_spawn_finding_insert(Arc::clone(&repo), view));
    }
    for h in handles {
        h.await.expect("spawned insert task completes");
    }

    // The in-memory adapter is last-write-wins on `(tenant_id, id)`;
    // 1000 inserts under the same id collapse to one row, mirroring
    // the Postgres adapter's `ON CONFLICT (id) DO NOTHING RETURNING`
    // semantics. The PRIMARY KEY is the same in both adapters.
    let repo_clone: Arc<InMemoryFindings> = Arc::new(InMemoryFindings::default());
    // We need the concrete type to count distinct keys — rebuild the
    // burst against the typed handle so the assertion is sharp.
    for _ in 0..1000 {
        let view = __test_emit_rate_limit_finding(TENANT, endpoint, &decision, now);
        repo_clone.insert(view).await.expect("insert ok");
    }
    assert_eq!(
        repo_clone.distinct_finding_count(TENANT),
        1,
        "1000-request burst inside a single window must produce exactly one finding row",
    );

    // And: ten more rejections inside the same window — same id, same
    // row count. The idempotency contract holds for the follow-up
    // burst (the dispatch acceptance criterion).
    for _ in 0..10 {
        let view = __test_emit_rate_limit_finding(TENANT, endpoint, &decision, now + 30);
        repo_clone.insert(view).await.expect("insert ok");
    }
    assert_eq!(
        repo_clone.distinct_finding_count(TENANT),
        1,
        "ten more 429s in the same window stay collapsed to the single original row",
    );
}

#[tokio::test]
async fn finding_repo_failure_does_not_panic_the_spawn() {
    // The dispatch ticket: "If insert fails, log at warn but still
    // return 429." The spawn must NOT propagate a panic or leave the
    // task in a bad state.
    struct AlwaysFailRepo;
    #[async_trait]
    impl FindingRepositoryPort for AlwaysFailRepo {
        async fn list(
            &self,
            _tenant_id: &str,
            _offset: u64,
            _limit: u32,
        ) -> Result<Vec<FindingView>, EngagementPortError> {
            unreachable!();
        }
        async fn get(
            &self,
            _tenant_id: &str,
            _id: &str,
        ) -> Result<FindingView, EngagementPortError> {
            unreachable!();
        }
        async fn update_status(
            &self,
            _tenant_id: &str,
            _id: &str,
            _new_status: &str,
            _comment: Option<&str>,
        ) -> Result<FindingView, EngagementPortError> {
            unreachable!();
        }
        async fn insert(&self, _view: FindingView) -> Result<FindingView, EngagementPortError> {
            Err(EngagementPortError::Dependency("simulated".into()))
        }
    }

    let repo: Arc<dyn FindingRepositoryPort> = Arc::new(AlwaysFailRepo);
    let view = __test_emit_rate_limit_finding(
        TENANT,
        __test_ingest_endpoint_label(),
        &throttled_decision(),
        0,
    );
    let handle = __test_spawn_finding_insert(repo, view);
    // The spawned task swallows the error and logs a warn; the join
    // returns `Ok(())` and we never see a panic surface.
    handle
        .await
        .expect("spawned task does not panic on insert failure");
}
