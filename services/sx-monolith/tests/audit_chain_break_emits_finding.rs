//! TOP5-#3-P2-007 — integration coverage for the audit chain-break
//! Finding emitter.
//!
//! What this asserts (acceptance criteria from the dispatch prompt):
//!
//! 1. A synthetic [`sx_audit::ChainVerifier`] tick that detects a
//!    tampered chain causes a [`FindingView`] to land in the
//!    `FindingRepositoryPort`.
//! 2. Re-firing the same break (a subsequent verifier tick over the
//!    same tampered window) does NOT add a duplicate row — the
//!    deterministic finding-id contract makes the second `insert` a
//!    no-op via FOUND-001's idempotency clause.
//! 3. The persisted finding carries the curated enrichment payload:
//!    CWE-117 + CWE-345, MITRE ATT&CK T1562.008, NIST AU-9.
//!
//! ## Why the emitter logic lives in this test file too
//!
//! `sx-monolith` ships only a binary target (`src/main.rs`); there is
//! no library surface from which the integration test can import the
//! private `audit_break_observer::AuditBreakFindingEmitter` adapter
//! directly (the same shape FOUND-001's
//! `services/sx-monolith/tests/finding_insert.rs` documents).
//!
//! The translation under test is intentionally a *near-copy* of the
//! adapter — it shares the same enrichment table lookup from
//! `sx_core::reference::audit_enrichment` and the same finding-id
//! derivation contract. The unit tests inside
//! `services/sx-monolith/src/adapters/audit_break_observer.rs` pin the
//! exact emitter behaviour; this integration test guards the
//! *contract* (chain-break → enriched finding, idempotent, persisted)
//! end-to-end across the `sx-audit` verifier, the `sx-core` enrichment
//! table, and a `FindingRepositoryPort` mock that mirrors the FOUND-001
//! in-memory adapter semantics.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::similar_names)]
#![allow(clippy::significant_drop_tightening)]

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use sx_api::port::{EngagementPortError, FindingRepositoryPort};
use sx_api::view::finding_view::FindingView;
use sx_audit::chain_verifier::{
    AuditChainBrokenPayload, BrokenChainSubscriber, ChainVerifier, Clock, DEFAULT_INTERVAL,
};
use sx_audit::error::AuditError;
use sx_audit::model::action::AuditAction;
use sx_audit::model::actor::Actor;
use sx_audit::model::entry::AuditEntry;
use sx_audit::prelude::AuditSink;
use sx_audit::service::chain_builder::{build_entry, build_genesis, NewAuditEvent};
use sx_core::reference::audit_enrichment::{audit_enrichment, AUDIT_CHAIN_BROKEN_DOTTED};
use sx_core::value_object::ids::{TenantId, UserId};

// ---------------------------------------------------------------------------
// In-memory `FindingRepositoryPort` — mirrors FOUND-001's
// `services/sx-monolith/src/adapters/repository.rs::InMemoryFindings`.
// Last-write-wins on `(tenant_id, id)`; insert never errors.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct InMemoryFindings {
    rows: std::sync::Mutex<HashMap<(String, String), FindingView>>,
    insert_calls: std::sync::Mutex<u32>,
}

#[async_trait]
impl FindingRepositoryPort for InMemoryFindings {
    async fn list(
        &self,
        tenant_id: &str,
        offset: u64,
        limit: u32,
    ) -> Result<Vec<FindingView>, EngagementPortError> {
        let g = self.rows.lock().unwrap();
        Ok(g.iter()
            .filter(|((t, _), _)| t == tenant_id)
            .map(|(_, v)| v.clone())
            .skip(offset as usize)
            .take(limit as usize)
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
        Err(EngagementPortError::NotFound)
    }

    async fn insert(&self, view: FindingView) -> Result<FindingView, EngagementPortError> {
        *self.insert_calls.lock().unwrap() += 1;
        let key = (view.tenant_id.clone(), view.id.clone());
        self.rows.lock().unwrap().insert(key, view.clone());
        Ok(view)
    }
}

// ---------------------------------------------------------------------------
// In-memory `AuditSink` — mirrors the test sink in
// `crates/sx-audit/src/chain_verifier.rs::tests::VecSink`. Holds the
// per-tenant chain so the production-shape `ChainVerifier::run_once`
// path reaches our subscriber.
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct VecSink {
    entries: AsyncMutex<Vec<AuditEntry>>,
}

#[async_trait]
impl AuditSink for VecSink {
    async fn append(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        self.entries.lock().await.push(entry.clone());
        Ok(())
    }
    async fn last_entry_for_tenant(&self, tid: TenantId) -> Result<Option<AuditEntry>, AuditError> {
        let g = self.entries.lock().await;
        Ok(g.iter()
            .filter(|e| e.tenant_id == tid)
            .max_by_key(|e| e.seq)
            .cloned())
    }
    async fn read_range(
        &self,
        tid: TenantId,
        from: u64,
        to: u64,
    ) -> Result<Vec<AuditEntry>, AuditError> {
        let g = self.entries.lock().await;
        let mut v: Vec<AuditEntry> = g
            .iter()
            .filter(|e| e.tenant_id == tid && e.seq >= from && e.seq <= to)
            .cloned()
            .collect();
        v.sort_by_key(|e| e.seq);
        Ok(v)
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct FixedClock;
impl Clock for FixedClock {
    fn now_rfc3339(&self) -> String {
        "2026-06-25T00:00:00Z".to_owned()
    }
}

// ---------------------------------------------------------------------------
// Test-side translation. This is a near-copy of the production
// `AuditBreakFindingEmitter::build_view` so the integration test
// stays self-contained while the unit tests in the adapter file pin
// the exact production shape. Reads the enrichment table from
// `sx_core::reference::audit_enrichment` — the *same* import the
// production emitter uses — so a typo in the curated payload trips
// this test as well.
// ---------------------------------------------------------------------------

const META_ENGAGEMENT_ID: &str = "engagement_id";
const META_RULE_ID: &str = "rule_id";

fn derive_uuid_from_components(domain: &str, components: &[&str]) -> Uuid {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update(b"\x1f");
    for c in components {
        h.update(c.as_bytes());
        h.update(b"\x1f");
    }
    let digest = h.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    Uuid::from_bytes(bytes)
}

fn translate_break_to_view(payload: &AuditChainBrokenPayload) -> FindingView {
    let tenant_id = payload.tenant_id.to_string();
    let break_seq = payload.break_seq.to_string();
    let finding_id = derive_uuid_from_components(
        "sentinelx.audit_break_finding.v1",
        &[
            &tenant_id,
            &break_seq,
            &payload.expected_hash,
            &payload.actual_hash,
        ],
    )
    .to_string();
    let engagement_id =
        derive_uuid_from_components("sentinelx.audit.system_engagement.v1", &[&tenant_id])
            .to_string();
    let asset_id =
        derive_uuid_from_components("sentinelx.audit.system_asset.v1", &[&tenant_id]).to_string();

    let enrichment = audit_enrichment(AUDIT_CHAIN_BROKEN_DOTTED).unwrap();
    let cwe: Vec<String> = enrichment.cwe.iter().map(ToString::to_string).collect();
    let mitre: Vec<serde_json::Value> = enrichment
        .mitre_attack
        .iter()
        .map(|m| {
            serde_json::json!({
                "tactic": m.tactic,
                "technique": m.technique,
                "subtechnique": m.subtechnique,
            })
        })
        .collect();
    let nist: Vec<String> = enrichment
        .compliance
        .nist_800_53
        .iter()
        .map(|n| n.as_str().to_owned())
        .collect();

    let metadata = serde_json::json!({
        META_ENGAGEMENT_ID: engagement_id,
        META_RULE_ID: AUDIT_CHAIN_BROKEN_DOTTED,
        "check_id": AUDIT_CHAIN_BROKEN_DOTTED,
        "break_seq": payload.break_seq,
        "last_good_seq": payload.last_good_seq,
        "confidence": 1.0_f64,
        "enrichment": {
            "cwe": cwe,
            "mitre_attack": mitre,
            "nist_800_53": nist,
        },
    });

    FindingView {
        id: finding_id,
        tenant_id,
        asset_id,
        severity: "high".to_owned(),
        status: "open".to_owned(),
        title: "Audit chain hash mismatch detected".to_owned(),
        description: format!("chain divergence at seq {seq}", seq = payload.break_seq),
        cvss: None,
        cve_id: None,
        first_seen: payload.detected_at.clone(),
        last_seen: payload.detected_at.clone(),
        metadata: Some(metadata),
    }
}

struct AuditBreakSubscriber {
    findings: Arc<dyn FindingRepositoryPort>,
}

impl std::fmt::Debug for AuditBreakSubscriber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditBreakSubscriber")
            .field("findings", &"<dyn FindingRepositoryPort>")
            .finish()
    }
}

#[async_trait]
impl BrokenChainSubscriber for AuditBreakSubscriber {
    async fn on_broken(&self, payload: &AuditChainBrokenPayload) {
        let view = translate_break_to_view(payload);
        let _ = self.findings.insert(view).await;
    }
}

// ---------------------------------------------------------------------------
// Chain fixture builders — copied from
// `crates/sx-audit/src/chain_verifier.rs::tests` so the test rig
// drives the same production code path as the verifier unit tests.
// ---------------------------------------------------------------------------

fn tenant() -> TenantId {
    Uuid::parse_str("00000000-0000-7000-8000-00000000000a")
        .unwrap()
        .into()
}

fn audit_event(seq_hint: u64, tid: TenantId) -> NewAuditEvent {
    let user: UserId = Uuid::parse_str("00000000-0000-7000-8000-000000000002")
        .unwrap()
        .into();
    NewAuditEvent {
        tenant_id: tid,
        actor: Actor::user(user),
        action: AuditAction::Login,
        resource_kind: "session".to_owned(),
        resource_id: format!("s-{seq_hint}"),
        before: None,
        after: None,
        request_id: format!("req-{seq_hint}"),
        ts: Some(
            time::OffsetDateTime::from_unix_timestamp(1_700_000_000 + seq_hint as i64).unwrap(),
        ),
    }
}

fn make_chain(tid: TenantId, n: u64) -> Vec<AuditEntry> {
    let mut entries = Vec::with_capacity(n as usize);
    let g = build_genesis(audit_event(1, tid)).unwrap();
    entries.push(g);
    for i in 2..=n {
        let prev = entries.last().unwrap();
        let e = build_entry(i, prev.hash, audit_event(i, tid)).unwrap();
        entries.push(e);
    }
    entries
}

async fn seed_chain(sink: &VecSink, entries: &[AuditEntry]) {
    for e in entries {
        sink.append(e).await.unwrap();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// AC (a) + (c): a synthetic chain-break causes the subscriber to land
/// a finding through `FindingRepositoryPort::insert`, and the
/// persisted view carries the curated enrichment payload.
#[tokio::test]
async fn chain_break_emits_enriched_finding() {
    let sink = Arc::new(VecSink::default());
    let mut entries = make_chain(tenant(), 5);
    entries[2].request_id = "TAMPERED".to_owned();
    seed_chain(&sink, &entries).await;

    let findings: Arc<InMemoryFindings> = Arc::new(InMemoryFindings::default());
    let subscriber: Arc<dyn BrokenChainSubscriber> = Arc::new(AuditBreakSubscriber {
        findings: Arc::clone(&findings) as Arc<dyn FindingRepositoryPort>,
    });

    let verifier = ChainVerifier::new(
        Arc::clone(&sink) as Arc<dyn AuditSink>,
        vec![subscriber],
        Arc::new(FixedClock),
        DEFAULT_INTERVAL,
    );
    verifier.register_tenant(tenant()).await;

    // Drive one production-shape tick.
    let _ = verifier.run_once().await;

    // AC (a) — exactly one finding landed.
    let rows = findings
        .list(&tenant().to_string(), 0, 100)
        .await
        .expect("list ok");
    assert_eq!(rows.len(), 1, "expected one finding, got {rows:?}");

    let view = &rows[0];
    assert_eq!(view.severity, "high");
    assert_eq!(view.status, "open");
    assert_eq!(view.title, "Audit chain hash mismatch detected");
    assert_eq!(view.tenant_id, tenant().to_string());

    // AC (c) — enrichment payload.
    let meta = view.metadata.as_ref().expect("metadata present");
    // FOUND-001 contract: engagement_id + rule_id must be in metadata
    // (the Postgres adapter rejects with `Invalid` otherwise).
    let eng = meta
        .get(META_ENGAGEMENT_ID)
        .and_then(|v| v.as_str())
        .expect("engagement_id present");
    Uuid::parse_str(eng).expect("engagement_id parses as UUID");
    assert_eq!(
        meta.get(META_RULE_ID).and_then(|v| v.as_str()),
        Some(AUDIT_CHAIN_BROKEN_DOTTED)
    );
    // TOP5-#3 Phase 3: emit uses dotted-form `check_id`.
    let cid = meta
        .get("check_id")
        .and_then(|v| v.as_str())
        .expect("check_id present");
    assert!(
        cid.contains('.'),
        "TOP5-#3 Phase 3: check_id must be dotted-form; got `{cid}`"
    );
    assert_eq!(cid, AUDIT_CHAIN_BROKEN_DOTTED);

    let enr = meta.get("enrichment").expect("enrichment present");
    let cwe = enr
        .get("cwe")
        .and_then(|v| v.as_array())
        .expect("cwe array");
    assert!(
        cwe.iter().any(|v| v.as_str() == Some("CWE-117")),
        "CWE-117 expected: {cwe:?}"
    );
    assert!(
        cwe.iter().any(|v| v.as_str() == Some("CWE-345")),
        "CWE-345 expected: {cwe:?}"
    );

    let mitre = enr
        .get("mitre_attack")
        .and_then(|v| v.as_array())
        .expect("mitre array");
    assert!(
        mitre.iter().any(|m| {
            m.get("technique").and_then(|t| t.as_str()) == Some("T1562")
                && m.get("subtechnique").and_then(|t| t.as_str()) == Some("T1562.008")
        }),
        "MITRE T1562.008 expected: {mitre:?}",
    );

    let nist = enr
        .get("nist_800_53")
        .and_then(|v| v.as_array())
        .expect("nist array");
    assert!(
        nist.iter().any(|v| v.as_str() == Some("AU-9")),
        "NIST AU-9 expected: {nist:?}"
    );

    assert_eq!(
        meta.get("confidence").and_then(serde_json::Value::as_f64),
        Some(1.0)
    );
}

/// AC (b): re-firing the verifier over the same tampered window must
/// NOT create a duplicate finding. The FOUND-001 `(tenant_id, id)`
/// idempotency clause plus the deterministic finding-id derivation
/// collapse re-fires into a single persisted row.
#[tokio::test]
async fn rebroken_chain_does_not_duplicate_finding() {
    let sink = Arc::new(VecSink::default());
    let mut entries = make_chain(tenant(), 6);
    entries[3].request_id = "TAMPERED-REFIRE".to_owned();
    seed_chain(&sink, &entries).await;

    let findings: Arc<InMemoryFindings> = Arc::new(InMemoryFindings::default());
    let subscriber: Arc<dyn BrokenChainSubscriber> = Arc::new(AuditBreakSubscriber {
        findings: Arc::clone(&findings) as Arc<dyn FindingRepositoryPort>,
    });
    let verifier = ChainVerifier::new(
        Arc::clone(&sink) as Arc<dyn AuditSink>,
        vec![subscriber],
        Arc::new(FixedClock),
        DEFAULT_INTERVAL,
    );
    verifier.register_tenant(tenant()).await;

    // Three ticks (the verifier would normally re-run every
    // `DEFAULT_INTERVAL` until the tamper is rotated out). No sleep
    // between ticks — the tick is deterministic on the in-memory sink.
    for _ in 0..3 {
        let _ = verifier.run_once().await;
    }

    // Insert was called every tick…
    let insert_calls = *findings.insert_calls.lock().unwrap();
    assert_eq!(
        insert_calls, 3,
        "subscriber fired on every tick (got {insert_calls})"
    );
    // …but exactly one row landed.
    let rows = findings
        .list(&tenant().to_string(), 0, 100)
        .await
        .expect("list ok");
    assert_eq!(
        rows.len(),
        1,
        "re-fire must NOT duplicate the finding, got {rows:?}",
    );
}
