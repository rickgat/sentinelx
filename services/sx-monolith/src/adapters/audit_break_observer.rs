//! Audit chain-break → synthetic `Finding` emitter (TOP5-#3-P2-007).
//!
//! Wave-B audit recommendation: keep `sx-audit` decoupled from the
//! finding stack and translate `audit.chain.broken` events into
//! [`FindingView`]s at the monolith adapter boundary. This observer is
//! registered as a [`BrokenChainSubscriber`] (a.k.a. [`BreakObserver`])
//! alongside the IR auto-fire subscriber so a single verifier tick
//! both opens an IR incident *and* lights up a Finding in the regular
//! finding read surface.
//!
//! ## Why not have `sx-audit` emit directly
//!
//! `sx-audit` deliberately knows nothing about
//! [`sx_api::view::finding_view::FindingView`] or the finding-repository
//! port — its only contract with the rest of the platform is the
//! tamper-evident `AuditSink` + the per-tenant hash chain. Threading a
//! `FindingRepositoryPort` into `sx-audit` would invert that direction
//! and pull a large dep tree into a crate that intentionally has none.
//! Translating at the monolith boundary keeps both crates pure and
//! co-locates the FOUND-001 metadata contract enforcement with the
//! adapter that already enforces it for every other emitter.
//!
//! ## Idempotency
//!
//! Per Wave-B step 4: a chain break may re-fire on every verifier tick
//! until an operator either rotates the broken row out or accepts the
//! tamper. `view.id` is composed deterministically from
//! `(tenant_id, break_seq, expected_hash, actual_hash)` so re-fires
//! collapse into the same `findings.id` PRIMARY KEY — the Postgres
//! adapter's `ON CONFLICT (id) DO NOTHING` clause from FOUND-001 turns
//! the re-fire into a cheap re-read.
//!
//! ## Engagement / asset metadata
//!
//! FOUND-001 requires `metadata.engagement_id` AND `metadata.rule_id`
//! on every insert (the Postgres `findings` table has NOT NULL columns
//! and a FK on `engagement_id`). For audit-internal findings we have no
//! single "real" engagement to attribute the tamper to, so the
//! observer reads `audit.system_engagement_id` from `sx-config` when
//! the operator has provisioned one, and otherwise derives a
//! deterministic per-tenant sentinel UUID via SHA-256 — keeping the
//! Postgres FK semantics correct in production (where the operator
//! creates a real "Platform Internal" engagement row) and the
//! emission path resilient in test / standalone dev where the FK is
//! not enforced.
//!
//! `asset_id` follows the same derivation pattern: there is no real
//! asset on an audit-chain break, so we mint a deterministic per-tenant
//! sentinel via SHA-256. Re-fires collapse to the same id.

use std::sync::Arc;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sx_api::port::{EngagementPortError, FindingRepositoryPort};
use sx_api::view::finding_view::FindingView;
use sx_audit::chain_verifier::{AuditChainBrokenPayload, BrokenChainSubscriber};
use sx_core::reference::audit_enrichment::{audit_enrichment, AUDIT_CHAIN_BROKEN_DOTTED};
use uuid::Uuid;

/// Wire keys the FOUND-001 Postgres adapter extracts from `metadata`.
/// Mirror the constants used by every other emitter so a future
/// refactor that lifts these into a shared module flips one import.
const META_ENGAGEMENT_ID: &str = "engagement_id";
const META_RULE_ID: &str = "rule_id";

/// Adapter that subscribes to `audit.chain.broken` events from the
/// background verifier and lights up a synthetic [`FindingView`] via
/// [`FindingRepositoryPort::insert`].
///
/// The adapter holds a single `Arc<dyn FindingRepositoryPort>` — it is
/// safe to clone and ship across runtimes because the trait object is
/// `Send + Sync` by contract.
pub(crate) struct AuditBreakFindingEmitter {
    findings: Arc<dyn FindingRepositoryPort>,
    /// Optional operator-supplied UUID for the "Platform Internal"
    /// engagement. When `None` the per-call derivation kicks in.
    system_engagement_id: Option<Uuid>,
}

impl std::fmt::Debug for AuditBreakFindingEmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditBreakFindingEmitter")
            .field("system_engagement_id", &self.system_engagement_id)
            .finish_non_exhaustive()
    }
}

impl AuditBreakFindingEmitter {
    /// Construct a new emitter.
    pub(crate) fn new(
        findings: Arc<dyn FindingRepositoryPort>,
        system_engagement_id: Option<Uuid>,
    ) -> Self {
        Self {
            findings,
            system_engagement_id,
        }
    }

    /// Test/helper accessor for the configured engagement id (None in
    /// dev / standalone, Some in production).
    #[cfg(test)]
    pub(crate) fn configured_engagement(&self) -> Option<Uuid> {
        self.system_engagement_id
    }

    /// Translate a chain-break payload into a [`FindingView`] ready for
    /// `FindingRepositoryPort::insert`. Pure — does not touch the port
    /// — so the unit tests can drive every shape independently.
    pub(crate) fn build_view(&self, payload: &AuditChainBrokenPayload) -> FindingView {
        let tenant_id = payload.tenant_id.to_string();
        let finding_id = derive_finding_id(&tenant_id, payload).to_string();
        let engagement_id = self
            .system_engagement_id
            .unwrap_or_else(|| derive_system_engagement_id(&tenant_id))
            .to_string();
        let asset_id = derive_system_asset_id(&tenant_id).to_string();

        // Enrichment table lookup — keeps the CWE / MITRE / NIST
        // payload in one curated place (sx-core/reference) so any future
        // emitter or SARIF exporter consults the same row. Look up via
        // the legacy id (the table accepts both shapes) but emit the
        // canonical dotted-form on the wire (TOP5-#3 Phase 3).
        let enrichment = audit_enrichment(AUDIT_CHAIN_BROKEN_DOTTED).unwrap_or_default();
        let enrichment_meta = serialize_enrichment(&enrichment);

        let metadata = serde_json::json!({
            META_ENGAGEMENT_ID: engagement_id,
            META_RULE_ID: AUDIT_CHAIN_BROKEN_DOTTED,
            // Detection signal — keeps re-fires diagnostic from the
            // wire payload without forcing a `get` round-trip.
            "check_id": AUDIT_CHAIN_BROKEN_DOTTED,
            "break_seq": payload.break_seq,
            "last_good_seq": payload.last_good_seq,
            "expected_hash": payload.expected_hash,
            "actual_hash": payload.actual_hash,
            // Confidence is 1.0 — a chain break is deterministic: the
            // verifier re-computed the SHA-256 from the canonical bytes
            // and observed a divergence. There is no "probably tampered"
            // mode in the detector.
            "confidence": 1.0_f64,
            // Curated enrichment lookups (Wave-B step 3).
            "enrichment": enrichment_meta,
        });

        let description = format!(
            "Audit hash chain integrity violation detected by the \
             background hot-tail verifier (CRIT-002). The recomputed \
             SHA-256 at seq {break_seq} diverged from the stored hash; \
             expected {expected}, observed {actual}. Last good seq: \
             {last_good}. Detected at {detected}.",
            break_seq = payload.break_seq,
            expected = display_hash(&payload.expected_hash),
            actual = display_hash(&payload.actual_hash),
            last_good = payload
                .last_good_seq
                .map_or_else(|| "n/a".to_owned(), |s| s.to_string()),
            detected = payload.detected_at,
        );

        FindingView {
            id: finding_id,
            tenant_id,
            asset_id,
            severity: "high".to_owned(),
            status: "open".to_owned(),
            title: "Audit chain hash mismatch detected".to_owned(),
            description,
            // Per Wave-B step 3: CVSS stays None on chain-break (it is
            // a detection over a control surface, not a vulnerability
            // proof). The CWE/MITRE/NIST payload lives in `metadata`.
            cvss: None,
            cve_id: None,
            first_seen: payload.detected_at.clone(),
            last_seen: payload.detected_at.clone(),
            metadata: Some(metadata),
        }
    }
}

#[async_trait]
impl BrokenChainSubscriber for AuditBreakFindingEmitter {
    async fn on_broken(&self, payload: &AuditChainBrokenPayload) {
        let view = self.build_view(payload);
        let finding_id = view.id.clone();
        let tenant_id = view.tenant_id.clone();
        match self.findings.insert(view).await {
            Ok(persisted) => {
                tracing::error!(
                    target: "monolith.audit_break_finding",
                    tenant = %tenant_id,
                    finding = %persisted.id,
                    break_seq = payload.break_seq,
                    rule_id = AUDIT_CHAIN_BROKEN_DOTTED,
                    "audit.chain.broken synthetic finding persisted"
                );
            }
            Err(EngagementPortError::Conflict(msg)) => {
                // The FOUND-001 contract says implementations SHOULD
                // turn `(tenant_id, view.id)` collisions into a no-op
                // re-read, but a stricter adapter MAY surface
                // `Conflict`. Either is observably-correct for our
                // idempotency goal — re-fires on the same break never
                // double-write — so we log at DEBUG and move on.
                tracing::debug!(
                    target: "monolith.audit_break_finding",
                    tenant = %tenant_id,
                    finding = %finding_id,
                    break_seq = payload.break_seq,
                    reason = %msg,
                    "audit.chain.broken finding insert conflict (re-fire on existing row)"
                );
            }
            Err(err) => {
                tracing::error!(
                    target: "monolith.audit_break_finding",
                    tenant = %tenant_id,
                    finding = %finding_id,
                    break_seq = payload.break_seq,
                    error = %err,
                    "audit.chain.broken finding insert FAILED — finding NOT persisted"
                );
            }
        }
    }
}

/// Build a UUID by taking the first 16 bytes of a SHA-256 digest. The
/// digest is computed over a fixed-prefix + the caller-supplied
/// components so two derivations with the same inputs produce the same
/// UUID — that is what makes the FOUND-001 idempotency contract work
/// across re-fires. The version nibble is forced to `4` to keep the
/// wire shape inside the canonical "random" range and the variant bits
/// are set per RFC 4122; this is the same hand-rolled v5-style
/// derivation other adapters use when the workspace `uuid` feature
/// set does not include `v5`.
fn derive_uuid_from_components(domain: &str, components: &[&str]) -> Uuid {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update(b"\x1f"); // ASCII unit-separator — keeps domain ≠ component.
    for c in components {
        h.update(c.as_bytes());
        h.update(b"\x1f");
    }
    let digest = h.finalize();
    let mut bytes = [0_u8; 16];
    // SAFETY: SHA-256 always produces 32 bytes, so [..16] never panics.
    #[allow(clippy::indexing_slicing)]
    bytes.copy_from_slice(&digest[..16]);
    // RFC 4122: set the variant bits to `10xx` …
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    // … and the version to 4 (the workspace `uuid` features do not
    // include `v5`, so we stamp the deterministic bytes inside the v4
    // envelope — semantically still a hash-derived id).
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    Uuid::from_bytes(bytes)
}

/// Deterministic `findings.id` for a chain-break payload. Composed
/// from `(tenant_id, break_seq, expected_hash, actual_hash)` so the
/// FOUND-001 `ON CONFLICT (id) DO NOTHING` collapses every re-fire
/// observed over a single tamper window into one persisted row. We
/// deliberately exclude `detected_at` so the timestamp tick does not
/// mint a new id — that would defeat the idempotency goal.
fn derive_finding_id(tenant_id: &str, payload: &AuditChainBrokenPayload) -> Uuid {
    let break_seq = payload.break_seq.to_string();
    derive_uuid_from_components(
        "sentinelx.audit_break_finding.v1",
        &[
            tenant_id,
            &break_seq,
            &payload.expected_hash,
            &payload.actual_hash,
        ],
    )
}

/// Deterministic "Platform Internal" engagement id used when the
/// operator has not provisioned one via `audit.system_engagement_id`.
/// Per-tenant so the in-memory adapter still keys cleanly across
/// multiple tenants in test fixtures.
fn derive_system_engagement_id(tenant_id: &str) -> Uuid {
    derive_uuid_from_components("sentinelx.audit.system_engagement.v1", &[tenant_id])
}

/// Deterministic "Platform Internal" asset id used in the same role
/// as [`derive_system_engagement_id`].
fn derive_system_asset_id(tenant_id: &str) -> Uuid {
    derive_uuid_from_components("sentinelx.audit.system_asset.v1", &[tenant_id])
}

/// Project an [`AuditEnrichment`] payload into a JSON value safe to
/// stash in `FindingView::metadata`. CWE ids are emitted in their
/// canonical `CWE-<n>` form so SARIF / dashboard consumers can render
/// the metadata without re-parsing.
fn serialize_enrichment(
    e: &sx_core::reference::audit_enrichment::AuditEnrichment,
) -> serde_json::Value {
    serde_json::json!({
        "cwe": e.cwe.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "mitre_attack": e
            .mitre_attack
            .iter()
            .map(|m| {
                serde_json::json!({
                    "tactic": m.tactic,
                    "technique": m.technique,
                    "subtechnique": m.subtechnique,
                })
            })
            .collect::<Vec<_>>(),
        "nist_800_53": e
            .compliance
            .nist_800_53
            .iter()
            .map(|n| n.as_str().to_owned())
            .collect::<Vec<_>>(),
    })
}

/// Hex-friendly display helper for the hash slots. Empty strings (which
/// `broken_payload` produces for `SequenceGap` / sink errors) render as
/// the literal `<unknown>` rather than an empty pair of quotes.
fn display_hash(h: &str) -> &str {
    if h.is_empty() {
        "<unknown>"
    } else {
        h
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::Mutex;

    use sx_core::value_object::ids::TenantId;
    use uuid::Uuid;

    fn payload(tenant: TenantId, break_seq: u64) -> AuditChainBrokenPayload {
        AuditChainBrokenPayload {
            tenant_id: tenant,
            expected_hash: "ee".repeat(32),
            actual_hash: "ff".repeat(32),
            last_good_seq: break_seq.checked_sub(1),
            break_seq,
            detected_at: "2026-06-25T00:00:00Z".to_owned(),
        }
    }

    fn tenant() -> TenantId {
        Uuid::parse_str("00000000-0000-7000-8000-00000000000a")
            .unwrap()
            .into()
    }

    #[derive(Debug, Default)]
    struct StubFindings {
        rows: Mutex<HashMap<(String, String), FindingView>>,
        insert_calls: Mutex<u32>,
    }

    #[async_trait]
    impl FindingRepositoryPort for StubFindings {
        async fn list(
            &self,
            tenant_id: &str,
            _offset: u64,
            _limit: u32,
        ) -> Result<Vec<FindingView>, EngagementPortError> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .values()
                .filter(|v| v.tenant_id == tenant_id)
                .cloned()
                .collect())
        }
        async fn get(&self, tenant_id: &str, id: &str) -> Result<FindingView, EngagementPortError> {
            self.rows
                .lock()
                .unwrap()
                .get(&(tenant_id.to_owned(), id.to_owned()))
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

    #[test]
    fn build_view_carries_metadata_and_enrichment() {
        let findings: Arc<dyn FindingRepositoryPort> = Arc::new(StubFindings::default());
        let emitter = AuditBreakFindingEmitter::new(findings, None);
        let p = payload(tenant(), 7);
        let view = emitter.build_view(&p);

        assert_eq!(view.severity, "high");
        assert_eq!(view.status, "open");
        assert_eq!(view.title, "Audit chain hash mismatch detected");
        assert_eq!(view.tenant_id, tenant().to_string());

        let meta = view.metadata.expect("metadata present");
        assert_eq!(
            meta.get(META_RULE_ID).and_then(|v| v.as_str()),
            Some(AUDIT_CHAIN_BROKEN_DOTTED)
        );
        // TOP5-#3 Phase 3: check_id must be dotted-form on the wire.
        assert!(meta
            .get("check_id")
            .and_then(|v| v.as_str())
            .is_some_and(|s| s.contains('.') && s == AUDIT_CHAIN_BROKEN_DOTTED));
        // engagement_id must be present and a valid UUID per FOUND-001.
        let eng = meta
            .get(META_ENGAGEMENT_ID)
            .and_then(|v| v.as_str())
            .expect("engagement_id present");
        Uuid::parse_str(eng).expect("engagement_id parses as UUID");
        // Enrichment payload smoke check.
        let enr = meta.get("enrichment").expect("enrichment present");
        let cwe = enr
            .get("cwe")
            .and_then(|v| v.as_array())
            .expect("cwe array");
        assert!(cwe.iter().any(|v| v.as_str() == Some("CWE-117")));
        assert!(cwe.iter().any(|v| v.as_str() == Some("CWE-345")));
        let mitre = enr
            .get("mitre_attack")
            .and_then(|v| v.as_array())
            .expect("mitre array");
        assert!(mitre.iter().any(|m| {
            m.get("technique").and_then(|t| t.as_str()) == Some("T1562")
                && m.get("subtechnique").and_then(|t| t.as_str()) == Some("T1562.008")
        }));
        let nist = enr
            .get("nist_800_53")
            .and_then(|v| v.as_array())
            .expect("nist array");
        assert!(nist.iter().any(|v| v.as_str() == Some("AU-9")));
        assert_eq!(
            meta.get("confidence").and_then(serde_json::Value::as_f64),
            Some(1.0)
        );
    }

    #[tokio::test]
    async fn on_broken_persists_and_is_idempotent_on_refire() {
        let stub = Arc::new(StubFindings::default());
        let emitter = AuditBreakFindingEmitter::new(
            Arc::clone(&stub) as Arc<dyn FindingRepositoryPort>,
            None,
        );
        let p = payload(tenant(), 9);
        emitter.on_broken(&p).await;
        emitter.on_broken(&p).await;
        // Two on_broken calls, two insert calls — but the stub keys by
        // (tenant_id, id) so a deterministic finding id means only one
        // row lands in the store.
        assert_eq!(*stub.insert_calls.lock().unwrap(), 2);
        let rows: Vec<_> = stub.rows.lock().unwrap().values().cloned().collect();
        assert_eq!(
            rows.len(),
            1,
            "deterministic id keeps re-fire idempotent: {rows:?}"
        );
    }

    #[test]
    fn configured_engagement_overrides_derived() {
        let fixed = Uuid::parse_str("99999999-9999-7999-8999-999999999999").unwrap();
        let findings: Arc<dyn FindingRepositoryPort> = Arc::new(StubFindings::default());
        let emitter = AuditBreakFindingEmitter::new(findings, Some(fixed));
        assert_eq!(emitter.configured_engagement(), Some(fixed));
        let view = emitter.build_view(&payload(tenant(), 3));
        let eng = view
            .metadata
            .as_ref()
            .and_then(|m| m.get(META_ENGAGEMENT_ID))
            .and_then(|v| v.as_str())
            .map(|s| Uuid::parse_str(s).unwrap())
            .unwrap();
        assert_eq!(eng, fixed);
    }

    #[test]
    fn finding_id_is_deterministic_across_calls() {
        let findings: Arc<dyn FindingRepositoryPort> = Arc::new(StubFindings::default());
        let emitter = AuditBreakFindingEmitter::new(findings, None);
        let p = payload(tenant(), 11);
        let id1 = emitter.build_view(&p).id;
        let id2 = emitter.build_view(&p).id;
        assert_eq!(id1, id2);
        // … and changing break_seq mints a fresh id.
        let mut p2 = p;
        p2.break_seq = 12;
        let id3 = emitter.build_view(&p2).id;
        assert_ne!(id1, id3);
    }

    #[test]
    fn derived_uuid_sets_rfc4122_variant_and_version_bits() {
        let u = derive_system_engagement_id("01010101-0101-0101-0101-010101010101");
        let bytes = u.as_bytes();
        assert_eq!(
            bytes[6] & 0xF0,
            0x40,
            "version nibble must be 4: byte[6]={:02x}",
            bytes[6]
        );
        assert_eq!(
            bytes[8] & 0xC0,
            0x80,
            "variant bits must be 10xx: byte[8]={:02x}",
            bytes[8]
        );
    }
}
