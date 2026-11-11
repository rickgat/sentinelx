//! TOP5-#3 Phase 3 — FOUND-001 wire-shape regression harness.
//!
//! Every Phase-2/3 emitter (SAML XSW/XEE, RBA block, audit-chain break,
//! log-ingest rate limit) implements the FOUND-001
//! [`FindingRepositoryPort::insert`] idempotency contract via a
//! deterministic-id scheme. Each emitter has its own per-emitter
//! integration test in `services/sx-monolith/tests/*_emits_finding.rs`
//! and `crates/sx-api/tests/rate_limit_emits_finding.rs`. This file is
//! the **generic** harness the Phase-3 residual in
//! `docs/finding-enrichment.md` §5 asks for: it exercises every
//! emitter's contract under load through a single loop so a future
//! regression (a busted id derivation, a dropped mandatory field, an
//! accidental schema drift) shows up here rather than being missed
//! between per-emitter files.
//!
//! ## What the harness asserts, per emitter fixture
//!
//! For each fixture in [`FIXTURES`], the harness:
//!
//! 1. Drives the emit path `N=100` times against a fresh
//!    [`InMemoryFindings`] repo. The 100 emits represent the same
//!    logical event repeated (or perturbed only along axes the
//!    idempotency key ignores — e.g. hour-of-day for a UTC-day bucket)
//!    so an idempotency-correct emitter collapses them to one row.
//! 2. Asserts exactly 1 row landed in the tenant.
//! 3. Asserts every FOUND-001 mandatory wire-shape field is present
//!    and non-empty on the persisted view:
//!    - `id` (non-empty and stable across re-emits — the single-row
//!      count check pins this).
//!    - `tenant_id` (non-empty).
//!    - `severity` from the accepted set.
//!    - `status` from the accepted set.
//!    - `title` (non-empty).
//!    - `description` (non-empty).
//!    - `first_seen` / `last_seen` (non-empty).
//!    - `metadata.engagement_id` (non-empty).
//!    - `metadata.rule_id` (non-empty, matches the fixture's expected
//!      canonical value).
//! 4. Enrichment fields (`cvss`, `cve_id`, `metadata.cwe`,
//!    `metadata.mitre_attack`, `metadata.compliance`,
//!    `metadata.confidence`) are optional per emitter — the harness
//!    only asserts internal consistency: e.g. if `confidence` is
//!    present it must be finite in `0.0..=1.0`.
//!
//! A separate test drives the same fixtures under **concurrent load**
//! (4 tokio tasks × 25 emits each) to catch any race the sequential
//! test would miss.
//!
//! ## Why the emit path is mirrored, not called directly
//!
//! The monolith crate ships only a binary target (`src/main.rs`), so
//! the private `pub(crate)` observer types (`MonolithSamlAttackObserver`,
//! `RbaAdapter::maybe_emit_block_finding`, `AuditBreakFindingEmitter`)
//! are not reachable from an integration test. Each fixture inlines a
//! **near-copy** of the observer's `build_finding` path — the same
//! convention the sibling per-emitter tests (`saml_attack_emits_finding.rs`,
//! `rba_block_emits_finding.rs`, `audit_chain_break_emits_finding.rs`)
//! already use. Where possible the harness reads the same enrichment
//! table (`sx_core::reference::*_enrichment`) or public helper
//! (`sx_rba::finding::*`, `sx_api::controller::log_ingest::__test_*`)
//! the production emitter uses, so a typo in the curated payload trips
//! both this harness and the per-emitter test.
//!
//! ## Dotted `check_id` namespace (TOP5-#3 Phase 3)
//!
//! Phase 3 landed in the 2026-07-04 sweep: every FOUND-001 emitter
//! now emits the canonical dotted form (`SAML.XSW`, `SAML.XEE`,
//! `RBA.HIGH_RISK_BLOCK`, `AUDIT.CHAIN.BROKEN`,
//! `MED001.RATE_LIMITER.REJECT`). The harness asserts every
//! `metadata.rule_id` equals its fixture's expected dotted string AND
//! `contains('.')` — regressing an emitter back to the colon form is
//! now a hard failure at CI. Legacy colon strings remain resolvable
//! via the receive-side alias map in
//! `sx-core::reference::*_enrichment` so external SIEM consumers
//! pinned to old strings do not break.
//!
//! SAML id derivation deliberately keeps the legacy colon form
//! (`kind.rule_id()`) so a finding minted before Phase 3 keeps the
//! same `(tenant_id, id)` idempotency key across the migration.
//! Only `metadata.rule_id` on emit is dotted.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::too_many_lines)]
// Integration-test harness: a wire-shape mismatch is the exact failure
// signal we want surfaced. Panicking on the offending fixture beats any
// `Result` propagation, which would obscure which emitter tripped.
#![allow(clippy::panic)]
// The 900-sec rate-limit window aligns via `1_750_000_000 / 900 * 900`;
// the integer division is intentional (window-start rounding).
#![allow(clippy::integer_division)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use sx_api::controller::log_ingest::{
    __test_emit_rate_limit_finding, __test_ingest_endpoint_label,
};
use sx_api::port::{EngagementPortError, FindingRepositoryPort, LogRateLimitDecision};
use sx_api::view::finding_view::FindingView;
use sx_core::reference::saml_attack_enrichment::{
    saml_attack_enrichment, SamlAttackEnrichment, SamlAttackSeverity,
};
use sx_iam::service::saml::SamlAttackKind;

// ---------------------------------------------------------------------------
// In-memory `FindingRepositoryPort` — a faithful mirror of the monolith's
// `InMemoryFindings` adapter (`services/sx-monolith/src/adapters/repository.rs`).
// Last-write-wins on `(tenant_id, id)`; insert never errors. This is the
// same shape every sibling per-emitter test uses.
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct InMemoryFindings {
    rows: Mutex<HashMap<(String, String), FindingView>>,
    insert_calls: Mutex<u32>,
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

impl InMemoryFindings {
    fn distinct_row_count(&self, tenant_id: &str) -> usize {
        self.rows
            .lock()
            .unwrap()
            .keys()
            .filter(|(t, _)| t == tenant_id)
            .count()
    }

    fn insert_calls(&self) -> u32 {
        *self.insert_calls.lock().unwrap()
    }
}

// ---------------------------------------------------------------------------
// Fixture surface — one entry per FOUND-001 emitter under test.
//
// `EmitFn` produces the FindingView for iteration `i`. Fixtures perturb
// `i` only along axes the emitter's idempotency key IGNORES so the
// harness can assert single-row cardinality. E.g. the SAML fixture bumps
// `detected_at_unix` by 60s per iteration (still same UTC day), so the
// `(tenant, kind, idp, day)` bucket does not roll over; the rate-limit
// fixture bumps `now_unix` by 1s (still same 15-min window).
// ---------------------------------------------------------------------------

const TENANT_A: &str = "01010101-0101-0101-0101-010101010101";

struct Fixture {
    /// Human-readable label — printed on assertion failure so the
    /// operator can jump straight to the offending emitter.
    name: &'static str,
    /// Canonical `metadata.rule_id` string the emitter is expected to
    /// stamp. Auditor / SIEM rules pin against these.
    expected_rule_id: &'static str,
    /// Accepted `severity` value the emitter is expected to stamp.
    expected_severity: &'static str,
    /// Build the `FindingView` for iteration `i` (`0..N`). The
    /// emitter's idempotency key must NOT vary with `i`.
    build: fn(iteration: usize) -> FindingView,
}

/// The wire severities the FOUND-001 contract accepts. Kept in one
/// place so a future emitter that introduces a novel severity trips a
/// review here rather than silently passing.
const ACCEPTED_SEVERITIES: &[&str] = &["info", "low", "medium", "high", "critical"];

/// The wire statuses the FOUND-001 contract accepts for a *freshly
/// emitted* finding. Emitters open the row; the human-facing
/// `PATCH /v1/findings/{id}` surface transitions it later.
const ACCEPTED_STATUSES: &[&str] = &["open", "triaged", "accepted", "closed"];

// ---------------------------------------------------------------------------
// Fixture #1 — SAML XSW (XML Signature Wrapping) attack detection.
//
// Mirrors `services/sx-monolith/src/adapters/saml_attack_observer.rs`
// build path byte-for-byte. Perturbation axis: `detected_at_unix` bumped
// by 60s per iteration; still same UTC day → same `(tenant, kind, idp,
// day)` bucket → same finding id.
// ---------------------------------------------------------------------------

const SAML_FINDING_NAMESPACE: &str = "sentinelx:saml-attack:v1";
const SAML_SYSTEM_ENGAGEMENT: &str = "11111111-1111-1111-1111-111111111111";
const SAML_SP_ASSET: &str = "22222222-2222-2222-2222-222222222222";
const SAML_IDP_ISSUER: &str = "https://idp.example.com";
/// 2026-06-25T00:00:00Z — pins the day bucket.
const SAML_ANCHOR_UNIX: i64 = 1_782_604_800;

fn saml_day_bucket_utc(unix_secs: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix_secs).map_or_else(
        |_| "1970-01-01".into(),
        |t| format!("{:04}-{:02}-{:02}", t.year(), u8::from(t.month()), t.day()),
    )
}

fn saml_unix_to_rfc3339(unix_secs: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix_secs).map_or_else(
        |_| "1970-01-01T00:00:00Z".into(),
        |t| {
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                t.year(),
                u8::from(t.month()),
                t.day(),
                t.hour(),
                t.minute(),
                t.second(),
            )
        },
    )
}

fn saml_finding_id(kind: SamlAttackKind, detected_at_unix: i64) -> String {
    let day = saml_day_bucket_utc(detected_at_unix);
    let tuple = format!(
        "{SAML_FINDING_NAMESPACE}|{TENANT_A}|{}|{SAML_IDP_ISSUER}|{day}",
        kind.rule_id()
    );
    let digest: [u8; 32] = Sha256::digest(tuple.as_bytes()).into();
    format!(
        "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]),
        u16::from_be_bytes([digest[4], digest[5]]),
        u16::from_be_bytes([digest[6], digest[7]]),
        u16::from_be_bytes([digest[8], digest[9]]),
        u64::from_be_bytes([
            0, 0, digest[10], digest[11], digest[12], digest[13], digest[14], digest[15],
        ]),
    )
}

fn saml_build(kind: SamlAttackKind, iteration: usize) -> FindingView {
    let enrichment = saml_attack_enrichment(kind.rule_id())
        .expect("enrichment row must exist for every SamlAttackKind");
    let SamlAttackEnrichment {
        cwe,
        mitre_attack,
        compliance,
        severity,
        title,
        description,
    } = enrichment;
    // Perturbation axis: bump by up to 99 minutes across 100 iters.
    // Still same UTC day so the idempotency bucket does not roll over.
    let detected_at_unix = SAML_ANCHOR_UNIX + (iteration as i64 * 60);
    let id = saml_finding_id(kind, detected_at_unix);
    let iso = saml_unix_to_rfc3339(detected_at_unix);
    let metadata = serde_json::json!({
        "engagement_id": SAML_SYSTEM_ENGAGEMENT,
        "rule_id": kind.rule_id_dotted(),
        "confidence": 1.0,
        "emitter": "saml_attack_observer",
        "idp_issuer": SAML_IDP_ISSUER,
        "cwe": cwe.iter().map(|c| format!("CWE-{}", c.as_u32())).collect::<Vec<_>>(),
        "mitre_attack": mitre_attack
            .iter()
            .map(|t| {
                let mut o = serde_json::json!({
                    "tactic": t.tactic,
                    "technique": t.technique,
                });
                if let (Some(sub), Some(map)) = (t.subtechnique.as_ref(), o.as_object_mut()) {
                    map.insert(
                        "subtechnique".to_owned(),
                        serde_json::Value::String(sub.clone()),
                    );
                }
                o
            })
            .collect::<Vec<_>>(),
        "compliance": {
            "nist_800_53": compliance
                .nist_800_53
                .iter()
                .map(|c| c.as_str().to_owned())
                .collect::<Vec<_>>(),
        },
    });
    FindingView {
        id,
        tenant_id: TENANT_A.into(),
        asset_id: SAML_SP_ASSET.into(),
        severity: match severity {
            SamlAttackSeverity::High => "high".into(),
            SamlAttackSeverity::Medium => "medium".into(),
        },
        status: "open".into(),
        title: title.into(),
        description: description.into(),
        cvss: None,
        cve_id: None,
        first_seen: iso.clone(),
        last_seen: iso,
        metadata: Some(metadata),
    }
}

fn saml_xsw_build(i: usize) -> FindingView {
    saml_build(SamlAttackKind::Xsw, i)
}

fn saml_xee_build(i: usize) -> FindingView {
    saml_build(SamlAttackKind::Xee, i)
}

// ---------------------------------------------------------------------------
// Fixture #2 — RBA (Risk-Based Authentication) high-risk Block.
//
// Mirrors `RbaAdapter::maybe_emit_block_finding` build path. Perturbation
// axis: bump the decision score across iterations; the id derivation
// key is `(tenant, identity_key, day)` — score does not participate.
// ---------------------------------------------------------------------------

const RBA_SYSTEM_ENGAGEMENT: &str = "e0e0e0e0-0000-0000-0000-000000000001";
const RBA_SYSTEM_ASSET: &str = "facecafe-0000-0000-0000-000000000001";
const RBA_USER: &str = "a0a0a0a0-0000-0000-0000-000000000001";
/// 2026-06-25 UTC — pins the day bucket. RFC 3339 wire form.
const RBA_DECIDED_AT_ISO: &str = "2026-06-25T04:00:00Z";
const RBA_DECIDED_AT_DATE: &str = "2026-06-25";

fn rba_synthetic_finding_id(identity_key: &str, day: &str) -> String {
    let mut h = Sha256::new();
    h.update(TENANT_A.as_bytes());
    h.update(b"|");
    h.update(identity_key.as_bytes());
    h.update(b"|");
    h.update(day.as_bytes());
    let digest = h.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
}

fn rba_build(iteration: usize) -> FindingView {
    // Perturbation axis: score walks 76..=99, still same identity_key
    // + day. The idempotency key is `(tenant, identity_key, day)` so
    // every iteration collapses to the same id.
    let score = 76_i32 + (iteration as i32 % 24);
    let confidence = f64::from(score) / 100.0;
    let id = rba_synthetic_finding_id(RBA_USER, RBA_DECIDED_AT_DATE);
    let metadata = serde_json::json!({
        "engagement_id": RBA_SYSTEM_ENGAGEMENT,
        "rule_id": sx_rba::finding::RBA_HIGH_RISK_BLOCK_DOTTED,
        "check_id": sx_rba::finding::RBA_HIGH_RISK_BLOCK_DOTTED,
        "confidence": confidence,
        "rba": {
            "score": score,
            "threshold": 75,
            "tenant_id": TENANT_A,
            "user_id": RBA_USER,
            "reason": "burst from unknown country",
        },
    });
    FindingView {
        id,
        tenant_id: TENANT_A.into(),
        asset_id: RBA_SYSTEM_ASSET.into(),
        severity: "critical".into(),
        status: "open".into(),
        title: "Risk-based authentication blocked sign-in".into(),
        description: format!(
            "Risk-based authentication blocked sign-in for tenant {TENANT_A} user {RBA_USER}. \
             Composite score: {score}/100 (threshold: 75).",
        ),
        cvss: None,
        cve_id: None,
        first_seen: RBA_DECIDED_AT_ISO.into(),
        last_seen: RBA_DECIDED_AT_ISO.into(),
        metadata: Some(metadata),
    }
}

// ---------------------------------------------------------------------------
// Fixture #3 — Audit-chain break.
//
// Mirrors `AuditBreakFindingEmitter::build_view`. Perturbation axis:
// the `break_seq` is fixed (that's the tamper coordinate); iteration
// only changes the `detected_at` clock string. The id derivation reads
// `(tenant_id, break_seq, expected_hash, actual_hash)` — clock is
// deliberately not part of the key so re-fires collapse.
// ---------------------------------------------------------------------------

const AUDIT_BREAK_SEQ: u64 = 3;
const AUDIT_LAST_GOOD_SEQ: u64 = 2;
const AUDIT_EXPECTED_HASH: &str =
    "aa11bb22cc33dd44ee55ff6600778899aa11bb22cc33dd44ee55ff6600778899";
const AUDIT_ACTUAL_HASH: &str = "99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbb00";

fn audit_derive_uuid(domain: &str, components: &[&str]) -> String {
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
    uuid::Uuid::from_bytes(bytes).to_string()
}

fn audit_build(iteration: usize) -> FindingView {
    let enrichment = sx_core::reference::audit_enrichment::audit_enrichment(
        sx_core::reference::audit_enrichment::AUDIT_CHAIN_BREAK,
    )
    .expect("audit chain-break enrichment row must exist");
    let break_seq = AUDIT_BREAK_SEQ.to_string();
    let finding_id = audit_derive_uuid(
        "sentinelx.audit_break_finding.v1",
        &[TENANT_A, &break_seq, AUDIT_EXPECTED_HASH, AUDIT_ACTUAL_HASH],
    );
    let engagement_id = audit_derive_uuid("sentinelx.audit.system_engagement.v1", &[TENANT_A]);
    let asset_id = audit_derive_uuid("sentinelx.audit.system_asset.v1", &[TENANT_A]);
    // Perturbation axis: detected_at clock. Not part of the id key, so
    // re-fires still collapse. Iteration walks second-of-minute.
    let detected_at = format!("2026-06-25T00:00:{:02}Z", iteration % 60);
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
        "engagement_id": engagement_id,
        "rule_id": sx_core::reference::audit_enrichment::AUDIT_CHAIN_BROKEN_DOTTED,
        "check_id": sx_core::reference::audit_enrichment::AUDIT_CHAIN_BROKEN_DOTTED,
        "break_seq": AUDIT_BREAK_SEQ,
        "last_good_seq": AUDIT_LAST_GOOD_SEQ,
        "confidence": 1.0_f64,
        "enrichment": {
            "cwe": cwe,
            "mitre_attack": mitre,
            "nist_800_53": nist,
        },
    });
    FindingView {
        id: finding_id,
        tenant_id: TENANT_A.into(),
        asset_id,
        severity: "high".into(),
        status: "open".into(),
        title: "Audit chain hash mismatch detected".into(),
        description: format!("chain divergence at seq {AUDIT_BREAK_SEQ}"),
        cvss: None,
        cve_id: None,
        first_seen: detected_at.clone(),
        last_seen: detected_at,
        metadata: Some(metadata),
    }
}

// ---------------------------------------------------------------------------
// Fixture #4 — Log-ingest rate-limit rejection.
//
// Uses the public `__test_emit_rate_limit_finding` seam so the harness
// exercises the exact production build path (the controller uses the
// same underlying helper). Perturbation axis: bump `now_unix` by 1s per
// iteration — still inside the same 15-min window, so the id key
// `(tenant, endpoint, window)` stays constant.
// ---------------------------------------------------------------------------

/// Aligned to a 15-minute window-start so 100 sequential 1-second bumps
/// stay inside the same window bucket.
const RATE_LIMIT_ANCHOR_UNIX: u64 = 1_750_000_000_u64 / 900 * 900;

const fn throttled_decision() -> LogRateLimitDecision {
    LogRateLimitDecision {
        allowed: false,
        limit: 200,
        remaining: 0,
        reset_at_unix_secs: RATE_LIMIT_ANCHOR_UNIX + 900,
        retry_after_secs: 1,
    }
}

fn rate_limit_build(iteration: usize) -> FindingView {
    let endpoint = __test_ingest_endpoint_label();
    let decision = throttled_decision();
    __test_emit_rate_limit_finding(
        TENANT_A,
        endpoint,
        &decision,
        RATE_LIMIT_ANCHOR_UNIX + iteration as u64,
    )
}

// ---------------------------------------------------------------------------
// The fixture registry — every currently-shipping FOUND-001 emitter.
// New emitters land alongside a new entry here.
// ---------------------------------------------------------------------------

const FIXTURES: &[Fixture] = &[
    Fixture {
        name: "saml_xsw",
        expected_rule_id: "SAML.XSW",
        expected_severity: "high",
        build: saml_xsw_build,
    },
    Fixture {
        name: "saml_xee",
        expected_rule_id: "SAML.XEE",
        expected_severity: "high",
        build: saml_xee_build,
    },
    Fixture {
        name: "rba_high_risk_block",
        expected_rule_id: "RBA.HIGH_RISK_BLOCK",
        expected_severity: "critical",
        build: rba_build,
    },
    Fixture {
        name: "audit_chain_break",
        expected_rule_id: "AUDIT.CHAIN.BROKEN",
        expected_severity: "high",
        build: audit_build,
    },
    Fixture {
        name: "log_ingest_rate_limit",
        expected_rule_id: "MED001.RATE_LIMITER.REJECT",
        expected_severity: "medium",
        build: rate_limit_build,
    },
];

// ---------------------------------------------------------------------------
// Wire-shape assertion — the single source of truth for what a
// FOUND-001-compliant FindingView must carry. Callers pass the
// persisted view + a label; on any failure the panic message names the
// fixture so the operator can jump straight to the offending emitter.
// ---------------------------------------------------------------------------

fn assert_found_001_wire_shape(fixture: &Fixture, view: &FindingView) {
    let ctx = fixture.name;

    // Mandatory identity fields.
    assert!(!view.id.is_empty(), "[{ctx}] view.id must be non-empty");
    assert!(
        !view.tenant_id.is_empty(),
        "[{ctx}] view.tenant_id must be non-empty"
    );

    // Severity from the accepted set.
    assert!(
        ACCEPTED_SEVERITIES.contains(&view.severity.as_str()),
        "[{ctx}] view.severity {:?} not in accepted set {:?}",
        view.severity,
        ACCEPTED_SEVERITIES,
    );
    assert_eq!(
        view.severity, fixture.expected_severity,
        "[{ctx}] severity drift: got {:?}, expected {:?}",
        view.severity, fixture.expected_severity,
    );

    // Status from the accepted set. Freshly-emitted findings are
    // conventionally `"open"` — the harness enforces membership only,
    // not equality, so an emitter that chooses to open at `"triaged"`
    // (auto-triage flow) still passes.
    assert!(
        ACCEPTED_STATUSES.contains(&view.status.as_str()),
        "[{ctx}] view.status {:?} not in accepted set {:?}",
        view.status,
        ACCEPTED_STATUSES,
    );

    // Human-readable descriptors.
    assert!(
        !view.title.is_empty(),
        "[{ctx}] view.title must be non-empty"
    );
    assert!(
        !view.description.is_empty(),
        "[{ctx}] view.description must be non-empty"
    );

    // Discovery timestamps.
    assert!(
        !view.first_seen.is_empty(),
        "[{ctx}] view.first_seen must be non-empty"
    );
    assert!(
        !view.last_seen.is_empty(),
        "[{ctx}] view.last_seen must be non-empty"
    );

    // FOUND-001 metadata envelope.
    let metadata = view
        .metadata
        .as_ref()
        .unwrap_or_else(|| panic!("[{ctx}] FOUND-001 requires metadata be present"));
    let meta_obj = metadata
        .as_object()
        .unwrap_or_else(|| panic!("[{ctx}] metadata must be a JSON object, got {metadata:?}"));

    let eng_id = meta_obj
        .get("engagement_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("[{ctx}] metadata.engagement_id must be a string"));
    assert!(
        !eng_id.is_empty(),
        "[{ctx}] metadata.engagement_id must be non-empty"
    );

    let rule_id = meta_obj
        .get("rule_id")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("[{ctx}] metadata.rule_id must be a string"));
    assert!(
        !rule_id.is_empty(),
        "[{ctx}] metadata.rule_id must be non-empty"
    );
    assert_eq!(
        rule_id, fixture.expected_rule_id,
        "[{ctx}] rule_id drift: got {rule_id:?}, expected {:?}",
        fixture.expected_rule_id,
    );

    // TOP5-#3 Phase 3: every FOUND-001 emitter now emits the dotted
    // canonical form. A regression back to the colon shape fails here.
    assert!(
        rule_id.contains('.'),
        "[{ctx}] Phase-3 rule_id must be dotted-form; got {rule_id:?}"
    );

    // `check_id` is an optional twin — but if present it MUST match
    // `rule_id` (the two are aliases in every current emitter).
    if let Some(check_id) = meta_obj.get("check_id").and_then(serde_json::Value::as_str) {
        assert_eq!(
            check_id, rule_id,
            "[{ctx}] metadata.check_id {check_id:?} must match metadata.rule_id {rule_id:?}",
        );
    }

    // Enrichment consistency (optional fields — asserted only when
    // present). Emitters that skip enrichment are still FOUND-001
    // compliant.
    if let Some(conf) = meta_obj
        .get("confidence")
        .and_then(serde_json::Value::as_f64)
    {
        assert!(
            conf.is_finite() && (0.0..=1.0).contains(&conf),
            "[{ctx}] metadata.confidence must be finite in 0.0..=1.0, got {conf}",
        );
    }
    if let Some(cvss_score) = view.cvss {
        assert!(
            cvss_score.is_finite() && (0.0..=10.0).contains(&cvss_score),
            "[{ctx}] cvss must be finite in 0.0..=10.0, got {cvss_score}",
        );
    }
}

// ---------------------------------------------------------------------------
// Test #1 — sequential load. For each fixture, drive N=100 emits into a
// fresh repo, assert single-row collapse, assert wire-shape.
// ---------------------------------------------------------------------------

const HARNESS_ITERATIONS: usize = 100;

/// Sequential harness: for each FOUND-001 emitter fixture, drive 100
/// repeated emits (perturbed only along axes the idempotency key
/// ignores) through the `FindingRepositoryPort::insert` contract and
/// assert exactly one row lands with a valid wire shape.
#[tokio::test]
async fn found_001_sequential_load_across_all_emitters() {
    for fixture in FIXTURES {
        let repo = InMemoryFindings::default();

        for i in 0..HARNESS_ITERATIONS {
            let view = (fixture.build)(i);
            repo.insert(view).await.unwrap_or_else(|e| {
                panic!(
                    "[{name}] insert failed on iteration {i}: {e}",
                    name = fixture.name,
                );
            });
        }

        let insert_calls = repo.insert_calls();
        assert_eq!(
            insert_calls,
            HARNESS_ITERATIONS as u32,
            "[{name}] insert_calls tally mismatch (got {insert_calls})",
            name = fixture.name,
        );

        // FOUND-001 idempotency: 100 emits collapse to exactly one row.
        let rows = repo.list(TENANT_A, 0, 500).await.expect("list ok");
        assert_eq!(
            rows.len(),
            1,
            "[{name}] FOUND-001 idempotency broken: {n} emits produced {got} rows (expected 1). \
             Rows: {rows:#?}",
            name = fixture.name,
            n = HARNESS_ITERATIONS,
            got = rows.len(),
        );
        assert_eq!(
            repo.distinct_row_count(TENANT_A),
            1,
            "[{name}] distinct_row_count sanity mismatch",
            name = fixture.name,
        );

        // Wire-shape gate on the surviving row.
        assert_found_001_wire_shape(fixture, &rows[0]);
    }
}

// ---------------------------------------------------------------------------
// Test #2 — concurrent load. 4 tokio tasks × 25 emits each = 100 emits
// per fixture, driven in parallel through the same repo. Catches races
// the sequential test cannot (e.g. non-deterministic id derivation
// silently landing multiple rows under a lock-free adapter).
// ---------------------------------------------------------------------------

const CONCURRENT_TASKS: usize = 4;
const PER_TASK_ITERATIONS: usize = 25;

/// Concurrent harness: 4 tokio tasks × 25 emits per fixture, all
/// funneled through one `FindingRepositoryPort`. A racy id derivation
/// (e.g. `Utc::now()` sneaking into a build path) would land multiple
/// rows here even though the sequential test still passes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn found_001_concurrent_load_across_all_emitters() {
    for fixture in FIXTURES {
        let repo = Arc::new(InMemoryFindings::default());

        let mut handles = Vec::with_capacity(CONCURRENT_TASKS);
        for task_idx in 0..CONCURRENT_TASKS {
            let repo_c = Arc::clone(&repo);
            let build = fixture.build;
            let name = fixture.name;
            let handle = tokio::spawn(async move {
                for j in 0..PER_TASK_ITERATIONS {
                    let iter = task_idx * PER_TASK_ITERATIONS + j;
                    let view = build(iter);
                    repo_c.insert(view).await.unwrap_or_else(|e| {
                        panic!("[{name}] concurrent insert failed at iter {iter}: {e}");
                    });
                }
            });
            handles.push(handle);
        }
        for h in handles {
            h.await.expect("spawned harness task joins cleanly");
        }

        let insert_calls = repo.insert_calls();
        let expected_calls = (CONCURRENT_TASKS * PER_TASK_ITERATIONS) as u32;
        assert_eq!(
            insert_calls, expected_calls,
            "[{name}] concurrent insert_calls tally mismatch (got {insert_calls}, want {expected_calls})",
            name = fixture.name,
        );

        let rows = repo.list(TENANT_A, 0, 500).await.expect("list ok");
        assert_eq!(
            rows.len(),
            1,
            "[{name}] concurrent FOUND-001 idempotency broken: {n} concurrent emits produced {got} rows. \
             Rows: {rows:#?}",
            name = fixture.name,
            n = CONCURRENT_TASKS * PER_TASK_ITERATIONS,
            got = rows.len(),
        );

        assert_found_001_wire_shape(fixture, &rows[0]);
    }
}

// ---------------------------------------------------------------------------
// Test #3 — cross-fixture disambiguation. When all fixtures share the
// same tenant but each emits its own logical event, the repo must end
// up with exactly `FIXTURES.len()` distinct rows (one per emitter). If
// two emitters accidentally hash to the same id, one silently
// overwrites the other and the audit trail loses evidence.
// ---------------------------------------------------------------------------

/// Cross-fixture disambiguation: drive one emit per fixture into a
/// SHARED repo and assert distinct-row cardinality. Guards against an
/// id collision where a hash namespace bump silently loses evidence.
#[tokio::test]
async fn found_001_fixtures_produce_distinct_ids() {
    let repo = InMemoryFindings::default();
    let mut minted_ids: Vec<(String, String)> = Vec::with_capacity(FIXTURES.len());
    for fixture in FIXTURES {
        let view = (fixture.build)(0);
        minted_ids.push((fixture.name.to_owned(), view.id.clone()));
        repo.insert(view).await.expect("insert ok");
    }

    let rows = repo.list(TENANT_A, 0, 500).await.expect("list ok");
    assert_eq!(
        rows.len(),
        FIXTURES.len(),
        "cross-fixture id collision: expected {expected} distinct rows, got {got}. \
         Minted ids: {minted_ids:#?}",
        expected = FIXTURES.len(),
        got = rows.len(),
    );

    // And: each surviving row still passes the wire-shape gate.
    for fixture in FIXTURES {
        let target_id = minted_ids
            .iter()
            .find(|(n, _)| n == fixture.name)
            .map(|(_, id)| id.clone())
            .expect("fixture id recorded");
        let landed = rows.iter().find(|r| r.id == target_id).unwrap_or_else(|| {
            panic!("[{name}] row missing from shared repo", name = fixture.name)
        });
        assert_found_001_wire_shape(fixture, landed);
    }
}
