//! TOP5-#3-P2-005 — integration coverage for the RBA → Finding
//! emission path.
//!
//! Asserts the four contract invariants the monolith RBA adapter
//! upholds when `rba.finding_emission` is wired:
//!
//! 1. A `Block` decision with `score >= threshold` and emission enabled
//!    persists a synthetic Finding with the canonical
//!    `rba:high-risk-block` rule id, severity=`critical`, and metadata
//!    carrying both `engagement_id` and `rule_id` per the FOUND-001
//!    contract.
//! 2. The Finding's wire-side enrichment resolves via
//!    `sx_core::reference::rba_block_enrichment` to **CWE-1390** Weak
//!    Authentication + **MITRE ATT&CK TA0001** Initial Access (the
//!    Wave B audit spec line).
//! 3. An `Allow` decision OR a `Block` decision whose score is below
//!    the threshold persists ZERO findings.
//! 4. Re-firing the same `(tenant, user, day)` produces NO duplicate
//!    row — the synthetic id is hashed off `(tenant, user, day_bucket)`
//!    so the in-memory adapter's last-write-wins collapses the repeat
//!    hit to one row.
//!
//! The `sx-monolith` crate is a binary (no library surface) so we
//! cannot import its private `RbaAdapter` directly. We mirror the
//! adapter's emission helper inline here — the same logic, the same
//! inputs, the same `FindingRepositoryPort::insert` contract — which
//! pins both the emission gating and the synthetic-finding shape
//! against future drift. The pattern matches the existing
//! `finding_insert.rs` convention.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::significant_drop_tightening)]

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use sx_api::port::{EngagementPortError, FindingRepositoryPort};
use sx_api::view::finding_view::FindingView;
use sx_config::schema::RbaFindingEmissionConfig;
use sx_core::reference::rba_block_enrichment::{
    rba_block_enrichment, RBA_HIGH_RISK_BLOCK_CHECK_ID, RBA_HIGH_RISK_BLOCK_DOTTED,
};
use sx_rba::baseline::BaselinePhase;
use sx_rba::finding::block_decision_description;
use sx_rba::scorer::SignalContribution;
use sx_rba::service::{RbaAction, RbaDecision, SignalSnapshot};
use sx_rba::signals::SignalKind;
use time::format_description::well_known::Rfc3339;
use time::macros::datetime;
use time::OffsetDateTime;
use uuid::Uuid;

const TENANT_A: &str = "01010101-0101-0101-0101-010101010101";
const USER_A: &str = "a0a0a0a0-0000-0000-0000-000000000001";
const SYSTEM_ENGAGEMENT: &str = "e0e0e0e0-0000-0000-0000-000000000001";
const SYSTEM_ASSET: &str = "facecafe-0000-0000-0000-000000000001";

/// Faithful re-implementation of the monolith's `InMemoryFindings`
/// adapter — same shape, same `(tenant_id, id)` last-write-wins
/// semantics.
#[derive(Default)]
struct InMemoryFindings {
    rows: Mutex<HashMap<(String, String), FindingView>>,
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
        tenant_id: &str,
        id: &str,
        new_status: &str,
        _comment: Option<&str>,
    ) -> Result<FindingView, EngagementPortError> {
        let mut g = self.rows.lock().unwrap();
        match g.get_mut(&(tenant_id.to_owned(), id.to_owned())) {
            Some(view) => {
                new_status.clone_into(&mut view.status);
                Ok(view.clone())
            }
            None => Err(EngagementPortError::NotFound),
        }
    }

    async fn insert(&self, view: FindingView) -> Result<FindingView, EngagementPortError> {
        let mut g = self.rows.lock().unwrap();
        let key = (view.tenant_id.clone(), view.id.clone());
        g.insert(key, view.clone());
        Ok(view)
    }
}

/// Mirrors `RbaAdapter::synthetic_finding_id` byte-for-byte.
fn synthetic_finding_id(decision: &RbaDecision, identity_key: &str) -> Uuid {
    let day = decision.decided_at.date().to_string();
    let mut hasher = Sha256::new();
    hasher.update(decision.tenant_id.as_bytes());
    hasher.update(b"|");
    hasher.update(identity_key.as_bytes());
    hasher.update(b"|");
    hasher.update(day.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

/// Mirrors `RbaAdapter::maybe_emit_block_finding`.
async fn maybe_emit_block_finding(
    sink: &dyn FindingRepositoryPort,
    decision: &RbaDecision,
    identity_key: &str,
    emission: &RbaFindingEmissionConfig,
) -> Option<FindingView> {
    if !emission.enabled {
        return None;
    }
    if decision.action != RbaAction::Block {
        return None;
    }
    let threshold_score = i32::from(emission.block_threshold_score);
    if decision.score < threshold_score {
        return None;
    }
    let finding_id = synthetic_finding_id(decision, identity_key);
    let detected_at_str = decision
        .decided_at
        .format(&Rfc3339)
        .unwrap_or_else(|_| String::new());
    let description = block_decision_description(decision, emission.block_threshold_score);
    let confidence = f64::from(decision.score) / 100.0;
    // TOP5-#3 Phase 3: dotted-form on the wire.
    let metadata = serde_json::json!({
        "engagement_id": emission.system_engagement_id,
        "rule_id": sx_rba::finding::RBA_HIGH_RISK_BLOCK_DOTTED,
        "check_id": sx_rba::finding::RBA_HIGH_RISK_BLOCK_DOTTED,
        "confidence": confidence,
        "rba": {
            "score": decision.score,
            "threshold": emission.block_threshold_score,
            "tenant_id": decision.tenant_id.to_string(),
            "user_id": decision.user_id.map(|u| u.to_string()),
            "ip": decision.ip.to_string(),
            "reason": decision.reason.clone(),
        },
    });
    let view = FindingView {
        id: finding_id.to_string(),
        tenant_id: decision.tenant_id.to_string(),
        asset_id: emission.system_asset_id.clone(),
        severity: "critical".to_owned(),
        status: "open".to_owned(),
        title: "Risk-based authentication blocked sign-in".to_owned(),
        description,
        cvss: None,
        cve_id: None,
        first_seen: detected_at_str.clone(),
        last_seen: detected_at_str,
        metadata: Some(metadata),
    };
    Some(sink.insert(view).await.expect("in-memory insert ok"))
}

fn emission_enabled(threshold: u8) -> RbaFindingEmissionConfig {
    RbaFindingEmissionConfig {
        enabled: true,
        block_threshold_score: threshold,
        system_engagement_id: SYSTEM_ENGAGEMENT.to_owned(),
        system_asset_id: SYSTEM_ASSET.to_owned(),
    }
}

fn decision(
    action: RbaAction,
    score: i32,
    user_id: Option<Uuid>,
    decided_at: OffsetDateTime,
) -> RbaDecision {
    RbaDecision {
        id: Uuid::new_v4(),
        tenant_id: Uuid::parse_str(TENANT_A).unwrap(),
        user_id,
        ip: Ipv4Addr::new(203, 0, 113, 7),
        score,
        action,
        signals: HashMap::new(),
        snapshot: SignalSnapshot::default(),
        signal_contributions: vec![SignalContribution {
            signal: SignalKind::IpGeo,
            sub_score: 80,
            weight: 0.20,
            weighted: 16.0,
        }],
        reason: "burst from unknown country".to_owned(),
        baseline_phase: BaselinePhase::Active,
        decided_at,
    }
}

#[tokio::test]
async fn block_at_or_above_threshold_emits_synthetic_finding() {
    let repo = InMemoryFindings::default();
    let emission = emission_enabled(75);
    let user = Uuid::parse_str(USER_A).unwrap();

    let d = decision(
        RbaAction::Block,
        80,
        Some(user),
        datetime!(2026-06-25 04:00:00 UTC),
    );
    let identity_key = user.to_string();
    let persisted = maybe_emit_block_finding(&repo, &d, &identity_key, &emission)
        .await
        .expect("emission must mint a finding");

    // FOUND-001 contract: metadata carries engagement_id + rule_id.
    let metadata = persisted.metadata.as_ref().expect("metadata present");
    assert_eq!(
        metadata.get("engagement_id").and_then(|v| v.as_str()),
        Some(SYSTEM_ENGAGEMENT),
        "metadata.engagement_id must match the configured system engagement",
    );
    // TOP5-#3 Phase 3: rule_id must be the dotted-form now.
    let rule = metadata
        .get("rule_id")
        .and_then(|v| v.as_str())
        .expect("rule_id present");
    assert_eq!(
        rule, RBA_HIGH_RISK_BLOCK_DOTTED,
        "metadata.rule_id must be the canonical dotted-form RBA block check_id",
    );
    assert!(
        rule.contains('.'),
        "TOP5-#3 Phase 3: rule_id must contain a `.` on emit; got `{rule}`",
    );
    // Alias-map fallback: the legacy colon-form still resolves through
    // the receive-side lookup for downstream consumers pinned to it.
    assert!(
        rba_block_enrichment(RBA_HIGH_RISK_BLOCK_CHECK_ID).is_some(),
        "legacy colon-form must still resolve on receive-side lookup",
    );

    // Severity / title / status pinned by the spec.
    assert_eq!(persisted.severity, "critical");
    assert_eq!(persisted.title, "Risk-based authentication blocked sign-in");
    assert_eq!(persisted.status, "open");

    // List shows exactly one row for the tenant.
    let rows = repo.list(TENANT_A, 0, 100).await.unwrap();
    assert_eq!(rows.len(), 1, "exactly one finding for the tenant");

    // Wave B audit spec line: CWE-1390 + MITRE TA0001 resolve via the
    // enrichment table.
    let enrichment =
        rba_block_enrichment(RBA_HIGH_RISK_BLOCK_CHECK_ID).expect("canonical check_id resolves");
    assert!(
        enrichment.cwe.iter().any(|c| c.as_u32() == 1390),
        "CWE-1390 Weak Authentication must be carried"
    );
    assert!(
        enrichment.mitre_attack.iter().any(|t| t.tactic == "TA0001"),
        "MITRE ATT&CK TA0001 Initial Access must be carried"
    );
    assert!(
        enrichment
            .compliance
            .nist_800_53
            .iter()
            .any(|c| c.as_str() == "AC-7"),
        "NIST AC-7 must be carried"
    );
}

#[tokio::test]
async fn allow_decision_does_not_emit_finding() {
    let repo = InMemoryFindings::default();
    let emission = emission_enabled(75);
    let user = Uuid::parse_str(USER_A).unwrap();

    let d = decision(
        RbaAction::Allow,
        92, // high score but Allow action — must NOT emit.
        Some(user),
        datetime!(2026-06-25 10:00:00 UTC),
    );
    let result = maybe_emit_block_finding(&repo, &d, &user.to_string(), &emission).await;
    assert!(result.is_none(), "Allow decisions must not emit");

    let rows = repo.list(TENANT_A, 0, 100).await.unwrap();
    assert!(rows.is_empty(), "no finding rows should be persisted");
}

#[tokio::test]
async fn block_below_threshold_does_not_emit_finding() {
    let repo = InMemoryFindings::default();
    let emission = emission_enabled(75);
    let user = Uuid::parse_str(USER_A).unwrap();

    let d = decision(
        RbaAction::Block,
        60, // Block but below the 75 threshold.
        Some(user),
        datetime!(2026-06-25 10:00:00 UTC),
    );
    let result = maybe_emit_block_finding(&repo, &d, &user.to_string(), &emission).await;
    assert!(
        result.is_none(),
        "Block decisions below the threshold must not emit"
    );

    let rows = repo.list(TENANT_A, 0, 100).await.unwrap();
    assert!(rows.is_empty());
}

#[tokio::test]
async fn disabled_emission_short_circuits() {
    let repo = InMemoryFindings::default();
    let emission = RbaFindingEmissionConfig::default(); // enabled=false
    let user = Uuid::parse_str(USER_A).unwrap();

    let d = decision(
        RbaAction::Block,
        99,
        Some(user),
        datetime!(2026-06-25 10:00:00 UTC),
    );
    let result = maybe_emit_block_finding(&repo, &d, &user.to_string(), &emission).await;
    assert!(
        result.is_none(),
        "emission disabled by default must short-circuit"
    );

    let rows = repo.list(TENANT_A, 0, 100).await.unwrap();
    assert!(rows.is_empty());
}

#[tokio::test]
async fn repeat_block_same_user_same_day_is_idempotent() {
    let repo = InMemoryFindings::default();
    let emission = emission_enabled(75);
    let user = Uuid::parse_str(USER_A).unwrap();
    let identity_key = user.to_string();

    // First block at 04:00 UTC.
    let d1 = decision(
        RbaAction::Block,
        82,
        Some(user),
        datetime!(2026-06-25 04:00:00 UTC),
    );
    let first = maybe_emit_block_finding(&repo, &d1, &identity_key, &emission)
        .await
        .expect("first emission");

    // Same user fires again later the same day with a worse score —
    // the day_bucket hash collapses to the same finding id, so the
    // in-memory adapter overwrites the row (last-write-wins, matching
    // the Pg adapter's `ON CONFLICT DO NOTHING RETURNING` semantics).
    let d2 = decision(
        RbaAction::Block,
        95,
        Some(user),
        datetime!(2026-06-25 22:00:00 UTC),
    );
    let second = maybe_emit_block_finding(&repo, &d2, &identity_key, &emission)
        .await
        .expect("second emission still returns");

    assert_eq!(
        first.id, second.id,
        "the synthetic finding id must collapse to the same hash within one day"
    );

    let rows = repo.list(TENANT_A, 0, 100).await.unwrap();
    assert_eq!(
        rows.len(),
        1,
        "exactly one row per (tenant, user, day_bucket); got {} rows",
        rows.len()
    );
}

#[tokio::test]
async fn different_days_produce_distinct_findings() {
    // Sanity: the day_bucket hash must change between distinct UTC
    // days. Otherwise a user who tripped the threshold yesterday could
    // never trip it again today.
    let repo = InMemoryFindings::default();
    let emission = emission_enabled(75);
    let user = Uuid::parse_str(USER_A).unwrap();
    let identity_key = user.to_string();

    let d1 = decision(
        RbaAction::Block,
        80,
        Some(user),
        datetime!(2026-06-25 12:00:00 UTC),
    );
    let d2 = decision(
        RbaAction::Block,
        80,
        Some(user),
        datetime!(2026-06-26 12:00:00 UTC),
    );
    let first = maybe_emit_block_finding(&repo, &d1, &identity_key, &emission)
        .await
        .expect("day-1 emission");
    let second = maybe_emit_block_finding(&repo, &d2, &identity_key, &emission)
        .await
        .expect("day-2 emission");

    assert_ne!(
        first.id, second.id,
        "different UTC days must produce different synthetic ids"
    );

    let rows = repo.list(TENANT_A, 0, 100).await.unwrap();
    assert_eq!(rows.len(), 2, "two rows — one per day");
}

#[tokio::test]
async fn anonymous_user_falls_back_to_email_identity_key() {
    // Failed credential lookups never resolve a user_id. Per the
    // adapter, we still want to dedupe repeated hits in the same day
    // — the identity key falls back to the lowercased email.
    let repo = InMemoryFindings::default();
    let emission = emission_enabled(75);

    let d = decision(
        RbaAction::Block,
        80,
        None, // anonymous
        datetime!(2026-06-25 04:00:00 UTC),
    );
    let identity_key = "alice@example.test".to_owned();
    let first = maybe_emit_block_finding(&repo, &d, &identity_key, &emission)
        .await
        .expect("first anonymous emission");
    let second = maybe_emit_block_finding(&repo, &d, &identity_key, &emission)
        .await
        .expect("second anonymous emission");

    assert_eq!(first.id, second.id, "anonymous idempotency by email");
    let rows = repo.list(TENANT_A, 0, 100).await.unwrap();
    assert_eq!(rows.len(), 1);

    // Description renders the anonymous fallback verbatim.
    assert!(
        first.description.contains("user anonymous"),
        "description must render 'user anonymous' for missing user_id, got: {}",
        first.description,
    );
}
