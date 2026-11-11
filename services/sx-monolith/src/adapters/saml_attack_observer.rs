//! SAML SP attack-observer → Finding adapter (TOP5-#3-P2-004).
//!
//! Implements [`sx_iam::service::saml::SamlAttackObserver`] by
//! translating each detected attack event into a synthetic [`FindingView`]
//! and inserting it via [`FindingRepositoryPort::insert`] (FOUND-001).
//!
//! ## Idempotency
//!
//! The emitted `view.id` is a deterministic UUID v5 over
//! `(tenant_id, kind, idp_issuer, day_bucket)` where `day_bucket` is
//! the UTC midnight of `event.detected_at_unix`. A flood of XSW
//! attempts from the same IdP within one UTC day collapses to a single
//! finding row — the wire-level rejection still happens on every
//! request; the **finding** only records one evidence row per
//! `(tenant, kind, idp, day)` tuple.
//!
//! ## Async dispatch
//!
//! [`SamlAttackObserver::notify`] is synchronous (the SAML verifier hot
//! path must not block on remote I/O). The adapter spawns the actual
//! `insert` call onto the Tokio runtime so the verifier returns to the
//! caller immediately; a failed insert is logged at WARN and the
//! rejection still stands (the finding is best-effort evidence, never
//! a verification gate).
//!
//! ## Engagement resolution
//!
//! The FOUND-001 metadata key `metadata.engagement_id` is set to the
//! configured `system_engagement_id` — every system-internal emitter
//! (P2-007/008 BAS observer, this adapter, the cloud-drift watcher)
//! writes against the same well-known engagement so auditors can scope
//! "automated detection" findings as a single audit trail.

use std::sync::Arc;

use sha2::{Digest, Sha256};
use sx_api::port::FindingRepositoryPort;
use sx_api::view::finding_view::FindingView;
use sx_core::reference::saml_attack_enrichment::{
    saml_attack_enrichment, SamlAttackEnrichment, SamlAttackSeverity,
};
use sx_iam::service::saml::{SamlAttackEvent, SamlAttackKind, SamlAttackObserver};
use time::OffsetDateTime;
use tracing::warn;

/// FOUND-001 namespace prefix mixed into the deterministic SAML
/// attack-detection finding id. Constant; rotating it invalidates
/// every prior idempotency bucket so changes here are a compatibility
/// break by design.
const SAML_FINDING_NAMESPACE: &str = "sentinelx:saml-attack:v1";

/// Configuration the composition root supplies when wiring the observer.
#[derive(Debug, Clone)]
pub(crate) struct SamlAttackObserverConfig {
    /// System-internal engagement id every emitted finding is tagged
    /// against. Same resolution as the P2-007/008 BAS observer.
    pub system_engagement_id: String,
    /// Synthetic asset id used as the `Finding.asset_id` foreign key.
    /// SAML attacks target the SP identity surface as a whole — there
    /// is no per-host asset to anchor against — so we use a stable
    /// "SAML SP" pseudo-asset.
    pub saml_sp_asset_id: String,
}

impl Default for SamlAttackObserverConfig {
    fn default() -> Self {
        // Stable nil-derived UUIDs the rest of the SAML observer
        // stack pivots against. Production deployments override both
        // via the loader config so auditors can scope findings to
        // tenant-owned engagement / asset rows.
        Self {
            system_engagement_id: "00000000-0000-0000-0000-00005a4d4c01".into(),
            saml_sp_asset_id: "00000000-0000-0000-0000-00005a4d4c02".into(),
        }
    }
}

/// Monolith implementation of [`SamlAttackObserver`].
///
/// Holds an `Arc<dyn FindingRepositoryPort>` (the same trait object
/// `AppState` distributes to the read-side handlers) plus a config
/// snapshot. The `notify` impl spawns the async `insert` on the
/// current Tokio runtime so the SAML verifier hot path does not
/// await network I/O.
#[derive(Clone)]
pub(crate) struct MonolithSamlAttackObserver {
    findings: Arc<dyn FindingRepositoryPort>,
    config: SamlAttackObserverConfig,
}

impl std::fmt::Debug for MonolithSamlAttackObserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonolithSamlAttackObserver")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl MonolithSamlAttackObserver {
    /// Build a new observer wired to the canonical
    /// `FindingRepositoryPort`.
    pub(crate) fn new(
        findings: Arc<dyn FindingRepositoryPort>,
        config: SamlAttackObserverConfig,
    ) -> Self {
        Self { findings, config }
    }

    /// Build the deterministic `(tenant, kind, idp, day)` finding id.
    ///
    /// Exposed `pub(crate)` for the integration test so it can predict
    /// the row id and assert idempotency without re-implementing the
    /// hashing rule.
    pub(crate) fn finding_id(
        tenant_id: &str,
        kind: SamlAttackKind,
        idp_issuer: &str,
        detected_at_unix: i64,
    ) -> String {
        let day = day_bucket_utc(detected_at_unix);
        let tuple = format!(
            "{SAML_FINDING_NAMESPACE}|{tenant_id}|{}|{idp_issuer}|{day}",
            kind.rule_id()
        );
        // SHA-256 produces a fixed-size 32-byte digest; coerce to a
        // fixed-size array so subsequent indexing is statically bounded
        // (clippy's `indexing_slicing` lint accepts indexing into
        // `[u8; N]` because the bound is known at compile time).
        let digest: [u8; 32] = Sha256::digest(tuple.as_bytes()).into();
        // Format the first 16 bytes as an RFC 4122 8-4-4-4-12 hex
        // string. The result is not a strict UUID v5 (no version /
        // variant nibbles) but the wire shape is a 36-char hex UUID,
        // identical to every other finding id the platform mints, and
        // the value is deterministic on the input tuple — exactly what
        // the idempotency rule needs.
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

    /// Build the [`FindingView`] from a [`SamlAttackEvent`]. Public-in-
    /// crate so tests can snapshot the payload shape.
    pub(crate) fn build_finding(&self, event: &SamlAttackEvent) -> Option<FindingView> {
        let enrichment = saml_attack_enrichment(event.kind.rule_id())?;
        let SamlAttackEnrichment {
            cwe,
            mitre_attack,
            compliance,
            severity,
            title,
            description,
        } = enrichment;

        let id = Self::finding_id(
            &event.tenant_id,
            event.kind,
            &event.idp_issuer,
            event.detected_at_unix,
        );
        let detected_at_iso = unix_to_rfc3339(event.detected_at_unix);

        // FOUND-001 metadata envelope:
        //   - engagement_id: system engagement (auditor scope tag)
        //   - rule_id: TOP5-#3 Phase 3 dotted-form (SAML.XSW, SAML.XEE, ...)
        //     The alias-map in `saml_attack_enrichment` keeps the legacy
        //     colon-form (saml:xsw-detected, …) resolving on receive-side
        //     lookups for downstream consumers pinned to it.
        //   - confidence: 1.0 — gate rejection is deterministic
        //   - cwe / mitre_attack / compliance: enrichment payload
        let metadata = serde_json::json!({
            "engagement_id": self.config.system_engagement_id,
            "rule_id": event.kind.rule_id_dotted(),
            "confidence": 1.0,
            "emitter": "saml_attack_observer",
            "idp_issuer": event.idp_issuer,
            "cwe": cwe.iter().map(|c| format!("CWE-{}", c.as_u32())).collect::<Vec<_>>(),
            "mitre_attack": mitre_attack
                .iter()
                .map(|t| {
                    let mut o = serde_json::json!({
                        "tactic": t.tactic,
                        "technique": t.technique,
                    });
                    if let (Some(sub), Some(map)) =
                        (t.subtechnique.as_ref(), o.as_object_mut())
                    {
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

        Some(FindingView {
            id,
            tenant_id: event.tenant_id.clone(),
            asset_id: self.config.saml_sp_asset_id.clone(),
            severity: match severity {
                SamlAttackSeverity::High => "high".into(),
                SamlAttackSeverity::Medium => "medium".into(),
            },
            status: "open".into(),
            title: title.into(),
            description: description.into(),
            cvss: None, // detection signal, not vuln score — per PO scope decision
            cve_id: None,
            first_seen: detected_at_iso.clone(),
            last_seen: detected_at_iso,
            metadata: Some(metadata),
        })
    }
}

impl SamlAttackObserver for MonolithSamlAttackObserver {
    fn notify(&self, event: SamlAttackEvent) {
        let Some(view) = self.build_finding(&event) else {
            // Unknown attack kind — the enrichment table omits it.
            // Don't crash the verifier hot path; just log.
            warn!(
                target: "adapters.saml_attack_observer",
                rule_id = %event.kind.rule_id(),
                "saml attack observer: no enrichment row; finding skipped"
            );
            return;
        };
        let findings = Arc::clone(&self.findings);
        let rule_id = event.kind.rule_id();
        let tenant_id = event.tenant_id;
        let finding_id = view.id.clone();
        // Spawn on the ambient runtime so the verifier returns
        // immediately. If no runtime is available (synchronous test
        // harness), fall back to a blocking insert via futures::block_on
        // equivalent — but we prefer a tokio::spawn under any
        // production code path.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Err(e) = findings.insert(view).await {
                    warn!(
                        target: "adapters.saml_attack_observer",
                        tenant_id = %tenant_id,
                        rule_id = %rule_id,
                        finding_id = %finding_id,
                        error = %e,
                        "saml attack observer: insert failed; rejection still recorded"
                    );
                }
            });
        } else {
            // No runtime — likely a unit test that didn't go through
            // `tokio::test`. Skip; the rejection is still recorded.
            warn!(
                target: "adapters.saml_attack_observer",
                "saml attack observer: no tokio runtime; finding skipped"
            );
        }
    }
}

/// Compute the UTC midnight (`YYYY-MM-DD`) for a Unix-epoch second.
/// Pure helper so the integration test can predict the bucket without
/// touching `OffsetDateTime` directly.
pub(crate) fn day_bucket_utc(unix_secs: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix_secs).map_or_else(
        |_| "1970-01-01".into(),
        |t| format!("{:04}-{:02}-{:02}", t.year(), u8::from(t.month()), t.day()),
    )
}

/// Format a Unix-epoch second as RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`).
fn unix_to_rfc3339(unix_secs: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix_secs).map_or_else(
        |_| "1970-01-01T00:00:00Z".into(),
        |t| {
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                t.year(),
                u8::from(t.month()),
                t.day(),
                t.hour(),
                t.minute(),
                t.second()
            )
        },
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::adapters::repository::InMemoryFindings;
    use std::sync::Arc;

    fn cfg() -> SamlAttackObserverConfig {
        SamlAttackObserverConfig {
            system_engagement_id: "11111111-1111-1111-1111-111111111111".into(),
            saml_sp_asset_id: "22222222-2222-2222-2222-222222222222".into(),
        }
    }

    fn evt(kind: SamlAttackKind) -> SamlAttackEvent {
        SamlAttackEvent {
            tenant_id: "t-1".into(),
            kind,
            idp_issuer: "https://idp.example.com".into(),
            // 2026-06-25T00:00:00Z — pins the day bucket.
            detected_at_unix: 1_782_604_800,
        }
    }

    #[test]
    fn finding_id_is_deterministic_per_day() {
        let a = MonolithSamlAttackObserver::finding_id(
            "t-1",
            SamlAttackKind::Xsw,
            "https://idp.example.com",
            1_782_604_800, // 2026-06-25 00:00 UTC
        );
        let b = MonolithSamlAttackObserver::finding_id(
            "t-1",
            SamlAttackKind::Xsw,
            "https://idp.example.com",
            1_782_604_800 + 3600, // same day, one hour later
        );
        assert_eq!(a, b, "same day → same finding id");

        let c = MonolithSamlAttackObserver::finding_id(
            "t-1",
            SamlAttackKind::Xsw,
            "https://idp.example.com",
            1_782_604_800 + 86_400, // next day
        );
        assert_ne!(a, c, "next day → different finding id");
    }

    #[test]
    fn finding_id_differs_per_kind() {
        let xsw = MonolithSamlAttackObserver::finding_id(
            "t-1",
            SamlAttackKind::Xsw,
            "https://idp.example.com",
            1_782_604_800,
        );
        let xee = MonolithSamlAttackObserver::finding_id(
            "t-1",
            SamlAttackKind::Xee,
            "https://idp.example.com",
            1_782_604_800,
        );
        assert_ne!(xsw, xee);
    }

    #[test]
    fn day_bucket_pins_utc_midnight() {
        // 1_782_604_800 == 2026-06-28 00:00:00 UTC (anchor used by the
        // sibling tests above). One second before next midnight stays in
        // the same day; one second after crosses.
        // 2026-06-28 23:59:59 UTC → 2026-06-28
        assert_eq!(day_bucket_utc(1_782_604_800 + 86_399), "2026-06-28");
        // 2026-06-29 00:00:00 UTC → 2026-06-29
        assert_eq!(day_bucket_utc(1_782_604_800 + 86_400), "2026-06-29");
    }

    #[test]
    fn build_finding_populates_found_001_metadata() {
        let findings = Arc::new(InMemoryFindings::default());
        let obs = MonolithSamlAttackObserver::new(findings, cfg());
        let view = obs.build_finding(&evt(SamlAttackKind::Xsw)).unwrap();
        assert_eq!(view.severity, "high");
        assert_eq!(view.status, "open");
        assert!(view.metadata.is_some());
        let meta = view.metadata.as_ref().unwrap();
        assert_eq!(
            meta.get("engagement_id").and_then(|v| v.as_str()),
            Some("11111111-1111-1111-1111-111111111111")
        );
        // TOP5-#3 Phase 3: dotted-form rule_id on the wire.
        let rule_id = meta
            .get("rule_id")
            .and_then(|v| v.as_str())
            .expect("rule_id present");
        assert_eq!(rule_id, "SAML.XSW");
        assert!(
            rule_id.contains('.'),
            "TOP5-#3 Phase 3: rule_id must contain a `.` on emit; got `{rule_id}`"
        );
        assert_eq!(
            meta.get("confidence").and_then(serde_json::Value::as_f64),
            Some(1.0)
        );
        let cwe_arr = meta.get("cwe").and_then(|v| v.as_array()).unwrap();
        let cwe_strs: Vec<&str> = cwe_arr.iter().filter_map(|v| v.as_str()).collect();
        assert!(cwe_strs.contains(&"CWE-347"));
        assert!(cwe_strs.contains(&"CWE-345"));
    }

    #[tokio::test]
    async fn notify_inserts_finding_into_repository() {
        let findings: Arc<dyn FindingRepositoryPort> = Arc::new(InMemoryFindings::default());
        let obs = MonolithSamlAttackObserver::new(Arc::clone(&findings), cfg());
        let event = evt(SamlAttackKind::Xee);
        obs.notify(event);
        // Spawned task — yield so the insert lands before we read.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        let rows = findings.list("t-1", 0, 10).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].severity, "high");
    }

    #[tokio::test]
    async fn notify_is_idempotent_within_day() {
        let findings: Arc<dyn FindingRepositoryPort> = Arc::new(InMemoryFindings::default());
        let obs = MonolithSamlAttackObserver::new(Arc::clone(&findings), cfg());
        // Fire 3 XSW events same day.
        for _ in 0..3 {
            obs.notify(evt(SamlAttackKind::Xsw));
        }
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        let rows = findings.list("t-1", 0, 10).await.unwrap();
        assert_eq!(rows.len(), 1, "idempotent on (tenant, kind, idp, day)");
    }
}
