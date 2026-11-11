//! DLP adapter (P2-006) — wires `sx_dlp::InMemoryDlpService` behind
//! the [`sx_api::port::DlpPort`] HTTP trait.
//!
//! Responsibilities:
//!
//! * Translate the wire-level [`sx_api::port::DlpScanResultView`] /
//!   [`sx_api::port::DlpDetectorConfigView`] DTOs onto the in-crate
//!   [`sx_dlp::DlpScanResult`] / [`sx_dlp::TenantDetectorConfig`].
//! * Project the cross-crate [`sx_dlp::DlpMatchKind`] onto the wire-side
//!   [`sx_api::port::DlpDetectorKind`] and back. Both enums are kept
//!   identical by design — adding a new detector is therefore a two-line
//!   change in this file plus the implementation crate.
//! * Surface a 10 MB payload cap that matches [`sx_dlp::MAX_PAYLOAD_BYTES`]
//!   so a hostile caller cannot bypass it by sneaking around the HTTP
//!   middleware layer.
//!
//! The adapter never persists raw payloads — `scan` consumes the body
//! by value, forwards it to the service for inspection, and drops it
//! at function return. The in-crate `InMemoryDlpService` only ever
//! retains scan-metadata (kind counts + redacted previews).

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use sqlx::types::Json;
use sqlx::{PgPool, Row as _};
use sx_api::port::{
    DlpDetectorConfigView, DlpDetectorKind, DlpKindSummaryView, DlpMatchView, DlpPort,
    DlpPortError, DlpScanResultView, DlpSignalView, DlpThresholdView,
};
use sx_core::reference::dlp_enrichment::{dlp_enrichment, DlpEnrichment};
use sx_dlp::{
    DlpError, DlpMatch, DlpMatchKind, DlpScanResult, DlpService, InMemoryDlpService, ScanSource,
    SignalEvidence, TenantDetectorConfig, MAX_PAYLOAD_BYTES,
};

/// Bundle of DLP handles handed to the composition root.
#[derive(Clone)]
pub(crate) struct DlpBundle {
    /// HTTP-facing trait object installed onto [`sx_api::AppState`].
    pub dlp: Arc<dyn DlpPort>,
}

/// Build the DLP bundle. The composition root installs the in-memory
/// service with the canonical inspector set; future deployments can
/// swap in a persistent-history implementation behind the same trait
/// without disturbing this wiring.
pub(crate) fn build() -> DlpBundle {
    let svc = Arc::new(InMemoryDlpService::with_defaults());
    DlpBundle {
        dlp: Arc::new(DlpAdapter {
            svc,
            config_store: None,
        }),
    }
}

/// Build the durable DLP bundle. The detector engine itself stays the
/// in-memory `sx_dlp` service (scan is stateless — it never persists
/// payloads), but the **per-tenant detector config** (enabled set +
/// confidence threshold) is persisted to Postgres so an admin override no
/// longer reverts to permissive-all on restart. Writes go write-through
/// (Pg + the live engine); scans load-through (hydrate the engine from Pg
/// first) so a fresh process honours the stored policy without a re-`PUT`.
pub(crate) fn build_pg(pool: PgPool, stmt_timeout_ms: u64) -> DlpBundle {
    let svc = Arc::new(InMemoryDlpService::with_defaults());
    DlpBundle {
        dlp: Arc::new(DlpAdapter {
            svc,
            config_store: Some(Arc::new(PgDlpConfigStore {
                pool,
                stmt_timeout_ms,
            })),
        }),
    }
}

/// Concrete `DlpPort` implementation backed by [`InMemoryDlpService`] for
/// the detector engine, with an optional Postgres store for the durable
/// per-tenant config.
pub(crate) struct DlpAdapter {
    svc: Arc<InMemoryDlpService>,
    /// `Some` when the database is enabled — the authoritative home of the
    /// per-tenant detector config. `None` in dev (pure in-memory).
    config_store: Option<Arc<PgDlpConfigStore>>,
}

impl std::fmt::Debug for DlpAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DlpAdapter").finish_non_exhaustive()
    }
}

impl DlpAdapter {
    /// Load a tenant's authoritative detector config: from Postgres when a
    /// store is wired and a row exists, otherwise the in-memory engine's
    /// view (which is the permissive default for an untouched tenant).
    async fn load_config(&self, tenant_id: &str) -> Result<TenantDetectorConfig, DlpPortError> {
        if let Some(store) = &self.config_store {
            if let Some(cfg) = store.get(tenant_id).await? {
                return Ok(cfg);
            }
        }
        Ok(self.svc.get_tenant_config(tenant_id))
    }
}

/// Postgres store for the per-tenant DLP detector config — one JSONB row
/// per tenant in `dlp_detector_config`, keyed by `tenant_id` with an
/// explicit predicate (no RLS; see the migration). A missing row means the
/// tenant inherits the permissive default.
struct PgDlpConfigStore {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl PgDlpConfigStore {
    fn err(e: impl std::fmt::Display) -> DlpPortError {
        DlpPortError::Internal(format!("dlp config store: {e}"))
    }

    async fn begin(&self) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, DlpPortError> {
        let mut tx = self.pool.begin().await.map_err(Self::err)?;
        let bounded = self.stmt_timeout_ms.clamp(1, 60_000);
        sqlx::query(&format!("SET LOCAL statement_timeout = {bounded}"))
            .execute(&mut *tx)
            .await
            .map_err(Self::err)?;
        Ok(tx)
    }

    async fn get(&self, tenant_id: &str) -> Result<Option<TenantDetectorConfig>, DlpPortError> {
        let mut tx = self.begin().await?;
        let row = sqlx::query("SELECT config FROM dlp_detector_config WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(Self::err)?;
        tx.commit().await.map_err(Self::err)?;
        match row {
            Some(r) => r
                .try_get::<Json<TenantDetectorConfig>, _>("config")
                .map(|j| Some(j.0))
                .map_err(Self::err),
            None => Ok(None),
        }
    }

    async fn put(&self, tenant_id: &str, cfg: &TenantDetectorConfig) -> Result<(), DlpPortError> {
        let mut tx = self.begin().await?;
        sqlx::query(
            "INSERT INTO dlp_detector_config (tenant_id, config, updated_at) \
             VALUES ($1, $2, now()) \
             ON CONFLICT (tenant_id) DO UPDATE SET config = EXCLUDED.config, updated_at = now()",
        )
        .bind(tenant_id)
        .bind(Json(cfg))
        .execute(&mut *tx)
        .await
        .map_err(Self::err)?;
        tx.commit().await.map_err(Self::err)
    }
}

fn map_dlp(err: DlpError) -> DlpPortError {
    match err {
        DlpError::PayloadTooLarge(bytes) => DlpPortError::PayloadTooLarge {
            bytes,
            max: MAX_PAYLOAD_BYTES,
        },
        DlpError::InvalidTenant => DlpPortError::Invalid("invalid tenant id".into()),
        DlpError::Internal(m) => DlpPortError::Internal(m),
    }
}

fn project_kind(k: DlpMatchKind) -> DlpDetectorKind {
    match k {
        DlpMatchKind::CreditCard => DlpDetectorKind::CreditCard,
        DlpMatchKind::SsnUs => DlpDetectorKind::SsnUs,
        DlpMatchKind::AwsAccessKey => DlpDetectorKind::AwsAccessKey,
        DlpMatchKind::AwsSecretKey => DlpDetectorKind::AwsSecretKey,
        DlpMatchKind::GithubPat => DlpDetectorKind::GithubPat,
        DlpMatchKind::Jwt => DlpDetectorKind::Jwt,
        DlpMatchKind::PemPrivateKey => DlpDetectorKind::PemPrivateKey,
        DlpMatchKind::Email => DlpDetectorKind::Email,
        DlpMatchKind::Phone => DlpDetectorKind::Phone,
        DlpMatchKind::GcpServiceAccount => DlpDetectorKind::GcpServiceAccount,
        DlpMatchKind::SlackToken => DlpDetectorKind::SlackToken,
        DlpMatchKind::NamedEntity => DlpDetectorKind::NamedEntity,
    }
}

fn lift_kind(k: DlpDetectorKind) -> DlpMatchKind {
    match k {
        DlpDetectorKind::CreditCard => DlpMatchKind::CreditCard,
        DlpDetectorKind::SsnUs => DlpMatchKind::SsnUs,
        DlpDetectorKind::AwsAccessKey => DlpMatchKind::AwsAccessKey,
        DlpDetectorKind::AwsSecretKey => DlpMatchKind::AwsSecretKey,
        DlpDetectorKind::GithubPat => DlpMatchKind::GithubPat,
        DlpDetectorKind::Jwt => DlpMatchKind::Jwt,
        DlpDetectorKind::PemPrivateKey => DlpMatchKind::PemPrivateKey,
        DlpDetectorKind::Email => DlpMatchKind::Email,
        DlpDetectorKind::Phone => DlpMatchKind::Phone,
        DlpDetectorKind::GcpServiceAccount => DlpMatchKind::GcpServiceAccount,
        DlpDetectorKind::SlackToken => DlpMatchKind::SlackToken,
        DlpDetectorKind::NamedEntity => DlpMatchKind::NamedEntity,
    }
}

fn project_signal(s: SignalEvidence) -> DlpSignalView {
    DlpSignalView {
        kind: s.kind.as_str().to_owned(),
        sub_score: s.sub_score,
        weight: s.weight,
        rationale: s.rationale,
    }
}

/// Build the wire-level [`DlpMatchView`] enrichment payload for a
/// projected `DlpMatch`.
///
/// TOP5-#3-P2-003 at-boundary enrichment: the canonical lookup lives in
/// [`sx_core::reference::dlp_enrichment`]; this adapter is the single
/// place where DLP detection events cross into wire shape, so populating
/// the `cwe[]` / `mitre_attack[]` / `compliance` / `enrichment_confidence`
/// fields here keeps `sx-dlp` free of `sx-core` knowledge.
///
/// The fusion-score `confidence: f32` field on `DlpMatchView` is
/// preserved unchanged (legacy field consumed by the LOW-009
/// explainability dashboard). The new
/// `enrichment_confidence: Option<f64>` projects the same numeric onto
/// the canonical `Finding::confidence` shape so SARIF / SOC pipelines
/// downstream get the procurement-grade payload.
fn enriched_match_view(m: DlpMatch) -> DlpMatchView {
    let DlpEnrichment {
        // CVSS is deliberately None for every DLP variant — see
        // `dlp_enrichment.rs` §"CVSS posture for DLP". We pattern-match
        // it to silence dead-binding warnings on a future contributor
        // who flips a variant onto a CVSS payload.
        cvss: _,
        cwe,
        mitre_attack,
        compliance,
    } = dlp_enrichment(m.kind.as_str()).unwrap_or_default();
    let enrichment_confidence = if m.confidence > 0.0 {
        Some(f64::from(m.confidence))
    } else {
        None
    };
    DlpMatchView {
        kind: project_kind(m.kind),
        offset: m.offset,
        length: m.length,
        redacted_preview: m.redacted_preview,
        confidence: m.confidence,
        signals: m.signals.into_iter().map(project_signal).collect(),
        cwe,
        mitre_attack,
        compliance,
        enrichment_confidence,
        // TOP5-#3 Phase 3 — pass source-aware (line, column) through
        // when the emitter carries them; `None` for raw / network
        // payloads. SARIF `region.startLine` / `.startColumn` is
        // populated downstream via
        // `sx_api::controller::scan::scan_finding_to_finding`.
        line: m.line,
        column: m.column,
    }
}

fn project_result(r: DlpScanResult) -> DlpScanResultView {
    DlpScanResultView {
        id: r.id,
        tenant_id: r.tenant_id,
        finished_at: r.finished_at,
        bytes_scanned: r.bytes_scanned,
        total_matches: r.total_matches,
        summary: r
            .summary
            .into_iter()
            .map(|s| DlpKindSummaryView {
                kind: project_kind(s.kind),
                count: s.count,
            })
            .collect(),
        matches: r.matches.into_iter().map(enriched_match_view).collect(),
    }
}

fn project_config(tenant_id: &str, cfg: TenantDetectorConfig) -> DlpDetectorConfigView {
    DlpDetectorConfigView {
        tenant_id: tenant_id.to_owned(),
        enabled: cfg.enabled_vec().into_iter().map(project_kind).collect(),
        min_confidence: cfg.effective_min_confidence(),
    }
}

#[async_trait]
impl DlpPort for DlpAdapter {
    async fn scan(
        &self,
        tenant_id: &str,
        payload: &[u8],
    ) -> Result<DlpScanResultView, DlpPortError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(DlpPortError::PayloadTooLarge {
                bytes: payload.len(),
                max: MAX_PAYLOAD_BYTES,
            });
        }
        // Load-through: hydrate the engine from the durable config so a
        // fresh process scans against the tenant's persisted policy rather
        // than the permissive default. No-op when the DB is disabled.
        if let Some(store) = &self.config_store {
            if let Some(cfg) = store.get(tenant_id).await? {
                let _ = self.svc.put_tenant_config(tenant_id, cfg);
            }
        }
        // Lossy decode is intentional — DLP detectors run against
        // UTF-8 strings and the controller already capped the body to
        // 10 MB. Replacement characters do not influence regex hits.
        let text = String::from_utf8_lossy(payload);
        let result = self
            .svc
            .scan_text(tenant_id, ScanSource::Api, text.as_ref())
            .await
            .map_err(map_dlp)?;
        Ok(project_result(result))
    }

    async fn get_config(&self, tenant_id: &str) -> Result<DlpDetectorConfigView, DlpPortError> {
        if tenant_id.is_empty() {
            return Err(DlpPortError::Invalid("invalid tenant id".into()));
        }
        let cfg = self.load_config(tenant_id).await?;
        Ok(project_config(tenant_id, cfg))
    }

    async fn put_config(
        &self,
        tenant_id: &str,
        enabled: Vec<DlpDetectorKind>,
        min_confidence: Option<f32>,
    ) -> Result<DlpDetectorConfigView, DlpPortError> {
        if tenant_id.is_empty() {
            return Err(DlpPortError::Invalid("invalid tenant id".into()));
        }
        let mut set: BTreeSet<DlpMatchKind> = BTreeSet::new();
        for k in enabled {
            let _ = set.insert(lift_kind(k));
        }
        // Preserve the existing threshold if the caller did not supply
        // one — that keeps the `/v1/admin/dlp/thresholds` admin
        // endpoint the single source of truth for confidence updates.
        // The "existing" value is read from the durable store when wired.
        let threshold = match min_confidence {
            Some(v) => v,
            None => self
                .load_config(tenant_id)
                .await?
                .effective_min_confidence(),
        };
        let desired = TenantDetectorConfig {
            enabled: set,
            min_confidence: threshold,
        };
        // Write-through: persist first (authoritative), then update the
        // live engine so the next scan on this process sees it immediately.
        if let Some(store) = &self.config_store {
            store.put(tenant_id, &desired).await?;
        }
        let cfg = self.svc.put_tenant_config(tenant_id, desired);
        Ok(project_config(tenant_id, cfg))
    }

    async fn get_threshold(&self, tenant_id: &str) -> Result<DlpThresholdView, DlpPortError> {
        if tenant_id.is_empty() {
            return Err(DlpPortError::Invalid("invalid tenant id".into()));
        }
        let cfg = self.load_config(tenant_id).await?;
        Ok(DlpThresholdView {
            tenant_id: tenant_id.to_owned(),
            min_confidence: cfg.effective_min_confidence(),
        })
    }

    async fn put_threshold(
        &self,
        tenant_id: &str,
        min_confidence: f32,
    ) -> Result<DlpThresholdView, DlpPortError> {
        if tenant_id.is_empty() {
            return Err(DlpPortError::Invalid("invalid tenant id".into()));
        }
        if min_confidence.is_nan() {
            return Err(DlpPortError::Invalid(
                "min_confidence must be a finite number in [0.0, 1.0]".into(),
            ));
        }
        let clamped = min_confidence.clamp(0.0, 1.0);
        let existing = self.load_config(tenant_id).await?;
        let desired = TenantDetectorConfig {
            enabled: existing.enabled,
            min_confidence: clamped,
        };
        // Write-through: durable store first, then the live engine.
        if let Some(store) = &self.config_store {
            store.put(tenant_id, &desired).await?;
        }
        let cfg = self.svc.put_tenant_config(tenant_id, desired);
        Ok(DlpThresholdView {
            tenant_id: tenant_id.to_owned(),
            min_confidence: cfg.effective_min_confidence(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scan_projects_pan_match() {
        let bundle = build();
        // Luhn-valid PAN that's NOT on the HIGH-004 suppression list.
        let res = bundle
            .dlp
            .scan("t1", b"card number: 4539 5787 6362 1486 here")
            .await
            .unwrap();
        assert_eq!(res.tenant_id, "t1");
        assert!(res.total_matches >= 1);
        assert!(res
            .summary
            .iter()
            .any(|s| matches!(s.kind, DlpDetectorKind::CreditCard)));
    }

    #[tokio::test]
    async fn scan_rejects_oversize_payload() {
        let bundle = build();
        let big = vec![b'a'; MAX_PAYLOAD_BYTES + 1];
        let err = bundle.dlp.scan("t1", &big).await.unwrap_err();
        assert!(matches!(err, DlpPortError::PayloadTooLarge { .. }));
    }

    #[tokio::test]
    async fn get_config_defaults_permissive() {
        let bundle = build();
        let cfg = bundle.dlp.get_config("never-touched").await.unwrap();
        // Every detector is enabled until the tenant writes a row.
        assert!(cfg.enabled.contains(&DlpDetectorKind::Email));
        assert!(cfg.enabled.contains(&DlpDetectorKind::CreditCard));
    }

    #[tokio::test]
    async fn put_then_get_round_trips() {
        let bundle = build();
        let _ = bundle
            .dlp
            .put_config(
                "t1",
                vec![DlpDetectorKind::Email, DlpDetectorKind::CreditCard],
                None,
            )
            .await
            .unwrap();
        let cfg = bundle.dlp.get_config("t1").await.unwrap();
        assert_eq!(cfg.enabled.len(), 2);
        assert!(cfg.enabled.contains(&DlpDetectorKind::Email));
        assert!(cfg.enabled.contains(&DlpDetectorKind::CreditCard));
        assert!(!cfg.enabled.contains(&DlpDetectorKind::Phone));
    }

    #[tokio::test]
    async fn put_config_filters_subsequent_scans() {
        let bundle = build();
        // Only enable credit card on this tenant. The default threshold
        // is `0.0` so every PAN match still surfaces.
        let _ = bundle
            .dlp
            .put_config("t1", vec![DlpDetectorKind::CreditCard], None)
            .await
            .unwrap();
        let res = bundle
            .dlp
            .scan("t1", b"card number: 4539578763621486 or alice@example.com")
            .await
            .unwrap();
        // Email should be filtered out by the detector enable list.
        assert!(!res
            .matches
            .iter()
            .any(|m| matches!(m.kind, DlpDetectorKind::Email)));
        assert!(res
            .matches
            .iter()
            .any(|m| matches!(m.kind, DlpDetectorKind::CreditCard)));
    }

    #[tokio::test]
    async fn empty_tenant_is_invalid() {
        let bundle = build();
        let err = bundle.dlp.scan("", b"hi").await.unwrap_err();
        assert!(matches!(err, DlpPortError::Invalid(_)));
        let err = bundle.dlp.get_config("").await.unwrap_err();
        assert!(matches!(err, DlpPortError::Invalid(_)));
        let err = bundle.dlp.put_config("", vec![], None).await.unwrap_err();
        assert!(matches!(err, DlpPortError::Invalid(_)));
        let err = bundle.dlp.get_threshold("").await.unwrap_err();
        assert!(matches!(err, DlpPortError::Invalid(_)));
        let err = bundle.dlp.put_threshold("", 0.5).await.unwrap_err();
        assert!(matches!(err, DlpPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn threshold_round_trip_and_clamp() {
        let bundle = build();
        // Default is permissive zero.
        let t = bundle.dlp.get_threshold("t1").await.unwrap();
        assert!(t.min_confidence.abs() < f32::EPSILON);
        // Set in-range.
        let t = bundle.dlp.put_threshold("t1", 0.85).await.unwrap();
        assert!((t.min_confidence - 0.85).abs() < 1e-3);
        // Out-of-range high gets clamped.
        let t = bundle.dlp.put_threshold("t1", 9.9).await.unwrap();
        assert!((t.min_confidence - 1.0).abs() < 1e-6);
        // NaN is rejected.
        let err = bundle.dlp.put_threshold("t1", f32::NAN).await.unwrap_err();
        assert!(matches!(err, DlpPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn high_threshold_drops_low_confidence_findings() {
        let bundle = build();
        // Raise the bar so a bare PAN regex hit (no Luhn / no context)
        // is filtered out.
        let _ = bundle.dlp.put_threshold("t1", 0.7).await.unwrap();
        // Random 16-digit string that the credit-card matcher should
        // NOT pick up (because it does Luhn check), but the email
        // detector will not fire either — we use a known Luhn-fail PAN
        // shaped string smuggled in via context-free phone-style chars.
        let res = bundle
            .dlp
            .scan("t1", b"order id 1234567812345670 reference")
            .await
            .unwrap();
        // Either no matches OR every match exceeds the threshold.
        for m in res.matches {
            assert!(m.confidence >= 0.7 - 1e-3, "leaked low-confidence match");
        }
    }

    #[tokio::test]
    async fn scan_response_carries_signal_breakdown() {
        let bundle = build();
        let res = bundle
            .dlp
            .scan("t1", b"card number: 4539578763621486 thanks")
            .await
            .unwrap();
        // Expect at least one PAN finding with a non-empty signal
        // breakdown — the explainability surface.
        let pan = res
            .matches
            .iter()
            .find(|m| matches!(m.kind, DlpDetectorKind::CreditCard))
            .expect("PAN finding");
        assert!(pan.confidence > 0.0);
        assert!(!pan.signals.is_empty());
        assert!(pan.signals.iter().any(|s| s.kind == "regex_match"));
        assert!(pan.signals.iter().any(|s| s.kind == "luhn_check"));
    }

    /// TOP5-#3-P2-003 regression net — end-to-end DetectionEvent →
    /// DlpScanResultView projection must carry the Phase 1 enrichment
    /// surface (CWE / MITRE ATT&CK / compliance / enrichment_confidence)
    /// that auditors and SOC pipelines expect on every enriched finding.
    ///
    /// This is the at-boundary equivalent of
    /// `crates/sx-api/tests/scan_enrichment_reaches_wire.rs` (HDR.*
    /// canonical regression net): if a future contributor strips the
    /// enrichment lookup out of `enriched_match_view`, or breaks the
    /// `DlpMatchKind::as_str()` ↔ `dlp_enrichment` key contract, this
    /// test fails fast.
    #[tokio::test]
    async fn pan_match_carries_enrichment_to_the_wire() {
        let bundle = build();
        let res = bundle
            .dlp
            .scan("t1", b"card number: 4539578763621486 thanks")
            .await
            .unwrap();
        let pan = res
            .matches
            .iter()
            .find(|m| matches!(m.kind, DlpDetectorKind::CreditCard))
            .expect("PAN finding");

        // ---- CWE-311 Missing Encryption of Sensitive Data ----
        let cwe_strs: Vec<String> = pan
            .cwe
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        assert!(
            cwe_strs.iter().any(|s| s == "CWE-311"),
            "PAN finding includes CWE-311; got {cwe_strs:?}",
        );

        // ---- MITRE T1552 Unsecured Credentials ----
        assert!(
            pan.mitre_attack.iter().any(|t| t.technique == "T1552"),
            "PAN finding includes MITRE T1552 Unsecured Credentials",
        );

        // ---- Compliance: PCI 3.4 / 3.5 + NIST SC-28 / SI-12 ----
        let pci: Vec<&str> = pan
            .compliance
            .pci_dss
            .iter()
            .map(sx_core::value_object::compliance::PciRequirement::as_str)
            .collect();
        assert!(
            pci.contains(&"3.4") && pci.contains(&"3.5"),
            "PAN finding maps onto PCI 3.4 + 3.5; got {pci:?}",
        );
        let nist: Vec<&str> = pan
            .compliance
            .nist_800_53
            .iter()
            .map(sx_core::value_object::compliance::NistControl::as_str)
            .collect();
        assert!(
            nist.contains(&"SC-28") && nist.contains(&"SI-12"),
            "PAN finding maps onto NIST SC-28 + SI-12; got {nist:?}",
        );

        // ---- enrichment_confidence projects the fusion score onto f64 ----
        let ec = pan
            .enrichment_confidence
            .expect("non-zero fusion confidence projects onto enrichment_confidence");
        assert!(
            (ec - f64::from(pan.confidence)).abs() < 1e-6,
            "enrichment_confidence = f64 widening of fusion confidence; \
             got ec={ec} fusion={fusion}",
            fusion = pan.confidence,
        );

        // ---- JSON wire shape — verify skip_serializing_if behavior ----
        let json = serde_json::to_value(pan).expect("DlpMatchView serialises");
        assert!(
            json.get("cwe").and_then(|v| v.as_array()).is_some(),
            "cwe[] present on enriched wire payload",
        );
        assert!(
            json.get("mitre_attack")
                .and_then(|v| v.as_array())
                .is_some(),
            "mitre_attack[] present on enriched wire payload",
        );
        assert!(
            json.get("compliance").and_then(|v| v.as_object()).is_some(),
            "compliance object present on enriched wire payload",
        );
        assert!(
            json.get("enrichment_confidence")
                .and_then(serde_json::Value::as_f64)
                .is_some(),
            "enrichment_confidence present on enriched wire payload",
        );
    }

    /// Informational kinds (email / phone / named_entity) intentionally
    /// resolve to `None` in the enrichment table and must omit the
    /// enrichment keys from the wire payload via `skip_serializing_if`.
    #[tokio::test]
    async fn email_match_omits_enrichment_keys() {
        let bundle = build();
        let res = bundle
            .dlp
            .scan("t1", b"contact alice@example.com please")
            .await
            .unwrap();
        let email = res
            .matches
            .iter()
            .find(|m| matches!(m.kind, DlpDetectorKind::Email))
            .expect("email finding");
        // Unenriched-kind enrichment fields should be empty on the
        // struct, and the JSON should omit the keys entirely.
        assert!(email.cwe.is_empty());
        assert!(email.mitre_attack.is_empty());
        assert!(email.compliance.is_empty());
        let json = serde_json::to_value(email).expect("DlpMatchView serialises");
        let obj = json.as_object().expect("DlpMatchView is a JSON object");
        assert!(
            !obj.contains_key("cwe"),
            "empty cwe[] omitted via skip_serializing_if",
        );
        assert!(
            !obj.contains_key("mitre_attack"),
            "empty mitre_attack[] omitted via skip_serializing_if",
        );
        assert!(
            !obj.contains_key("compliance"),
            "empty compliance object omitted via skip_serializing_if",
        );
    }

    /// Durability proof against a real Postgres: a restricted detector set
    /// + raised confidence threshold written for a tenant survive a *fresh
    /// bundle (restart-equivalent)*, an unconfigured tenant reads back the
    /// permissive default, and a scan on the fresh process honours the
    /// persisted enable-list without a re-`PUT`. Gated on
    /// `TEST_DATABASE_URL` (silent no-op in CI).
    #[tokio::test]
    async fn pg_dlp_config_survives_restart() {
        #[allow(clippy::disallowed_methods)]
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let tenant = uuid::Uuid::new_v4().to_string();

        // First process: restrict to credit-card only + raise the floor.
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("connect");
            let bundle = build_pg(pool, 15_000);
            bundle
                .dlp
                .put_config(&tenant, vec![DlpDetectorKind::CreditCard], Some(0.8))
                .await
                .expect("put config");
        }

        // Fresh bundle == a fresh process. In-memory config would be gone.
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("reconnect");
            let bundle = build_pg(pool, 15_000);
            let cfg = bundle.dlp.get_config(&tenant).await.expect("get config");
            assert_eq!(
                cfg.enabled,
                vec![DlpDetectorKind::CreditCard],
                "enabled set survived restart"
            );
            assert!(
                (cfg.min_confidence - 0.8).abs() < 1e-6,
                "threshold survived restart"
            );

            // A never-configured tenant inherits the permissive default.
            let other = uuid::Uuid::new_v4().to_string();
            let def = bundle.dlp.get_config(&other).await.expect("default");
            assert!(
                def.enabled.contains(&DlpDetectorKind::Email),
                "unconfigured tenant stays permissive"
            );

            // Scan on the fresh process honours the persisted enable-list:
            // email is filtered out even though no re-PUT happened.
            let res = bundle
                .dlp
                .scan(&tenant, b"card 4539578763621486 and alice@example.com")
                .await
                .expect("scan");
            assert!(
                !res.matches
                    .iter()
                    .any(|m| matches!(m.kind, DlpDetectorKind::Email)),
                "email filtered post-restart via persisted config"
            );
        }

        // Cleanup.
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("reconnect");
            sqlx::query("DELETE FROM dlp_detector_config WHERE tenant_id = $1")
                .bind(&tenant)
                .execute(&pool)
                .await
                .expect("cleanup");
        }
    }
}
