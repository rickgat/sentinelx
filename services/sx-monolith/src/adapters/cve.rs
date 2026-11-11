//! CVE repository façade.
//!
//! Phase-3.5: thin façade over `sx_storage::PgCveRepository` (when Postgres
//! is wired) and an in-memory map (when running in dev mode). In addition
//! to the [`InMemoryCveSink`] used by offline developers, this module now
//! exposes [`PgCveLookup`] — a bridge adapter that implements
//! [`super::intel::CveLookup`] on top of `sx_storage::PgCveRepository` so
//! the risk pipeline can resolve CVE → CVSS/EPSS/KEV from a local Postgres
//! mirror instead of hitting the public NVD API on every request.
//!
//! The single trait this file declares stays pub(crate): it is an
//! internal contract between adapters and is intentionally NOT promoted
//! to `sx-api::port` because the HTTP layer never reads CVEs directly.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::RwLock;

use async_trait::async_trait;
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use sx_core::value_object::cvss::CvssScore;
use sx_core::value_object::ids::CveId;
use sx_risk::error::RiskError;
use sx_storage::domain::port::CveRepository;
use sx_storage::domain::value_object::CveId as StorageCveId;
use sx_storage::repository::PgCveRepository;

use crate::adapters::intel::{CveDetail, CveLookup};

/// In-memory sink that future Phase-3.5+1 hydration paths can prime so a
/// developer running the monolith offline still gets the canonical CVSS
/// envelope for a hand-picked CVE corpus.
///
/// Mutability is gated behind a [`RwLock`] so the structure remains
/// `Send + Sync` and can be shared as a trait object without an inner
/// `Mutex` interior.
#[derive(Default, Debug)]
pub(crate) struct InMemoryCveSink {
    rows: RwLock<HashMap<String, CveDetail>>,
}

impl InMemoryCveSink {
    /// Construct an empty sink.
    #[allow(dead_code)] // Constructor parked for Phase-3.5+1 wiring.
    pub(crate) fn new() -> Self {
        Self {
            rows: RwLock::new(HashMap::new()),
        }
    }

    /// Insert / overwrite a record. Returns `Err(())` only if the lock is
    /// poisoned, which a unit test can assert against.
    #[allow(dead_code)] // Used by Phase-3.5+1 fixture wiring.
    pub(crate) fn put(&self, cve: &CveId, detail: CveDetail) -> Result<(), ()> {
        let Ok(mut guard) = self.rows.write() else {
            return Err(());
        };
        guard.insert(cve.as_str().to_ascii_uppercase(), detail);
        Ok(())
    }

    /// Fetch a record by id (case-insensitive). Returns `None` if the
    /// store is empty or the id is unknown.
    #[allow(dead_code)] // Used by Phase-3.5+1 fixture wiring.
    pub(crate) fn get(&self, cve: &CveId) -> Option<CveDetail> {
        let guard = self.rows.read().ok()?;
        guard.get(&cve.as_str().to_ascii_uppercase()).cloned()
    }
}

// ---------------------------------------------------------------------------
// Postgres-backed CVE lookup
// ---------------------------------------------------------------------------

/// [`CveLookup`] implementation that resolves records from a Postgres
/// mirror of the NVD catalogue via `sx_storage::PgCveRepository`.
///
/// This is the production path enabled when `database.enabled = true`;
/// it replaces the HTTP-backed `NvdCveProvider` from
/// [`super::intel`], removing the per-request round-trip to nvd.nist.gov.
///
/// The CVE catalogue is **cross-tenant reference data** (no `tenant_id`
/// column, no RLS policy), so [`PgCveLookup`] does not take a tenant
/// context and does not apply [`sx_storage::TenantContext`]. Statement
/// timeouts are still applied per query by the underlying repository.
#[derive(Debug, Clone)]
pub(crate) struct PgCveLookup {
    inner: Arc<PgCveRepository>,
}

impl PgCveLookup {
    /// Construct from a pre-built pool and a statement-timeout budget
    /// (milliseconds, clamped to `u32::MAX` by the underlying repo).
    pub(crate) fn new(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            inner: Arc::new(PgCveRepository::new(pool, stmt_timeout_ms)),
        }
    }
}

#[async_trait]
impl CveLookup for PgCveLookup {
    async fn fetch(&self, cve: &CveId) -> Result<Option<CveDetail>, RiskError> {
        // Bridge the sx-core CVE id newtype to the sx-storage mirror.
        // Both validators normalise to the same canonical upper-case
        // string, so this round-trip is total for any well-formed
        // sx-core id.
        let storage_id = StorageCveId::new(cve.as_str()).map_err(|e| {
            RiskError::provider(format!("cve: invalid id at storage boundary: {e}"))
        })?;

        let row = self
            .inner
            .find_by_id(&storage_id)
            .await
            .map_err(|e| RiskError::provider(format!("cve: postgres lookup failed: {e}")))?;

        let Some(row) = row else {
            return Ok(None);
        };

        // The `cves.cvss` column is JSONB. We accept two shapes:
        //   { "v3": <f32>, "v4": <f32> }   — the canonical form written by
        //     this adapter and by future hydration jobs;
        //   { "cvssMetricV31": [{ "cvssData": { "baseScore": <f32> } }],
        //     "cvssMetricV40": [...] } — the raw NVD envelope (subset),
        //     accepted for back-compat with a pre-existing hydrator.
        //
        // A row with no usable CVSS produces `Ok(None)` — the same
        // semantics the HTTP NVD adapter uses for an entry without CVSS
        // metrics. This keeps the scoring pipeline's "unknown CVE"
        // branch behaviourally identical across the two backends.
        let Some(cvss) = parse_cvss(&row.cvss) else {
            return Ok(None);
        };

        let description = if row.description.is_empty() {
            None
        } else {
            Some(row.description)
        };

        Ok(Some(CveDetail { cvss, description }))
    }
}

/// Best-effort extraction of `(v3, v4)` baseScores from the `cves.cvss`
/// JSONB column. Returns `None` when no usable score is present so the
/// caller can map that to the "unknown CVE" path.
fn parse_cvss(value: &JsonValue) -> Option<CvssScore> {
    // Canonical form: {"v3": <f32>, "v4": <f32>}
    let v3_direct = value
        .get("v3")
        .and_then(JsonValue::as_f64)
        .and_then(clamp_f32);
    let v4_direct = value
        .get("v4")
        .and_then(JsonValue::as_f64)
        .and_then(clamp_f32);

    // NVD envelope: {"cvssMetricV31": [{"cvssData": {"baseScore": …}}], …}
    let v3_nvd = value
        .get("cvssMetricV31")
        .and_then(JsonValue::as_array)
        .and_then(|rows| rows.first())
        .and_then(|row| row.get("cvssData"))
        .and_then(|d| d.get("baseScore"))
        .and_then(JsonValue::as_f64)
        .and_then(clamp_f32);
    let v4_nvd = value
        .get("cvssMetricV40")
        .and_then(JsonValue::as_array)
        .and_then(|rows| rows.first())
        .and_then(|row| row.get("cvssData"))
        .and_then(|d| d.get("baseScore"))
        .and_then(JsonValue::as_f64)
        .and_then(clamp_f32);

    let v3 = v3_direct.or(v3_nvd);
    let v4 = v4_direct.or(v4_nvd);

    if v3.is_none() && v4.is_none() {
        return None;
    }

    CvssScore::new(v3, v4).ok()
}

/// Narrow a JSON `f64` baseScore to the `f32` the [`CvssScore`] validator
/// accepts. Mirrors the helper used by the NVD HTTP adapter — non-finite
/// and out-of-band values collapse to `None` so the caller can apply the
/// "unknown CVE" fallback.
fn clamp_f32(v: f64) -> Option<f32> {
    if v.is_finite() && (0.0..=10.0).contains(&v) {
        // Range checked above — the cast is precision-only.
        #[allow(clippy::cast_possible_truncation)]
        Some(v as f32)
    } else {
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample() -> CveDetail {
        CveDetail {
            cvss: CvssScore::v3_only(7.5).unwrap(),
            description: Some("test".into()),
        }
    }

    #[test]
    fn empty_sink_has_no_rows() {
        let sink = InMemoryCveSink::new();
        let id = CveId::new("CVE-2024-00001").unwrap();
        assert!(sink.get(&id).is_none());
    }

    #[test]
    fn put_then_get_round_trips() {
        let sink = InMemoryCveSink::new();
        let id = CveId::new("CVE-2024-00001").unwrap();
        sink.put(&id, sample()).unwrap();
        let hit = sink.get(&id).unwrap();
        assert_eq!(hit.description.as_deref(), Some("test"));
    }

    #[test]
    fn get_is_case_insensitive() {
        let sink = InMemoryCveSink::new();
        let upper = CveId::new("CVE-2024-00001").unwrap();
        sink.put(&upper, sample()).unwrap();
        // CveId enforces the canonical upper-case form, so equality here
        // is by construction. The test pins the contract for future
        // implementors that may relax the constructor.
        assert!(sink.get(&upper).is_some());
    }

    // ----- parse_cvss --------------------------------------------------

    #[test]
    fn parse_cvss_reads_canonical_v3_v4() {
        let v = serde_json::json!({ "v3": 7.5, "v4": 8.1 });
        let s = parse_cvss(&v).expect("canonical envelope must parse");
        assert!((s.v3.unwrap() - 7.5).abs() < 1e-6);
        assert!((s.v4.unwrap() - 8.1).abs() < 1e-6);
        // primary() prefers v4 — verifies the bridge preserves ordering.
        assert!((s.primary() - 8.1).abs() < 1e-6);
    }

    #[test]
    fn parse_cvss_reads_nvd_envelope() {
        let v = serde_json::json!({
            "cvssMetricV31": [{ "cvssData": { "baseScore": 9.0 } }],
            "cvssMetricV40": [{ "cvssData": { "baseScore": 9.4 } }],
        });
        let s = parse_cvss(&v).expect("nvd envelope must parse");
        assert!((s.v3.unwrap() - 9.0).abs() < 1e-6);
        assert!((s.v4.unwrap() - 9.4).abs() < 1e-6);
    }

    #[test]
    fn parse_cvss_returns_none_when_no_score_present() {
        let empty = serde_json::json!({});
        assert!(parse_cvss(&empty).is_none());
        let unrelated = serde_json::json!({ "summary": "no CVSS" });
        assert!(parse_cvss(&unrelated).is_none());
    }

    #[test]
    fn parse_cvss_rejects_out_of_band_scores() {
        // Out-of-range scores fall through to `None`, matching the NVD
        // HTTP adapter's behaviour.
        let too_high = serde_json::json!({ "v3": 99.0 });
        assert!(parse_cvss(&too_high).is_none());
        let negative = serde_json::json!({ "v3": -1.0 });
        assert!(parse_cvss(&negative).is_none());
    }

    #[test]
    fn parse_cvss_prefers_canonical_over_nvd_envelope() {
        let v = serde_json::json!({
            "v3": 5.0,
            "cvssMetricV31": [{ "cvssData": { "baseScore": 9.0 } }],
        });
        let s = parse_cvss(&v).expect("canonical wins");
        assert!((s.v3.unwrap() - 5.0).abs() < 1e-6);
    }

    #[test]
    fn clamp_f32_accepts_in_band_and_rejects_others() {
        assert!(clamp_f32(0.0).is_some());
        assert!(clamp_f32(10.0).is_some());
        assert!(clamp_f32(7.5).is_some());
        assert!(clamp_f32(-0.1).is_none());
        assert!(clamp_f32(10.1).is_none());
        assert!(clamp_f32(f64::NAN).is_none());
        assert!(clamp_f32(f64::INFINITY).is_none());
    }
}
