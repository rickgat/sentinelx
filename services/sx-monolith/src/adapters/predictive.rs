//! Predictive risk-classifier adapter.
//!
//! Wires the [`sx_ml::predictive`] GBDT model into the monolith. The
//! adapter:
//!
//! 1. Loads a hard-coded 3-tree forest fixture at build time (the
//!    `FIXTURE_FOREST_JSON` literal below). A pre-baked fixture lets the
//!    HTTP surface be wired before any training pipeline lands.
//! 2. Resolves the requested finding (plus its asset) through the same
//!    repository ports the rest of the HTTP layer already sees.
//! 3. Projects them into [`FindingFeatures`], runs the model, derives a
//!    `risk_band` via [`predictive_view::risk_band`], and returns the
//!    [`PredictResponse`].
//!
//! # 3-tree forest fixture
//!
//! Each tree is a single split on one of the headline features:
//!
//! - **Tree 0** — CVSS (slot 0). `<= 5.0` → `-1.0`; otherwise `+1.5`.
//! - **Tree 1** — KEV flag (slot 2). `<= 0.5` → `-0.5`; otherwise `+1.2`.
//! - **Tree 2** — EPSS (slot 1). `<= 0.5` → `-0.4`; otherwise `+1.0`.
//!
//! The raw forest scores are summed and squashed through the model's
//! sigmoid; the resulting probability sits comfortably above `0.75` for
//! findings with CVSS ≥ 9, KEV listed, and EPSS ≥ 0.5 (yielding a
//! `critical` band), and well below `0.25` for low-CVSS, non-KEV,
//! low-EPSS findings (`low` band). See the integration test at the
//! bottom of this file.

use std::sync::Arc;

use async_trait::async_trait;
use sx_api::port::{
    AssetRepositoryPort, EngagementPortError, FindingRepositoryPort, Phase3PortError,
    PredictivePort,
};
use sx_api::view::asset_view::AssetView;
use sx_api::view::finding_view::FindingView;
use sx_api::view::predictive_view::{risk_band, PredictResponse};
use sx_ml::predictive::{AssetViewLike, FindingFeatures, FindingViewLike, PredictiveModel};
use tracing::info;

/// JSON fixture for the 3-tree GBDT forest baked into the binary at build
/// time. Kept in one place so future agents can swap it for a real
/// trained model by replacing this literal.
///
/// Layout — see `FEATURE_VECTOR_LEN` in `sx_ml::predictive::features`:
///
/// | Slot | Name        |
/// |------|-------------|
/// | 0    | `cvss`      |
/// | 1    | `epss`      |
/// | 2    | `kev_flag`  |
///
/// Each tree carries one split + two leaves; the GBDT inference walker
/// sums the per-tree leaves and the model's sigmoid squashes the result.
const FIXTURE_FOREST_JSON: &str = r#"{
  "forest": {
    "trees": [
      {
        "splits": [{"feature_idx": 0, "threshold": 5.0, "left": -1, "right": -2}],
        "leaves": [-1.0, 1.5]
      },
      {
        "splits": [{"feature_idx": 2, "threshold": 0.5, "left": -1, "right": -2}],
        "leaves": [-0.5, 1.2]
      },
      {
        "splits": [{"feature_idx": 1, "threshold": 0.5, "left": -1, "right": -2}],
        "leaves": [-0.4, 1.0]
      }
    ],
    "bias": 0.0
  },
  "scaler": {"mean": [], "std": []}
}"#;

/// Bundle returned by [`build`]. Mirrors the other Phase-3 bundles for
/// shape consistency.
pub(crate) struct PredictiveBundle {
    /// Trait-object port handed to `AppState.predictive`.
    pub predict: Arc<dyn PredictivePort>,
}

/// Build the predictive bundle.
///
/// The fixture JSON is decoded once at boot. A malformed fixture is
/// surfaced as a built-in `PredictiveModel::default()` (uninformative
/// `0.5` prior) so the HTTP surface stays callable — the dependency on
/// the embedded literal is purely additive and we never panic on it.
pub(crate) fn build(
    findings: Arc<dyn FindingRepositoryPort>,
    assets: Arc<dyn AssetRepositoryPort>,
) -> PredictiveBundle {
    let model = PredictiveModel::from_json(FIXTURE_FOREST_JSON).unwrap_or_else(|err| {
        tracing::warn!(
            target = "adapters.predictive.fixture_invalid",
            error = %err,
            "predictive fixture failed to load; falling back to uninformative prior",
        );
        PredictiveModel::default()
    });
    let tree_count = model.forest.len();

    info!(
        target = "adapters.predictive.built",
        tree_count, "predictive bundle constructed",
    );

    PredictiveBundle {
        predict: Arc::new(PredictiveAdapter {
            model: Arc::new(model),
            findings,
            assets,
        }),
    }
}

/// Concrete adapter implementing [`PredictivePort`].
struct PredictiveAdapter {
    model: Arc<PredictiveModel>,
    findings: Arc<dyn FindingRepositoryPort>,
    assets: Arc<dyn AssetRepositoryPort>,
}

#[async_trait]
impl PredictivePort for PredictiveAdapter {
    async fn predict(
        &self,
        tenant_id: &str,
        finding_id: &str,
    ) -> Result<PredictResponse, Phase3PortError> {
        let finding = self
            .findings
            .get(tenant_id, finding_id)
            .await
            .map_err(map_engagement_error)?;
        let asset = self
            .assets
            .get(tenant_id, &finding.asset_id)
            .await
            .map_err(map_engagement_error)?;
        let features = features_from_views(&finding, &asset);
        let pred = self.model.predict(&features);
        Ok(PredictResponse {
            probability: pred.probability,
            confidence: pred.confidence,
            risk_band: risk_band(pred.probability).to_owned(),
        })
    }
}

/// Project the API wire views into the `sx-ml` feature shape, feeding
/// every slot the wire view actually exposes (see `FEATURE_SCHEMA` in
/// `sx_ml::predictive::features` for the full layout):
///
/// - `cvss` — from `finding.cvss`.
/// - `days_since_first_seen` — computed from the finding's `first_seen`
///   RFC3339 timestamp (clamped to `>= 0`), not a hard-coded `0`.
/// - `epss` — from `metadata.epss` when present, else `None` (neutral 0).
/// - `kev_flag` — from `metadata.kev` (bool) when present; otherwise falls
///   back to "the finding carries a CVE id" as a conservative proxy.
/// - `business_impact` / `chain_amplifier` — from `metadata`, default `1.0`.
/// - `severity` / `asset_kind` — the finding's severity tag and the asset's
///   kind tag (one-hot encoded downstream).
///
/// Bridging `sx_risk::RiskInput` (which carries the same signals from the
/// scoring path) is deferred until a caller on that path needs ML scoring —
/// there is no `RiskInput` at this `predict` call site today.
fn features_from_views(finding: &FindingView, asset: &AssetView) -> FindingFeatures {
    let meta = finding.metadata.as_ref();
    let finding_like = FindingViewLike {
        cvss: finding.cvss,
        epss: meta_f64(meta, "epss"),
        kev_flag: meta_bool(meta, "kev").unwrap_or_else(|| finding.cve_id.is_some()),
        severity: finding.severity.clone(),
        days_since_first_seen: days_since(&finding.first_seen),
        business_impact: meta_f64(meta, "business_impact").unwrap_or(1.0),
        chain_amplifier: meta_f64(meta, "chain_amplifier").unwrap_or(1.0),
    };
    let asset_like = AssetViewLike {
        kind: asset.kind.clone(),
    };
    FindingFeatures::from_views(&finding_like, &asset_like)
}

/// Read a finite `f64` from `metadata[key]`, if present.
fn meta_f64(meta: Option<&serde_json::Value>, key: &str) -> Option<f64> {
    meta.and_then(|m| m.get(key))
        .and_then(serde_json::Value::as_f64)
}

/// Read a bool from `metadata[key]`, if present.
fn meta_bool(meta: Option<&serde_json::Value>, key: &str) -> Option<bool> {
    meta.and_then(|m| m.get(key))
        .and_then(serde_json::Value::as_bool)
}

/// Whole days between an RFC3339 `first_seen` and now, clamped to `>= 0`.
/// Returns `0.0` when the timestamp is absent or unparseable (the neutral
/// "just seen" value the classifier treats as lowest-aging).
fn days_since(first_seen: &str) -> f64 {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    let Ok(seen) = OffsetDateTime::parse(first_seen, &Rfc3339) else {
        return 0.0;
    };
    let days = (OffsetDateTime::now_utc() - seen).whole_days();
    // Negative (future-dated) -> 0; u32 conversion avoids a precision-loss
    // cast and comfortably covers any realistic age.
    f64::from(u32::try_from(days).unwrap_or(0))
}

fn map_engagement_error(err: EngagementPortError) -> Phase3PortError {
    match err {
        EngagementPortError::NotFound => Phase3PortError::NotFound,
        EngagementPortError::Forbidden => Phase3PortError::Forbidden("forbidden".to_owned()),
        EngagementPortError::Conflict(msg) | EngagementPortError::Invalid(msg) => {
            Phase3PortError::Invalid(msg)
        }
        EngagementPortError::Dependency(msg) => Phase3PortError::Dependency(msg),
        EngagementPortError::Internal(msg) => Phase3PortError::Internal(msg),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::sync::Mutex;

    // --- helpers ----------------------------------------------------------

    #[derive(Default)]
    struct StubFindings {
        rows: Mutex<HashMap<(String, String), FindingView>>,
    }

    impl StubFindings {
        fn insert(&self, view: FindingView) {
            let key = (view.tenant_id.clone(), view.id.clone());
            self.rows.lock().unwrap().insert(key, view);
        }
    }

    #[async_trait]
    impl FindingRepositoryPort for StubFindings {
        async fn list(
            &self,
            _t: &str,
            _o: u64,
            _l: u32,
        ) -> Result<Vec<FindingView>, EngagementPortError> {
            Ok(vec![])
        }

        async fn get(&self, t: &str, id: &str) -> Result<FindingView, EngagementPortError> {
            self.rows
                .lock()
                .unwrap()
                .get(&(t.to_owned(), id.to_owned()))
                .cloned()
                .ok_or(EngagementPortError::NotFound)
        }

        async fn update_status(
            &self,
            _t: &str,
            _id: &str,
            _s: &str,
            _c: Option<&str>,
        ) -> Result<FindingView, EngagementPortError> {
            Err(EngagementPortError::NotFound)
        }
        async fn insert(&self, view: FindingView) -> Result<FindingView, EngagementPortError> {
            let key = (view.tenant_id.clone(), view.id.clone());
            self.rows.lock().unwrap().insert(key, view.clone());
            Ok(view)
        }
    }

    #[derive(Default)]
    struct StubAssets {
        rows: Mutex<HashMap<(String, String), AssetView>>,
    }

    impl StubAssets {
        fn insert(&self, view: AssetView) {
            let key = (view.tenant_id.clone(), view.id.clone());
            self.rows.lock().unwrap().insert(key, view);
        }
    }

    #[async_trait]
    impl AssetRepositoryPort for StubAssets {
        async fn list(
            &self,
            _t: &str,
            _o: u64,
            _l: u32,
        ) -> Result<Vec<AssetView>, EngagementPortError> {
            Ok(vec![])
        }

        async fn get(&self, t: &str, id: &str) -> Result<AssetView, EngagementPortError> {
            self.rows
                .lock()
                .unwrap()
                .get(&(t.to_owned(), id.to_owned()))
                .cloned()
                .ok_or(EngagementPortError::NotFound)
        }
    }

    fn finding(id: &str, tenant: &str, asset: &str, cvss: f64, kev: bool) -> FindingView {
        FindingView {
            id: id.into(),
            tenant_id: tenant.into(),
            asset_id: asset.into(),
            severity: "high".into(),
            status: "open".into(),
            title: "demo".into(),
            description: "demo finding".into(),
            cvss: Some(cvss),
            cve_id: if kev {
                Some("CVE-2024-1234".into())
            } else {
                None
            },
            first_seen: "2026-05-15T00:00:00Z".into(),
            last_seen: "2026-05-29T00:00:00Z".into(),
            metadata: None,
        }
    }

    fn asset(id: &str, tenant: &str, kind: &str) -> AssetView {
        AssetView {
            id: id.into(),
            tenant_id: tenant.into(),
            engagement_id: "engagement-1".into(),
            kind: kind.into(),
            identifier: "host.example.com".into(),
            source: "scan".into(),
            first_seen: "2026-05-15T00:00:00Z".into(),
            last_seen: "2026-05-29T00:00:00Z".into(),
            criticality: None,
        }
    }

    const TENANT: &str = "01010101-0101-0101-0101-010101010101";
    const FINDING_ID: &str = "f0000001-0000-0000-0000-000000000000";
    const ASSET_ID: &str = "a0000001-0000-0000-0000-000000000000";

    // --- tests ------------------------------------------------------------

    #[test]
    fn fixture_forest_loads_with_three_trees() {
        let model = PredictiveModel::from_json(FIXTURE_FOREST_JSON)
            .expect("fixture JSON must decode cleanly");
        assert_eq!(model.forest.len(), 3, "fixture forest must have 3 trees");
    }

    #[tokio::test]
    async fn predict_returns_not_found_when_finding_missing() {
        let findings = Arc::new(StubFindings::default());
        let assets = Arc::new(StubAssets::default());
        let bundle = build(
            Arc::clone(&findings) as Arc<dyn FindingRepositoryPort>,
            Arc::clone(&assets) as Arc<dyn AssetRepositoryPort>,
        );
        let err = bundle
            .predict
            .predict(TENANT, "missing-finding")
            .await
            .expect_err("expected NotFound");
        assert!(matches!(err, Phase3PortError::NotFound));
    }

    #[tokio::test]
    async fn predict_returns_not_found_when_asset_missing() {
        let findings = Arc::new(StubFindings::default());
        findings.insert(finding(FINDING_ID, TENANT, "ghost-asset", 9.5, true));
        let assets = Arc::new(StubAssets::default());
        let bundle = build(
            Arc::clone(&findings) as Arc<dyn FindingRepositoryPort>,
            Arc::clone(&assets) as Arc<dyn AssetRepositoryPort>,
        );
        let err = bundle
            .predict
            .predict(TENANT, FINDING_ID)
            .await
            .expect_err("expected NotFound for missing asset");
        assert!(matches!(err, Phase3PortError::NotFound));
    }

    #[tokio::test]
    async fn predict_passes_features_through_model_for_low_risk() {
        // Low CVSS, no KEV, default EPSS -> probability should sit in low band.
        let findings = Arc::new(StubFindings::default());
        findings.insert(finding(FINDING_ID, TENANT, ASSET_ID, 1.0, false));
        let assets = Arc::new(StubAssets::default());
        assets.insert(asset(ASSET_ID, TENANT, "host"));
        let bundle = build(
            Arc::clone(&findings) as Arc<dyn FindingRepositoryPort>,
            Arc::clone(&assets) as Arc<dyn AssetRepositoryPort>,
        );
        let resp = bundle
            .predict
            .predict(TENANT, FINDING_ID)
            .await
            .expect("must succeed");
        assert!(
            resp.probability >= 0.0 && resp.probability <= 1.0,
            "probability must be in [0,1], got {}",
            resp.probability
        );
        assert!(
            resp.probability < 0.5,
            "low-CVSS/no-KEV/low-EPSS must score below 0.5, got {}",
            resp.probability,
        );
        assert!(
            resp.risk_band == "low" || resp.risk_band == "medium",
            "expected low/medium band, got {}",
            resp.risk_band
        );
    }

    #[tokio::test]
    async fn predict_integration_high_cvss_finding_produces_high_risk_band() {
        // High CVSS + KEV-listed CVE -> raw forest score is well into the
        // positive region, sigmoid puts us into high/critical band.
        let findings = Arc::new(StubFindings::default());
        findings.insert(finding(FINDING_ID, TENANT, ASSET_ID, 9.8, true));
        let assets = Arc::new(StubAssets::default());
        assets.insert(asset(ASSET_ID, TENANT, "host"));
        let bundle = build(
            Arc::clone(&findings) as Arc<dyn FindingRepositoryPort>,
            Arc::clone(&assets) as Arc<dyn AssetRepositoryPort>,
        );
        let resp = bundle
            .predict
            .predict(TENANT, FINDING_ID)
            .await
            .expect("must succeed");
        assert!(
            resp.probability >= 0.5,
            "high-CVSS + KEV must score >= 0.5, got {}",
            resp.probability,
        );
        assert!(
            resp.risk_band == "high" || resp.risk_band == "critical",
            "expected high or critical band, got {}",
            resp.risk_band
        );
    }
}
