//! Risk-scoring adapter.
//!
//! Wires `sx-risk`'s [`CalculateRiskUseCase`] behind the [`CalculateRiskPort`].
//!
//! ## Pipelines
//!
//! The adapter exposes two flows:
//!
//! ### Single-finding scoring — [`CalculateRiskPort::calculate`]
//!
//! Selected by the presence of `cve_id` on the incoming
//! [`CalculateRiskRequest`]:
//!
//! 1. `cve_id = None` — the legacy Phase-0 path. A deterministic synthetic
//!    [`RiskCalculationInput`] is fed into the composite scorer so
//!    historical smoke tests continue to work.
//! 2. `cve_id = Some(id)` — the real pipeline:
//!    - validate / parse the id via [`CveId::new`],
//!    - resolve the canonical CVSS envelope via the [`CveLookup`] port
//!      (HTTP-backed at the composition root, with a 24-hour cache),
//!    - delegate EPSS + KEV resolution to the use case (it will call
//!      the providers held on this adapter when those fields are `None`).
//!
//! ### Engagement aggregate — [`CalculateRiskPort::calculate_engagement`]
//!
//! Phase-3.5 added a per-engagement aggregate flow that:
//!
//! 1. Pages through every finding owned by `tenant_id` via the injected
//!    [`FindingRepositoryPort`] (page size = [`FINDING_PAGE_SIZE`]).
//! 2. For each finding that carries a `cve_id`, parses the id and calls
//!    [`CalculateRiskUseCase::execute`].
//! 3. Folds the per-finding scores into an
//!    [`EngagementRiskBreakdownView`] (`max_score`, `average_score`,
//!    severity histogram, and the top-N findings by score).
//!
//! ## Asset-context resolution (Phase-3.5+1)
//!
//! When a finding carries a non-empty `asset_id`, the engagement aggregate
//! resolves the asset row via the injected
//! [`AssetRepositoryPort`] and hydrates the per-finding
//! [`RiskCalculationInput`] from the returned [`AssetView`]:
//!
//! * `exposure_level` is parsed from
//!   [`AssetView::source`]. The current `AssetView` schema does not surface
//!   a dedicated `tags` map, so the Postgres adapter overloads `source`
//!   with the `assets.exposure` column value. Recognised string forms
//!   (case-insensitive): `"internet"`, `"internal"`, `"isolated"`,
//!   `"unknown"`. Any other value, or an empty `asset_id`, or a missing
//!   row falls back to [`ExposureLevel::Internet`] — the most pessimistic
//!   default (matches the Phase-1 behaviour the rest of the pipeline
//!   already encodes).
//! * `criticality` is sourced from `AssetView::criticality` (`Option<String>`),
//!   parsed via [`sx_core::value_object::criticality::parse_criticality`].
//!   When the column is `None` (row pre-dates the migration) or the value is
//!   unrecognised, the scorer falls back to [`AssetCriticality::Production`]
//!   for Phase-1 behavioural parity.
//! * `business_impact` and `chain_amplifier` are resolved from the
//!   finding's `metadata` blob (see [`extract_factor`]). Absent, missing,
//!   non-numeric, or out-of-range (`[0.5, 5.0]`) entries fall back to the
//!   `1.0` identity factor — which in turn maps to `BusinessImpact::Medium`
//!   and `ChainAmplifier::identity()`, preserving Phase-1 behaviour for
//!   findings that ship without metadata.
//!
//! Asset-repo failures (timeout, decode error, not-found) are logged at
//! `warn` and the per-finding scorer falls back to the Phase-1 defaults
//! so the aggregate stays a best-effort projection.

use std::cmp::Ordering;
use std::sync::Arc;

use async_trait::async_trait;
use sx_api::port::{
    AssetRepositoryPort, CalculateRiskPort, EngagementPortError, FindingRepositoryPort,
    RiskPortError,
};
use sx_api::view::asset_view::AssetView;
use sx_api::view::finding_view::FindingView;
use sx_api::view::risk_view::{
    CalculateEngagementRiskRequest, CalculateRiskRequest, CalculateRiskView,
    EngagementRiskBreakdownView, FindingRisk, RiskBreakdownView, SeverityCounts,
};
use sx_config::schema::risk::RiskConfig as LoaderRiskConfig;
use sx_core::value_object::{
    criticality::{parse_criticality, AssetCriticality},
    cvss::CvssScore,
    epss::EpssScore,
    exposure::ExposureLevel,
    ids::CveId,
    severity::Severity,
    severity::SeverityBands,
};
use sx_risk::controller::{CalculateRiskUseCase, RiskCalculationInput};
use sx_risk::model::{BusinessImpact, ChainAmplifier, RiskScoringConfig};
use sx_risk::service::{CompositeScorer, EpssProvider, KevProvider};
use sx_risk::view::RiskBreakdownView as DomainRiskBreakdownView;
use sx_risk::RiskError;

use crate::adapters::intel::{CveDetail, CveLookup};

/// Page size used when iterating findings during the engagement-aggregate
/// flow. Chosen to balance round-trip count against per-page allocation.
const FINDING_PAGE_SIZE: u32 = 200;

/// Build the risk adapter. When `intel` is `Some`, the supplied EPSS / KEV /
/// CVE providers are used; otherwise null providers (which return `None` /
/// `false`) are wired in (current Phase-0 fallback for environments without
/// outbound HTTP).
///
/// `findings` is the read-side repository used by the engagement-aggregate
/// flow; it is held even when the request never reaches that path so the
/// adapter object stays a single trait object on `AppState`.
///
/// `assets` is the read-side repository used during the engagement
/// aggregate to hydrate per-finding asset context (exposure level). The
/// reference is held even when a tenant never reaches the aggregate path
/// — same single-trait-object shape on `AppState`.
///
/// `cve_lookup_override`, when `Some`, replaces the [`CveLookup`] resolved
/// from `intel`. This is the seam used by `build_app_state` to swap the
/// HTTP-backed NVD provider for the Postgres-backed
/// [`crate::adapters::cve::PgCveLookup`] when `database.enabled = true`.
/// EPSS + KEV providers continue to come from the intel bundle even when
/// the override is set so the upstream feeds remain authoritative for
/// those two dimensions.
pub(crate) fn build(
    _risk_cfg: &LoaderRiskConfig,
    intel: Option<crate::adapters::intel::IntelBundle>,
    findings: Arc<dyn FindingRepositoryPort>,
    assets: Arc<dyn AssetRepositoryPort>,
    cve_lookup_override: Option<Arc<dyn CveLookup>>,
) -> anyhow::Result<Arc<dyn CalculateRiskPort>> {
    let scoring = RiskScoringConfig::sentinelx_default()
        .map_err(|e| anyhow::anyhow!("risk default config invalid: {e}"))?;
    let bands = SeverityBands::new(0.1, 4.0, 7.0, 9.0)
        .map_err(|e| anyhow::anyhow!("severity bands invalid: {e}"))?;
    let scorer = CompositeScorer::new(scoring, bands)
        .map_err(|e| anyhow::anyhow!("composite scorer init: {e}"))?;

    let (epss, kev, cve_default): (
        Arc<dyn EpssProvider>,
        Arc<dyn KevProvider>,
        Arc<dyn CveLookup>,
    ) = match intel {
        Some(b) => (b.epss, b.kev, b.cve),
        None => (Arc::new(NullEpss), Arc::new(NullKev), Arc::new(NullCve)),
    };
    let cve = cve_lookup_override.unwrap_or(cve_default);
    let usecase = CalculateRiskUseCase::new(scorer, Arc::new(DynEpss(epss)), Arc::new(DynKev(kev)));
    Ok(Arc::new(RiskAdapter {
        uc: usecase,
        cve,
        findings,
        assets,
    }))
}

/// Thin trait-object wrapper so the use case's `E: EpssProvider` generic
/// (which is `Sized`) can hold either real or stub providers.
#[derive(Debug)]
struct DynEpss(Arc<dyn EpssProvider>);

#[async_trait]
impl EpssProvider for DynEpss {
    async fn fetch(&self, cve: &CveId) -> Result<Option<EpssScore>, RiskError> {
        self.0.fetch(cve).await
    }
}

/// Trait-object wrapper for [`KevProvider`].
#[derive(Debug)]
struct DynKev(Arc<dyn KevProvider>);

#[async_trait]
impl KevProvider for DynKev {
    async fn is_known_exploited(&self, cve: &CveId) -> Result<bool, RiskError> {
        self.0.is_known_exploited(cve).await
    }
}

/// Composite adapter wiring `sx-risk`'s use case with the upstream
/// [`CveLookup`] port for canonical CVSS retrieval, the
/// [`FindingRepositoryPort`] for the engagement aggregate, and the
/// [`AssetRepositoryPort`] for asset-context hydration.
struct RiskAdapter {
    uc: CalculateRiskUseCase<DynEpss, DynKev>,
    cve: Arc<dyn CveLookup>,
    findings: Arc<dyn FindingRepositoryPort>,
    assets: Arc<dyn AssetRepositoryPort>,
}

#[async_trait]
impl CalculateRiskPort for RiskAdapter {
    async fn calculate(
        &self,
        req: CalculateRiskRequest,
    ) -> Result<CalculateRiskView, RiskPortError> {
        let breakdown = match req.cve_id.as_ref() {
            Some(raw) => self.run_real_pipeline(raw).await?,
            None => self.uc.execute(synthetic_input()).await.map_err(map_err)?,
        };
        Ok(translate(req.engagement_id, &breakdown))
    }

    async fn calculate_engagement(
        &self,
        tenant_id: &str,
        engagement_id: &str,
        req: CalculateEngagementRiskRequest,
    ) -> Result<EngagementRiskBreakdownView, RiskPortError> {
        let mut acc = AggregateAccumulator::new();
        let mut offset: u64 = 0;
        loop {
            let page = self
                .findings
                .list(tenant_id, offset, FINDING_PAGE_SIZE)
                .await
                .map_err(map_repo_err)?;
            if page.is_empty() {
                break;
            }
            let n = page.len() as u64;
            for finding in page {
                self.fold_finding(&mut acc, &finding, req.include_unscored)
                    .await;
            }
            // Defensive stop: if the repository returned fewer rows than
            // we asked for, the next page would be empty.
            if n < u64::from(FINDING_PAGE_SIZE) {
                break;
            }
            offset = offset.saturating_add(n);
        }
        Ok(acc.finalize(engagement_id, req.top_n))
    }
}

impl RiskAdapter {
    /// Real flow: look up the CVE, delegate scoring to the use case.
    ///
    /// The single-finding path does not have an asset binding, so it
    /// continues to use the Phase-1 default asset context (Internet /
    /// Production / Medium / identity). The engagement-aggregate flow is
    /// the one that hydrates per-asset context.
    async fn run_real_pipeline(
        &self,
        raw_cve: &str,
    ) -> Result<DomainRiskBreakdownView, RiskPortError> {
        let cve_id = CveId::new(raw_cve)
            .map_err(|e| RiskPortError::Invalid(format!("invalid cve_id: {e}")))?;
        let detail = self
            .cve
            .fetch(&cve_id)
            .await
            .map_err(map_err)?
            .ok_or(RiskPortError::NotFound)?;
        // The single-finding flow has no `FindingView` to read metadata
        // from, so it uses the identity factors (`1.0`) which the helpers
        // below map to `BusinessImpact::Medium` and
        // `ChainAmplifier::identity()`.
        let input = real_input(
            cve_id,
            &detail,
            ExposureLevel::Internet,
            AssetCriticality::Production,
            1.0,
            1.0,
        );
        self.uc.execute(input).await.map_err(map_err)
    }

    /// Score a single finding inside the aggregate flow.
    ///
    /// Findings without a `cve_id` are counted in `total_findings` only
    /// when `include_unscored` is `true`. Findings whose CVE cannot be
    /// parsed or resolved are silently skipped (the aggregate is a
    /// best-effort projection — a single bad row must not poison the
    /// whole engagement view).
    async fn fold_finding(
        &self,
        acc: &mut AggregateAccumulator,
        finding: &FindingView,
        include_unscored: bool,
    ) {
        let Some(raw_cve) = finding.cve_id.as_deref() else {
            if include_unscored {
                acc.bump_total();
            }
            return;
        };
        acc.bump_total();

        let Ok(cve_id) = CveId::new(raw_cve) else {
            tracing::warn!(
                finding_id = finding.id.as_str(),
                cve_id = raw_cve,
                "risk.aggregate.skip.invalid_cve"
            );
            return;
        };

        let detail = match self.cve.fetch(&cve_id).await {
            Ok(Some(d)) => d,
            Ok(None) => {
                tracing::debug!(cve = cve_id.as_str(), "risk.aggregate.skip.cve_not_found");
                return;
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    cve = cve_id.as_str(),
                    "risk.aggregate.skip.cve_lookup_failed"
                );
                return;
            }
        };

        // Hydrate asset context. A finding without an `asset_id` (or one
        // whose asset row cannot be resolved) falls back to the Phase-1
        // defaults so the aggregate stays best-effort.
        let (exposure, criticality) = self
            .resolve_asset_context(&finding.tenant_id, &finding.asset_id)
            .await;

        // Resolve risk multipliers from the finding's metadata blob.
        // `extract_factor` is the single chokepoint that validates the
        // numeric range — see its docstring for the contract.
        let business_impact = extract_factor(finding, "business_impact");
        let chain_amplifier = extract_factor(finding, "chain_amplifier");

        let view = match self
            .uc
            .execute(real_input(
                cve_id,
                &detail,
                exposure,
                criticality,
                business_impact,
                chain_amplifier,
            ))
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    finding_id = finding.id.as_str(),
                    "risk.aggregate.skip.score_failed"
                );
                return;
            }
        };

        acc.push(FindingRisk {
            finding_id: finding.id.clone(),
            cve_id: finding.cve_id.clone(),
            score: view.score,
            severity: view.severity.to_string(),
        });
        acc.bump_severity(view.severity);
    }

    /// Hydrate asset context for the aggregate flow.
    ///
    /// Returns `(exposure, criticality)`. The defaults — `Internet` /
    /// `Production` — match the documented Phase-1 fallbacks and are
    /// applied when:
    ///
    /// * `asset_id` is empty,
    /// * the asset repo returns `NotFound` or any error,
    /// * the asset's [`AssetView::source`] does not parse to a known
    ///   [`ExposureLevel`] (see [`parse_exposure`]),
    /// * the asset's [`AssetView::criticality`] is `None` (row pre-dates
    ///   the column being surfaced) or does not parse to a known
    ///   [`AssetCriticality`] (see [`parse_criticality`]).
    ///
    /// `criticality` is sourced from `AssetView::criticality` and parsed
    /// via [`parse_criticality`]; the `Production` fallback preserves
    /// Phase-1 behaviour for unmigrated rows.
    async fn resolve_asset_context(
        &self,
        tenant_id: &str,
        asset_id: &str,
    ) -> (ExposureLevel, AssetCriticality) {
        // `business_impact` and `chain_amplifier` are sourced from the
        // finding's metadata blob (see [`extract_factor`]), not from the
        // asset row, so they are not part of this lookup.
        let default = (ExposureLevel::Internet, AssetCriticality::Production);
        if asset_id.is_empty() {
            return default;
        }
        match self.assets.get(tenant_id, asset_id).await {
            Ok(view) => {
                let exposure = parse_exposure(&view).unwrap_or(default.0);
                let criticality = parse_criticality(view.criticality.as_deref().unwrap_or(""))
                    .unwrap_or(default.1);
                (exposure, criticality)
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    tenant_id,
                    asset_id,
                    "risk.aggregate.asset_lookup_failed_using_defaults"
                );
                default
            }
        }
    }
}

/// Parse an [`AssetView`] into an [`ExposureLevel`].
///
/// The wire schema does not yet carry a dedicated `tags` map, so the
/// Postgres adapter overloads [`AssetView::source`] with the
/// `assets.exposure` column. Returns `None` when the field is empty or
/// when the string does not match a known variant — the caller then
/// applies the Phase-1 default.
fn parse_exposure(view: &AssetView) -> Option<ExposureLevel> {
    match view.source.trim().to_ascii_lowercase().as_str() {
        "internet" => Some(ExposureLevel::Internet),
        "internal" => Some(ExposureLevel::Internal),
        "isolated" => Some(ExposureLevel::Isolated),
        "unknown" => Some(ExposureLevel::Unknown),
        _ => None,
    }
}

/// Folds per-finding results into the engagement breakdown.
#[derive(Debug, Default)]
struct AggregateAccumulator {
    total_findings: u32,
    scored: u32,
    sum: f64,
    max_score: f64,
    severity_counts: SeverityCounts,
    items: Vec<FindingRisk>,
}

impl AggregateAccumulator {
    fn new() -> Self {
        Self::default()
    }

    fn bump_total(&mut self) {
        self.total_findings = self.total_findings.saturating_add(1);
    }

    fn bump_severity(&mut self, sev: Severity) {
        match sev {
            Severity::Critical => {
                self.severity_counts.critical = self.severity_counts.critical.saturating_add(1);
            }
            Severity::High => {
                self.severity_counts.high = self.severity_counts.high.saturating_add(1);
            }
            Severity::Medium => {
                self.severity_counts.medium = self.severity_counts.medium.saturating_add(1);
            }
            Severity::Low => {
                self.severity_counts.low = self.severity_counts.low.saturating_add(1);
            }
            Severity::Info => {
                self.severity_counts.info = self.severity_counts.info.saturating_add(1);
            }
        }
    }

    fn push(&mut self, item: FindingRisk) {
        // `bump_total` is the caller's responsibility — `push` only
        // touches the `scored` aggregates.
        self.scored = self.scored.saturating_add(1);
        if item.score > self.max_score {
            self.max_score = item.score;
        }
        self.sum += item.score;
        self.items.push(item);
    }

    fn finalize(self, engagement_id: &str, top_n: u32) -> EngagementRiskBreakdownView {
        let average_score = if self.scored == 0 {
            0.0
        } else {
            self.sum / f64::from(self.scored)
        };

        let mut items = self.items;
        items.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(Ordering::Equal));
        items.truncate(top_n as usize);

        EngagementRiskBreakdownView {
            engagement_id: engagement_id.to_owned(),
            total_findings: self.total_findings,
            scored: self.scored,
            max_score: self.max_score,
            average_score,
            severity_counts: self.severity_counts,
            top: items,
        }
    }
}

/// Translate the internal [`DomainRiskBreakdownView`] into the wire DTO.
#[allow(clippy::missing_const_for_fn)] // `String` field move is not `const`
fn translate(engagement_id: String, breakdown: &DomainRiskBreakdownView) -> CalculateRiskView {
    CalculateRiskView {
        engagement_id,
        composite_score: breakdown.score,
        components: RiskBreakdownView {
            cvss: breakdown.components.severity_part,
            epss: breakdown.components.exploit_part,
            exposure: breakdown.components.exposure_part,
            criticality: breakdown.components.criticality_part,
        },
    }
}

/// Build a [`RiskCalculationInput`] from upstream NVD data, the hydrated
/// asset context, and the per-finding risk multipliers.
///
/// EPSS / KEV are left `None` so the use case fetches them via the
/// providers wired on the adapter. `business_impact_factor` and
/// `chain_amplifier_factor` are the f64 multipliers returned by
/// [`extract_factor`] — both already in `[0.5, 5.0] ∪ {1.0}`. They are
/// mapped onto the typed enums consumed by the scorer via
/// [`bin_business_impact`] and [`clamp_chain_amplifier`].
fn real_input(
    cve: CveId,
    detail: &CveDetail,
    exposure: ExposureLevel,
    criticality: AssetCriticality,
    business_impact_factor: f64,
    chain_amplifier_factor: f64,
) -> RiskCalculationInput {
    RiskCalculationInput {
        cve,
        cvss: Some(detail.cvss),
        severity_hint: None,
        epss: None,
        kev: None,
        exposure,
        criticality,
        business_impact: bin_business_impact(business_impact_factor),
        chain_amplifier: clamp_chain_amplifier(chain_amplifier_factor),
    }
}

/// Read a numeric factor from finding metadata. Out-of-range or absent
/// values fall back to `1.0`. Range is `[0.5, 5.0]` — anything outside
/// that band is treated as adversarial input and ignored.
///
/// Non-numeric values, missing keys, missing or non-object metadata, and
/// `NaN` / `±inf` all collapse to the `1.0` identity factor so the rest
/// of the pipeline can stay infallible.
fn extract_factor(view: &FindingView, key: &str) -> f64 {
    let raw = view
        .metadata
        .as_ref()
        .and_then(|m| m.get(key))
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(1.0);
    if raw.is_finite() && (0.5..=5.0).contains(&raw) {
        raw
    } else {
        1.0
    }
}

/// Bin the f64 `business_impact` factor onto the [`BusinessImpact`] enum.
///
/// The mapping preserves the Phase-1 default: a factor of `1.0` (which is
/// what [`extract_factor`] returns when metadata is absent) maps to
/// [`BusinessImpact::Medium`], the historical default. Higher factors lift
/// the bin; lower factors drop it. Boundaries are half-open on the upper
/// side so each band is exclusive.
fn bin_business_impact(factor: f64) -> BusinessImpact {
    if factor < 1.0 {
        BusinessImpact::Low
    } else if factor < 2.0 {
        BusinessImpact::Medium
    } else if factor < 3.5 {
        BusinessImpact::High
    } else {
        BusinessImpact::Critical
    }
}

/// Clamp the f64 `chain_amplifier` factor onto the [`ChainAmplifier`]
/// newtype's accepted band (`[1.0, 2.0]`).
///
/// The extracted factor already lives in `[0.5, 5.0]` (or `1.0` when
/// absent), so a simple [`f64::clamp`] is sufficient. Construction cannot
/// fail because the clamped value is always a finite number in band, but
/// a defensive fallback to [`ChainAmplifier::identity`] keeps the function
/// total without `unwrap`.
fn clamp_chain_amplifier(factor: f64) -> ChainAmplifier {
    let clamped = factor.clamp(1.0, 2.0);
    ChainAmplifier::new(clamped).unwrap_or_else(|_| ChainAmplifier::identity())
}

fn synthetic_input() -> RiskCalculationInput {
    // Fixed inputs documented as a Phase-0 stand-in: the pipeline is
    // exercised end-to-end with deterministic CVSS / EPSS / KEV values so
    // operators can validate the composite math against a known answer.
    // The CVE literal is statically valid; `expect` documents the
    // unreachable failure mode — see the crate-level `expect_used` allow
    // in `main.rs`.
    RiskCalculationInput {
        cve: CveId::new("CVE-1970-0001").expect("static CVE id is well-formed"),
        cvss: CvssScore::v3_only(7.5).ok(),
        severity_hint: None,
        epss: EpssScore::new(0.10, 0.80).ok(),
        kev: Some(false),
        exposure: ExposureLevel::Internal,
        criticality: AssetCriticality::Production,
        business_impact: BusinessImpact::Medium,
        chain_amplifier: ChainAmplifier::identity(),
    }
}

fn map_err(e: RiskError) -> RiskPortError {
    match e {
        RiskError::InvalidInput(m) => RiskPortError::Invalid(m),
        _ => RiskPortError::Internal(e.to_string()),
    }
}

fn map_repo_err(e: EngagementPortError) -> RiskPortError {
    match e {
        EngagementPortError::NotFound => RiskPortError::NotFound,
        EngagementPortError::Invalid(m) => RiskPortError::Invalid(m),
        EngagementPortError::Forbidden
        | EngagementPortError::Conflict(_)
        | EngagementPortError::Dependency(_)
        | EngagementPortError::Internal(_) => RiskPortError::Internal(e.to_string()),
    }
}

// ----- Stub providers ----------------------------------------------------

#[derive(Debug)]
struct NullEpss;

#[async_trait]
impl EpssProvider for NullEpss {
    async fn fetch(&self, _cve: &CveId) -> Result<Option<EpssScore>, RiskError> {
        Ok(None)
    }
}

#[derive(Debug)]
struct NullKev;

#[async_trait]
impl KevProvider for NullKev {
    async fn is_known_exploited(&self, _cve: &CveId) -> Result<bool, RiskError> {
        Ok(false)
    }
}

/// Phase-0 fallback CVE lookup: always reports "unknown".
#[derive(Debug)]
struct NullCve;

#[async_trait]
impl CveLookup for NullCve {
    async fn fetch(&self, _cve: &CveId) -> Result<Option<CveDetail>, RiskError> {
        Ok(None)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use std::sync::Mutex;

    /// Mock [`CveLookup`] producing a fixed response and counting calls.
    #[derive(Debug)]
    struct MockCve {
        response: Result<Option<CveDetail>, RiskError>,
        calls: AtomicUsize,
    }

    impl MockCve {
        fn new(response: Result<Option<CveDetail>, RiskError>) -> Self {
            Self {
                response,
                calls: AtomicUsize::new(0),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(AtomicOrdering::SeqCst)
        }
    }

    #[async_trait]
    impl CveLookup for MockCve {
        async fn fetch(&self, _cve: &CveId) -> Result<Option<CveDetail>, RiskError> {
            self.calls.fetch_add(1, AtomicOrdering::SeqCst);
            match &self.response {
                Ok(Some(d)) => Ok(Some(d.clone())),
                Ok(None) => Ok(None),
                Err(e) => Err(e.clone()),
            }
        }
    }

    /// Map of (cve string, CveDetail) — used by [`MapCve`].
    #[derive(Debug, Default)]
    struct MapCve {
        rows: std::collections::HashMap<String, CveDetail>,
    }

    impl MapCve {
        fn with(rows: Vec<(&str, f32)>) -> Self {
            let mut m = std::collections::HashMap::new();
            for (id, score) in rows {
                m.insert(
                    id.to_owned(),
                    CveDetail {
                        cvss: CvssScore::v3_only(score).unwrap(),
                        description: None,
                    },
                );
            }
            Self { rows: m }
        }
    }

    #[async_trait]
    impl CveLookup for MapCve {
        async fn fetch(&self, cve: &CveId) -> Result<Option<CveDetail>, RiskError> {
            Ok(self.rows.get(cve.as_str()).cloned())
        }
    }

    /// Mock [`FindingRepositoryPort`] that returns a fixed list once.
    #[derive(Debug)]
    struct MockFindings {
        rows: Mutex<Vec<FindingView>>,
    }

    impl MockFindings {
        fn new(rows: Vec<FindingView>) -> Self {
            Self {
                rows: Mutex::new(rows),
            }
        }
    }

    #[async_trait]
    impl FindingRepositoryPort for MockFindings {
        async fn list(
            &self,
            _t: &str,
            offset: u64,
            limit: u32,
        ) -> Result<Vec<FindingView>, EngagementPortError> {
            let guard = self.rows.lock().unwrap();
            Ok(guard
                .iter()
                .skip(offset as usize)
                .take(limit as usize)
                .cloned()
                .collect())
        }

        async fn get(&self, _t: &str, _i: &str) -> Result<FindingView, EngagementPortError> {
            Err(EngagementPortError::NotFound)
        }

        async fn update_status(
            &self,
            _t: &str,
            _i: &str,
            _s: &str,
            _c: Option<&str>,
        ) -> Result<FindingView, EngagementPortError> {
            Err(EngagementPortError::NotFound)
        }
        async fn insert(&self, view: FindingView) -> Result<FindingView, EngagementPortError> {
            self.rows.lock().unwrap().push(view.clone());
            Ok(view)
        }
    }

    /// Mock [`AssetRepositoryPort`].
    ///
    /// Keyed by `asset_id`. The `source` field stands in for the future
    /// `tags["sx.exposure"]` entry — see the module docblock. An asset id
    /// not present in the map yields `EngagementPortError::NotFound`,
    /// exercising the default-fallback path.
    #[derive(Debug, Default)]
    struct MockAssets {
        rows: std::collections::HashMap<String, AssetView>,
    }

    impl MockAssets {
        fn empty() -> Self {
            Self::default()
        }

        fn with_exposure(asset_id: &str, exposure: &str) -> Self {
            let mut rows = std::collections::HashMap::new();
            rows.insert(asset_id.to_owned(), asset_view(asset_id, exposure));
            Self { rows }
        }

        fn with_view(view: AssetView) -> Self {
            let mut rows = std::collections::HashMap::new();
            rows.insert(view.id.clone(), view);
            Self { rows }
        }
    }

    /// Asset repo that always errors — used to exercise the
    /// repo-failure → fallback path of [`resolve_asset_context`].
    #[derive(Debug, Default)]
    struct FailingAssets;

    #[async_trait]
    impl AssetRepositoryPort for FailingAssets {
        async fn list(
            &self,
            _t: &str,
            _offset: u64,
            _limit: u32,
        ) -> Result<Vec<AssetView>, EngagementPortError> {
            Err(EngagementPortError::Internal("boom".into()))
        }

        async fn get(&self, _t: &str, _id: &str) -> Result<AssetView, EngagementPortError> {
            Err(EngagementPortError::Internal("boom".into()))
        }
    }

    #[async_trait]
    impl AssetRepositoryPort for MockAssets {
        async fn list(
            &self,
            _t: &str,
            _offset: u64,
            _limit: u32,
        ) -> Result<Vec<AssetView>, EngagementPortError> {
            Ok(self.rows.values().cloned().collect())
        }

        async fn get(&self, _t: &str, id: &str) -> Result<AssetView, EngagementPortError> {
            self.rows
                .get(id)
                .cloned()
                .ok_or(EngagementPortError::NotFound)
        }
    }

    fn asset_view(id: &str, exposure: &str) -> AssetView {
        AssetView {
            id: id.to_owned(),
            tenant_id: "tenant-1".into(),
            engagement_id: "eng-1".into(),
            kind: "host".into(),
            identifier: format!("{id}.example.com"),
            // Postgres adapter overloads `source` with the
            // `assets.exposure` column; the adapter reads from here.
            source: exposure.to_owned(),
            criticality: None,
            first_seen: "1970-01-01T00:00:00Z".into(),
            last_seen: "1970-01-01T00:00:00Z".into(),
        }
    }

    /// Build an [`AssetView`] with an explicit `criticality` string —
    /// used by the per-asset criticality-hydration tests.
    fn asset_view_with_criticality(
        id: &str,
        exposure: &str,
        criticality: Option<&str>,
    ) -> AssetView {
        AssetView {
            id: id.to_owned(),
            tenant_id: "tenant-1".into(),
            engagement_id: "eng-1".into(),
            kind: "host".into(),
            identifier: format!("{id}.example.com"),
            source: exposure.to_owned(),
            first_seen: "1970-01-01T00:00:00Z".into(),
            last_seen: "1970-01-01T00:00:00Z".into(),
            criticality: criticality.map(str::to_owned),
        }
    }

    fn make_finding(id: &str, cve: Option<&str>) -> FindingView {
        FindingView {
            id: id.to_owned(),
            tenant_id: "t".into(),
            asset_id: "a".into(),
            severity: "medium".into(),
            status: "open".into(),
            title: id.to_owned(),
            description: String::new(),
            cvss: None,
            cve_id: cve.map(str::to_owned),
            first_seen: "1970-01-01T00:00:00Z".into(),
            last_seen: "1970-01-01T00:00:00Z".into(),
            metadata: None,
        }
    }

    fn build_adapter(
        cve: Arc<dyn CveLookup>,
        findings: Arc<dyn FindingRepositoryPort>,
    ) -> Arc<dyn CalculateRiskPort> {
        build_adapter_with_assets(cve, findings, Arc::new(MockAssets::empty()))
    }

    fn build_adapter_with_assets(
        cve: Arc<dyn CveLookup>,
        findings: Arc<dyn FindingRepositoryPort>,
        assets: Arc<dyn AssetRepositoryPort>,
    ) -> Arc<dyn CalculateRiskPort> {
        let scoring = RiskScoringConfig::sentinelx_default().unwrap();
        let bands = SeverityBands::new(0.1, 4.0, 7.0, 9.0).unwrap();
        let scorer = CompositeScorer::new(scoring, bands).unwrap();
        let epss: Arc<dyn EpssProvider> = Arc::new(NullEpss);
        let kev: Arc<dyn KevProvider> = Arc::new(NullKev);
        let usecase =
            CalculateRiskUseCase::new(scorer, Arc::new(DynEpss(epss)), Arc::new(DynKev(kev)));
        Arc::new(RiskAdapter {
            uc: usecase,
            cve,
            findings,
            assets,
        })
    }

    /// Concrete [`RiskAdapter`] (not a trait object) so tests can call
    /// crate-private methods like [`RiskAdapter::resolve_asset_context`].
    fn build_concrete_adapter(assets: Arc<dyn AssetRepositoryPort>) -> RiskAdapter {
        let scoring = RiskScoringConfig::sentinelx_default().unwrap();
        let bands = SeverityBands::new(0.1, 4.0, 7.0, 9.0).unwrap();
        let scorer = CompositeScorer::new(scoring, bands).unwrap();
        let epss: Arc<dyn EpssProvider> = Arc::new(NullEpss);
        let kev: Arc<dyn KevProvider> = Arc::new(NullKev);
        let usecase =
            CalculateRiskUseCase::new(scorer, Arc::new(DynEpss(epss)), Arc::new(DynKev(kev)));
        RiskAdapter {
            uc: usecase,
            cve: Arc::new(NullCve),
            findings: Arc::new(MockFindings::new(vec![])),
            assets,
        }
    }

    fn build_single(cve: Arc<dyn CveLookup>) -> Arc<dyn CalculateRiskPort> {
        build_adapter(cve, Arc::new(MockFindings::new(vec![])))
    }

    fn engagement_req(top_n: u32, include_unscored: bool) -> CalculateEngagementRiskRequest {
        CalculateEngagementRiskRequest {
            include_unscored,
            top_n,
        }
    }

    #[tokio::test]
    async fn synthetic_input_still_used_when_cve_id_absent() {
        let mock = Arc::new(MockCve::new(Ok(None)));
        let adapter = build_single(Arc::clone(&mock) as Arc<dyn CveLookup>);
        let view = adapter
            .calculate(CalculateRiskRequest {
                engagement_id: "eng-1".into(),
                asset_id: None,
                cve_id: None,
            })
            .await
            .unwrap();
        assert_eq!(view.engagement_id, "eng-1");
        assert!(view.composite_score > 0.0);
        assert_eq!(mock.call_count(), 0, "CVE lookup must not be called");
    }

    #[tokio::test]
    async fn real_pipeline_uses_fetched_cvss_when_cve_id_present() {
        let baseline = {
            let mock = Arc::new(MockCve::new(Ok(None)));
            let adapter = build_single(mock as Arc<dyn CveLookup>);
            adapter
                .calculate(CalculateRiskRequest {
                    engagement_id: "eng-1".into(),
                    asset_id: None,
                    cve_id: None,
                })
                .await
                .unwrap()
                .composite_score
        };

        let detail = CveDetail {
            cvss: CvssScore::v3_only(9.0).unwrap(),
            description: Some("severe".into()),
        };
        let mock = Arc::new(MockCve::new(Ok(Some(detail))));
        let adapter = build_single(Arc::clone(&mock) as Arc<dyn CveLookup>);

        let view = adapter
            .calculate(CalculateRiskRequest {
                engagement_id: "eng-1".into(),
                asset_id: None,
                cve_id: Some("CVE-2024-12345".into()),
            })
            .await
            .unwrap();

        assert_eq!(mock.call_count(), 1);
        assert!(
            view.composite_score > baseline,
            "real-pipeline score {} must exceed synthetic baseline {}",
            view.composite_score,
            baseline,
        );
    }

    #[tokio::test]
    async fn not_found_when_cve_unknown() {
        let mock = Arc::new(MockCve::new(Ok(None)));
        let adapter = build_single(mock as Arc<dyn CveLookup>);
        let err = adapter
            .calculate(CalculateRiskRequest {
                engagement_id: "eng-1".into(),
                asset_id: None,
                cve_id: Some("CVE-2024-99999".into()),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, RiskPortError::NotFound), "got {err:?}");
    }

    #[tokio::test]
    async fn invalid_when_cve_id_malformed() {
        let mock = Arc::new(MockCve::new(Ok(None)));
        let adapter = build_single(Arc::clone(&mock) as Arc<dyn CveLookup>);
        let err = adapter
            .calculate(CalculateRiskRequest {
                engagement_id: "eng-1".into(),
                asset_id: None,
                cve_id: Some("not-a-cve".into()),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, RiskPortError::Invalid(_)), "got {err:?}");
        assert_eq!(mock.call_count(), 0, "lookup must not run for bad id");
    }

    #[tokio::test]
    async fn null_cve_returns_none() {
        // The Phase-0 fallback (no intel bundle) should resolve CVEs to
        // NotFound rather than panicking.
        let adapter = build_single(Arc::new(NullCve));
        let err = adapter
            .calculate(CalculateRiskRequest {
                engagement_id: "eng-1".into(),
                asset_id: None,
                cve_id: Some("CVE-2024-12345".into()),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, RiskPortError::NotFound));
    }

    // ----- Engagement-aggregate tests ------------------------------------

    #[tokio::test]
    async fn engagement_aggregate_empty_findings_returns_zero_scored() {
        let cve: Arc<dyn CveLookup> = Arc::new(MockCve::new(Ok(None)));
        let findings: Arc<dyn FindingRepositoryPort> = Arc::new(MockFindings::new(vec![]));
        let adapter = build_adapter(cve, findings);

        let v = adapter
            .calculate_engagement("tenant-1", "eng-1", engagement_req(5, false))
            .await
            .unwrap();

        assert_eq!(v.engagement_id, "eng-1");
        assert_eq!(v.total_findings, 0);
        assert_eq!(v.scored, 0);
        assert!((v.average_score - 0.0).abs() < f64::EPSILON);
        assert!((v.max_score - 0.0).abs() < f64::EPSILON);
        assert!(v.top.is_empty());
    }

    #[tokio::test]
    async fn engagement_aggregate_skips_findings_without_cve() {
        // 3 findings: one with a known CVE, two without. With
        // include_unscored=true the two CVE-less rows still count as
        // total_findings but not as scored.
        let rows = vec![
            make_finding("f-1", Some("CVE-2024-00001")),
            make_finding("f-2", None),
            make_finding("f-3", None),
        ];
        let cve: Arc<dyn CveLookup> = Arc::new(MapCve::with(vec![("CVE-2024-00001", 9.0)]));
        let findings: Arc<dyn FindingRepositoryPort> = Arc::new(MockFindings::new(rows));
        let adapter = build_adapter(cve, findings);

        let with_unscored = adapter
            .calculate_engagement("tenant-1", "eng-1", engagement_req(5, true))
            .await
            .unwrap();
        assert_eq!(with_unscored.total_findings, 3);
        assert_eq!(with_unscored.scored, 1);
        assert_eq!(with_unscored.top.len(), 1);

        // With include_unscored=false, CVE-less rows do not count towards
        // total_findings either.
        let rows2 = vec![
            make_finding("f-1", Some("CVE-2024-00001")),
            make_finding("f-2", None),
            make_finding("f-3", None),
        ];
        let cve2: Arc<dyn CveLookup> = Arc::new(MapCve::with(vec![("CVE-2024-00001", 9.0)]));
        let findings2: Arc<dyn FindingRepositoryPort> = Arc::new(MockFindings::new(rows2));
        let adapter2 = build_adapter(cve2, findings2);
        let without_unscored = adapter2
            .calculate_engagement("tenant-1", "eng-1", engagement_req(5, false))
            .await
            .unwrap();
        assert_eq!(without_unscored.total_findings, 1);
        assert_eq!(without_unscored.scored, 1);
    }

    #[tokio::test]
    async fn engagement_aggregate_picks_top_n_by_score() {
        let rows = vec![
            make_finding("low", Some("CVE-2024-00001")),
            make_finding("med", Some("CVE-2024-00002")),
            make_finding("high", Some("CVE-2024-00003")),
            make_finding("crit", Some("CVE-2024-00004")),
        ];
        let cve: Arc<dyn CveLookup> = Arc::new(MapCve::with(vec![
            ("CVE-2024-00001", 2.0),
            ("CVE-2024-00002", 5.0),
            ("CVE-2024-00003", 8.0),
            ("CVE-2024-00004", 9.8),
        ]));
        let findings: Arc<dyn FindingRepositoryPort> = Arc::new(MockFindings::new(rows));
        let adapter = build_adapter(cve, findings);

        let v = adapter
            .calculate_engagement("tenant-1", "eng-1", engagement_req(2, false))
            .await
            .unwrap();

        assert_eq!(v.scored, 4);
        assert_eq!(v.top.len(), 2);
        // Top-N must be descending by score.
        assert!(v.top[0].score >= v.top[1].score);
        // The highest CVSS row should land first.
        assert_eq!(v.top[0].finding_id, "crit");
        // max_score equals the top item's score.
        assert!((v.max_score - v.top[0].score).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn engagement_aggregate_severity_counts_sum_to_scored() {
        let rows = vec![
            make_finding("f-1", Some("CVE-2024-00001")),
            make_finding("f-2", Some("CVE-2024-00002")),
            make_finding("f-3", Some("CVE-2024-00003")),
            make_finding("f-4", Some("CVE-2024-00004")),
            make_finding("f-5", Some("CVE-2024-00005")),
        ];
        let cve: Arc<dyn CveLookup> = Arc::new(MapCve::with(vec![
            ("CVE-2024-00001", 1.0),
            ("CVE-2024-00002", 4.5),
            ("CVE-2024-00003", 7.5),
            ("CVE-2024-00004", 9.5),
            ("CVE-2024-00005", 9.9),
        ]));
        let findings: Arc<dyn FindingRepositoryPort> = Arc::new(MockFindings::new(rows));
        let adapter = build_adapter(cve, findings);

        let v = adapter
            .calculate_engagement("tenant-1", "eng-1", engagement_req(10, false))
            .await
            .unwrap();

        let sc = &v.severity_counts;
        let sum = sc.critical + sc.high + sc.medium + sc.low + sc.info;
        assert_eq!(sum, v.scored, "severity histogram must equal scored");
    }

    // ----- Asset-context-hydration tests --------------------------------
    //
    // The mock [`AssetRepositoryPort`] returns an [`AssetView`] whose
    // `source` field stands in for the (not-yet-wired)
    // `tags["sx.exposure"]` map. The test names use "tag" because that is
    // the Phase-3.5+1 spec terminology; the underlying transport today is
    // the `source` field. See the module docblock.

    /// `source = "internet"` → the per-finding scorer is given
    /// [`ExposureLevel::Internet`].
    #[tokio::test]
    async fn engagement_aggregate_uses_internet_exposure_when_tag_says_internet() {
        let mut row = make_finding("f-1", Some("CVE-2024-00001"));
        row.asset_id = "asset-internet".into();

        let cve: Arc<dyn CveLookup> = Arc::new(MapCve::with(vec![("CVE-2024-00001", 7.0)]));
        let findings: Arc<dyn FindingRepositoryPort> = Arc::new(MockFindings::new(vec![row]));
        let assets: Arc<dyn AssetRepositoryPort> =
            Arc::new(MockAssets::with_exposure("asset-internet", "internet"));
        let adapter = build_adapter_with_assets(cve, findings, assets);

        let v = adapter
            .calculate_engagement("tenant-1", "eng-1", engagement_req(5, false))
            .await
            .unwrap();

        assert_eq!(v.scored, 1);
        // Internet is the highest exposure score in the default config
        // (10.0). The composite is strictly positive — the contract here
        // is "the lookup succeeded and a score was produced"; the next
        // test verifies the ordering vs Isolated.
        assert!(
            v.top[0].score > 0.0,
            "expected a positive score, got {}",
            v.top[0].score,
        );
    }

    /// `source = "isolated"` produces a strictly lower composite score
    /// than `source = "internet"` for the same CVE — proves the asset
    /// context actually reaches the composite scorer.
    #[tokio::test]
    async fn engagement_aggregate_uses_isolated_exposure_when_tag_says_isolated_and_scores_lower() {
        let cve_internet: Arc<dyn CveLookup> =
            Arc::new(MapCve::with(vec![("CVE-2024-00001", 7.0)]));
        let cve_isolated: Arc<dyn CveLookup> =
            Arc::new(MapCve::with(vec![("CVE-2024-00001", 7.0)]));

        let mut row_a = make_finding("f-1", Some("CVE-2024-00001"));
        row_a.asset_id = "asset-internet".into();
        let mut row_b = make_finding("f-1", Some("CVE-2024-00001"));
        row_b.asset_id = "asset-isolated".into();

        let findings_a: Arc<dyn FindingRepositoryPort> = Arc::new(MockFindings::new(vec![row_a]));
        let findings_b: Arc<dyn FindingRepositoryPort> = Arc::new(MockFindings::new(vec![row_b]));

        let assets_a: Arc<dyn AssetRepositoryPort> =
            Arc::new(MockAssets::with_exposure("asset-internet", "internet"));
        let assets_b: Arc<dyn AssetRepositoryPort> =
            Arc::new(MockAssets::with_exposure("asset-isolated", "isolated"));

        let adapter_internet = build_adapter_with_assets(cve_internet, findings_a, assets_a);
        let adapter_isolated = build_adapter_with_assets(cve_isolated, findings_b, assets_b);

        let v_internet = adapter_internet
            .calculate_engagement("tenant-1", "eng-1", engagement_req(5, false))
            .await
            .unwrap();
        let v_isolated = adapter_isolated
            .calculate_engagement("tenant-1", "eng-1", engagement_req(5, false))
            .await
            .unwrap();

        assert_eq!(v_internet.scored, 1);
        assert_eq!(v_isolated.scored, 1);
        assert!(
            v_isolated.top[0].score < v_internet.top[0].score,
            "isolated ({}) must score below internet ({})",
            v_isolated.top[0].score,
            v_internet.top[0].score,
        );
    }

    /// No row in the asset repo for `asset_id` → falls back to
    /// [`ExposureLevel::Internet`] (the Phase-1 default). Verified by
    /// comparing against the explicit-internet adapter built above.
    #[tokio::test]
    async fn engagement_aggregate_falls_back_to_internet_when_tag_missing() {
        // Adapter A: asset row is present with "internet" exposure.
        let cve_a: Arc<dyn CveLookup> = Arc::new(MapCve::with(vec![("CVE-2024-00001", 7.0)]));
        let mut row_a = make_finding("f-1", Some("CVE-2024-00001"));
        row_a.asset_id = "asset-known".into();
        let findings_a: Arc<dyn FindingRepositoryPort> = Arc::new(MockFindings::new(vec![row_a]));
        let assets_a: Arc<dyn AssetRepositoryPort> =
            Arc::new(MockAssets::with_exposure("asset-known", "internet"));
        let adapter_a = build_adapter_with_assets(cve_a, findings_a, assets_a);

        // Adapter B: asset row is missing — the repo returns NotFound.
        let cve_b: Arc<dyn CveLookup> = Arc::new(MapCve::with(vec![("CVE-2024-00001", 7.0)]));
        let mut row_b = make_finding("f-1", Some("CVE-2024-00001"));
        row_b.asset_id = "asset-missing".into();
        let findings_b: Arc<dyn FindingRepositoryPort> = Arc::new(MockFindings::new(vec![row_b]));
        let assets_b: Arc<dyn AssetRepositoryPort> = Arc::new(MockAssets::empty());
        let adapter_b = build_adapter_with_assets(cve_b, findings_b, assets_b);

        let v_a = adapter_a
            .calculate_engagement("tenant-1", "eng-1", engagement_req(5, false))
            .await
            .unwrap();
        let v_b = adapter_b
            .calculate_engagement("tenant-1", "eng-1", engagement_req(5, false))
            .await
            .unwrap();

        assert_eq!(v_a.scored, 1);
        assert_eq!(v_b.scored, 1);
        assert!(
            (v_a.top[0].score - v_b.top[0].score).abs() < f64::EPSILON,
            "missing asset row must yield the same score as explicit \
             internet exposure (got {} vs {})",
            v_b.top[0].score,
            v_a.top[0].score,
        );
    }

    // ----- Asset-criticality-hydration tests ----------------------------
    //
    // These exercise [`RiskAdapter::resolve_asset_context`] directly so the
    // criticality-parsing fallback is asserted without leaning on the
    // composite-scorer output (which fold_finding routes into).

    #[tokio::test]
    async fn resolve_asset_context_uses_crown_jewel_when_view_says_crown_jewel() {
        let view = asset_view_with_criticality("asset-cj", "internet", Some("crown_jewel"));
        let assets: Arc<dyn AssetRepositoryPort> = Arc::new(MockAssets::with_view(view));
        let adapter = build_concrete_adapter(assets);

        let (exposure, criticality) = adapter.resolve_asset_context("tenant-1", "asset-cj").await;

        assert_eq!(exposure, ExposureLevel::Internet);
        assert_eq!(criticality, AssetCriticality::CrownJewel);
    }

    #[tokio::test]
    async fn resolve_asset_context_uses_staging_when_view_says_staging() {
        let view = asset_view_with_criticality("asset-stg", "internal", Some("staging"));
        let assets: Arc<dyn AssetRepositoryPort> = Arc::new(MockAssets::with_view(view));
        let adapter = build_concrete_adapter(assets);

        let (exposure, criticality) = adapter.resolve_asset_context("tenant-1", "asset-stg").await;

        assert_eq!(exposure, ExposureLevel::Internal);
        assert_eq!(criticality, AssetCriticality::Staging);
    }

    #[tokio::test]
    async fn resolve_asset_context_falls_back_to_production_when_criticality_garbage() {
        let view = asset_view_with_criticality("asset-garbage", "internet", Some("garbage"));
        let assets: Arc<dyn AssetRepositoryPort> = Arc::new(MockAssets::with_view(view));
        let adapter = build_concrete_adapter(assets);

        let (_, criticality) = adapter
            .resolve_asset_context("tenant-1", "asset-garbage")
            .await;

        assert_eq!(criticality, AssetCriticality::Production);
    }

    #[tokio::test]
    async fn resolve_asset_context_falls_back_to_production_when_criticality_none() {
        // `criticality: None` simulates a row that pre-dates the column
        // being surfaced through `AssetView`.
        let view = asset_view_with_criticality("asset-none", "internet", None);
        let assets: Arc<dyn AssetRepositoryPort> = Arc::new(MockAssets::with_view(view));
        let adapter = build_concrete_adapter(assets);

        let (_, criticality) = adapter
            .resolve_asset_context("tenant-1", "asset-none")
            .await;

        assert_eq!(criticality, AssetCriticality::Production);
    }

    #[tokio::test]
    async fn resolve_asset_context_falls_back_to_production_when_repo_errors() {
        let assets: Arc<dyn AssetRepositoryPort> = Arc::new(FailingAssets);
        let adapter = build_concrete_adapter(assets);

        let (exposure, criticality) = adapter
            .resolve_asset_context("tenant-1", "asset-anything")
            .await;

        // Repo failure must preserve the pessimistic Phase-1 defaults.
        assert_eq!(exposure, ExposureLevel::Internet);
        assert_eq!(criticality, AssetCriticality::Production);
    }

    // ----- extract_factor unit tests ------------------------------------

    fn finding_with_metadata(meta: serde_json::Value) -> FindingView {
        let mut f = make_finding("f-meta", Some("CVE-2024-00001"));
        f.metadata = Some(meta);
        f
    }

    #[test]
    fn extract_factor_reads_within_range_value() {
        let view = finding_with_metadata(serde_json::json!({
            "business_impact": 3.5,
            "chain_amplifier": 1.5,
        }));
        assert!((extract_factor(&view, "business_impact") - 3.5).abs() < f64::EPSILON);
        assert!((extract_factor(&view, "chain_amplifier") - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn extract_factor_clamps_out_of_range_to_one() {
        let view_high = finding_with_metadata(serde_json::json!({"business_impact": 99.0}));
        let view_low = finding_with_metadata(serde_json::json!({"business_impact": 0.1}));
        let view_edge_below = finding_with_metadata(serde_json::json!({"business_impact": 0.4999}));
        let view_edge_above = finding_with_metadata(serde_json::json!({"business_impact": 5.0001}));
        assert!((extract_factor(&view_high, "business_impact") - 1.0).abs() < f64::EPSILON);
        assert!((extract_factor(&view_low, "business_impact") - 1.0).abs() < f64::EPSILON);
        assert!((extract_factor(&view_edge_below, "business_impact") - 1.0).abs() < f64::EPSILON);
        assert!((extract_factor(&view_edge_above, "business_impact") - 1.0).abs() < f64::EPSILON);

        // Boundary values are inclusive.
        let view_low_edge = finding_with_metadata(serde_json::json!({"business_impact": 0.5}));
        let view_high_edge = finding_with_metadata(serde_json::json!({"business_impact": 5.0}));
        assert!((extract_factor(&view_low_edge, "business_impact") - 0.5).abs() < f64::EPSILON);
        assert!((extract_factor(&view_high_edge, "business_impact") - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn extract_factor_returns_one_when_metadata_absent() {
        let view = make_finding("f-1", Some("CVE-2024-00001"));
        assert!(view.metadata.is_none());
        assert!((extract_factor(&view, "business_impact") - 1.0).abs() < f64::EPSILON);
        assert!((extract_factor(&view, "chain_amplifier") - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn extract_factor_returns_one_when_key_missing() {
        let view = finding_with_metadata(serde_json::json!({"unrelated": 2.0}));
        assert!((extract_factor(&view, "business_impact") - 1.0).abs() < f64::EPSILON);
        assert!((extract_factor(&view, "chain_amplifier") - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn extract_factor_returns_one_when_value_non_numeric() {
        let view_str = finding_with_metadata(serde_json::json!({"business_impact": "high"}));
        let view_bool = finding_with_metadata(serde_json::json!({"business_impact": true}));
        let view_arr = finding_with_metadata(serde_json::json!({"business_impact": [3.5]}));
        let view_null = finding_with_metadata(serde_json::json!({"business_impact": null}));
        assert!((extract_factor(&view_str, "business_impact") - 1.0).abs() < f64::EPSILON);
        assert!((extract_factor(&view_bool, "business_impact") - 1.0).abs() < f64::EPSILON);
        assert!((extract_factor(&view_arr, "business_impact") - 1.0).abs() < f64::EPSILON);
        assert!((extract_factor(&view_null, "business_impact") - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn extract_factor_returns_one_when_metadata_not_an_object() {
        // `serde_json::Value::get(&str)` returns `None` for non-object
        // payloads (strings, numbers, arrays), so the fallback path runs.
        let mut view = make_finding("f-arr", Some("CVE-2024-00001"));
        view.metadata = Some(serde_json::json!("not-an-object"));
        assert!((extract_factor(&view, "business_impact") - 1.0).abs() < f64::EPSILON);
        let mut view2 = make_finding("f-num", Some("CVE-2024-00001"));
        view2.metadata = Some(serde_json::json!(3.5));
        assert!((extract_factor(&view2, "business_impact") - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn bin_business_impact_maps_default_to_medium() {
        assert_eq!(bin_business_impact(1.0), BusinessImpact::Medium);
    }

    #[test]
    fn bin_business_impact_maps_low_and_high_factors() {
        assert_eq!(bin_business_impact(0.5), BusinessImpact::Low);
        assert_eq!(bin_business_impact(1.99), BusinessImpact::Medium);
        assert_eq!(bin_business_impact(2.0), BusinessImpact::High);
        assert_eq!(bin_business_impact(3.4999), BusinessImpact::High);
        assert_eq!(bin_business_impact(3.5), BusinessImpact::Critical);
        assert_eq!(bin_business_impact(5.0), BusinessImpact::Critical);
    }

    #[test]
    fn clamp_chain_amplifier_preserves_identity_default() {
        assert!((clamp_chain_amplifier(1.0).value() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn clamp_chain_amplifier_clamps_outside_band() {
        assert!((clamp_chain_amplifier(0.5).value() - 1.0).abs() < f64::EPSILON);
        assert!((clamp_chain_amplifier(5.0).value() - 2.0).abs() < f64::EPSILON);
        assert!((clamp_chain_amplifier(1.5).value() - 1.5).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn engagement_aggregate_metadata_business_impact_lifts_score() {
        // Two findings, identical CVE + asset context, but one carries a
        // higher business_impact factor in metadata. The metadata-bearing
        // finding must produce a strictly higher composite score.
        let cve_a: Arc<dyn CveLookup> = Arc::new(MapCve::with(vec![("CVE-2024-00001", 7.0)]));
        let cve_b: Arc<dyn CveLookup> = Arc::new(MapCve::with(vec![("CVE-2024-00001", 7.0)]));

        let mut row_baseline = make_finding("f-base", Some("CVE-2024-00001"));
        row_baseline.asset_id = String::new(); // skip asset lookup
        let mut row_boosted = make_finding("f-boost", Some("CVE-2024-00001"));
        row_boosted.asset_id = String::new();
        row_boosted.metadata = Some(serde_json::json!({"business_impact": 4.2}));

        let findings_a: Arc<dyn FindingRepositoryPort> =
            Arc::new(MockFindings::new(vec![row_baseline]));
        let findings_b: Arc<dyn FindingRepositoryPort> =
            Arc::new(MockFindings::new(vec![row_boosted]));
        let assets: Arc<dyn AssetRepositoryPort> = Arc::new(MockAssets::empty());

        let adapter_a = build_adapter_with_assets(cve_a, findings_a, Arc::clone(&assets));
        let adapter_b = build_adapter_with_assets(cve_b, findings_b, assets);

        let v_a = adapter_a
            .calculate_engagement("tenant-1", "eng-1", engagement_req(5, false))
            .await
            .unwrap();
        let v_b = adapter_b
            .calculate_engagement("tenant-1", "eng-1", engagement_req(5, false))
            .await
            .unwrap();

        assert_eq!(v_a.scored, 1);
        assert_eq!(v_b.scored, 1);
        assert!(
            v_b.top[0].score > v_a.top[0].score,
            "metadata-bearing finding ({}) must score above the baseline ({})",
            v_b.top[0].score,
            v_a.top[0].score,
        );
    }
}
