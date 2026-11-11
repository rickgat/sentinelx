//! [`CalculateRiskUseCase`] — orchestrates EPSS / KEV lookups, the
//! composite scorer, and view assembly.

use std::sync::Arc;

use sx_core::value_object::{
    criticality::AssetCriticality, cvss::CvssScore, epss::EpssScore, exposure::ExposureLevel,
    ids::CveId, severity::Severity,
};

use crate::error::RiskError;
use crate::model::{BusinessImpact, ChainAmplifier, RiskInput};
use crate::service::{CompositeScorer, EpssProvider, KevProvider};
use crate::view::RiskBreakdownView;

/// Upstream input for [`CalculateRiskUseCase::execute`].
///
/// This is the shape the API / engagement layer sees — the use case is
/// responsible for turning it into a [`RiskInput`] (which adds EPSS / KEV
/// data fetched from the provider ports).
#[derive(Debug, Clone)]
pub struct RiskCalculationInput {
    /// CVE identifier driving the EPSS / KEV lookups.
    pub cve: CveId,
    /// Optional CVSS envelope. When absent, `severity_hint` is required.
    pub cvss: Option<CvssScore>,
    /// Pre-computed [`Severity`] used when `cvss` is `None`.
    pub severity_hint: Option<Severity>,
    /// Optional pre-fetched EPSS score; when `None` the provider is
    /// consulted.
    pub epss: Option<EpssScore>,
    /// Optional pre-fetched KEV flag; when `None` the provider is
    /// consulted.
    pub kev: Option<bool>,
    /// Asset exposure level.
    pub exposure: ExposureLevel,
    /// Asset criticality.
    pub criticality: AssetCriticality,
    /// Business impact band.
    pub business_impact: BusinessImpact,
    /// Attack-chain amplifier.
    pub chain_amplifier: ChainAmplifier,
}

/// Use case: turn a [`RiskCalculationInput`] into a [`RiskBreakdownView`].
#[derive(Debug, Clone)]
pub struct CalculateRiskUseCase<E: EpssProvider, K: KevProvider> {
    scorer: CompositeScorer,
    epss: Arc<E>,
    kev: Arc<K>,
}

impl<E: EpssProvider, K: KevProvider> CalculateRiskUseCase<E, K> {
    /// Wire the use case.
    pub const fn new(scorer: CompositeScorer, epss: Arc<E>, kev: Arc<K>) -> Self {
        Self { scorer, epss, kev }
    }

    /// Resolve EPSS and KEV (if not already supplied), score, and assemble
    /// the view.
    pub async fn execute(
        &self,
        input: RiskCalculationInput,
    ) -> Result<RiskBreakdownView, RiskError> {
        let epss = match input.epss {
            Some(s) => Some(s),
            None => self.epss.fetch(&input.cve).await?,
        };
        let kev = match input.kev {
            Some(v) => v,
            None => self.kev.is_known_exploited(&input.cve).await?,
        };
        let risk_input = RiskInput::new(
            input.cvss,
            input.severity_hint,
            epss,
            kev,
            input.exposure,
            input.criticality,
            input.business_impact,
            input.chain_amplifier,
        )?;
        let (score, components) = self.scorer.score(&risk_input)?;
        let severity = score.severity(self.scorer.config().score_band);
        let epss_breached = risk_input.epss.as_ref().is_some_and(|s| {
            f64::from(s.probability) >= self.scorer.config().core.epss_threshold_act
        });
        Ok(RiskBreakdownView::new(
            score,
            severity,
            components,
            epss_breached,
            kev,
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use mockall::mock;
    use std::sync::Arc;
    use sx_core::value_object::severity::SeverityBands;

    use crate::model::RiskScoringConfig;

    mock! {
        #[derive(Debug)]
        Epss {}

        #[async_trait::async_trait]
        impl EpssProvider for Epss {
            async fn fetch(&self, cve: &CveId) -> Result<Option<EpssScore>, RiskError>;
        }
    }

    mock! {
        #[derive(Debug)]
        Kev {}

        #[async_trait::async_trait]
        impl KevProvider for Kev {
            async fn is_known_exploited(&self, cve: &CveId) -> Result<bool, RiskError>;
        }
    }

    fn bands() -> SeverityBands {
        SeverityBands::new(0.1, 4.0, 7.0, 9.0).unwrap()
    }

    #[tokio::test]
    async fn execute_uses_providers_when_data_missing() {
        let mut epss = MockEpss::new();
        let mut kev = MockKev::new();
        epss.expect_fetch()
            .times(1)
            .returning(|_| Ok(Some(EpssScore::new(0.5, 0.9).unwrap())));
        kev.expect_is_known_exploited()
            .times(1)
            .returning(|_| Ok(true));

        let scorer =
            CompositeScorer::new(RiskScoringConfig::sentinelx_default().unwrap(), bands()).unwrap();
        let uc = CalculateRiskUseCase::new(scorer, Arc::new(epss), Arc::new(kev));

        let view = uc
            .execute(RiskCalculationInput {
                cve: CveId::new("CVE-2024-12345").unwrap(),
                cvss: Some(CvssScore::v3_only(8.5).unwrap()),
                severity_hint: None,
                epss: None,
                kev: None,
                exposure: ExposureLevel::Internet,
                criticality: AssetCriticality::Production,
                business_impact: BusinessImpact::High,
                chain_amplifier: ChainAmplifier::identity(),
            })
            .await
            .unwrap();
        assert!(view.kev);
        assert!(view.epss_act_threshold_breached);
        assert!(view.score > 0.0);
    }

    #[tokio::test]
    async fn execute_skips_providers_when_data_supplied() {
        let mut epss = MockEpss::new();
        let mut kev = MockKev::new();
        epss.expect_fetch().never();
        kev.expect_is_known_exploited().never();

        let scorer =
            CompositeScorer::new(RiskScoringConfig::sentinelx_default().unwrap(), bands()).unwrap();
        let uc = CalculateRiskUseCase::new(scorer, Arc::new(epss), Arc::new(kev));

        let view = uc
            .execute(RiskCalculationInput {
                cve: CveId::new("CVE-2024-99999").unwrap(),
                cvss: Some(CvssScore::v3_only(5.0).unwrap()),
                severity_hint: None,
                epss: Some(EpssScore::new(0.1, 0.5).unwrap()),
                kev: Some(false),
                exposure: ExposureLevel::Internal,
                criticality: AssetCriticality::Production,
                business_impact: BusinessImpact::Low,
                chain_amplifier: ChainAmplifier::identity(),
            })
            .await
            .unwrap();
        assert!(!view.kev);
        assert!(!view.epss_act_threshold_breached);
    }

    #[tokio::test]
    async fn provider_error_propagates() {
        let mut epss = MockEpss::new();
        let kev = MockKev::new();
        epss.expect_fetch()
            .times(1)
            .returning(|_| Err(RiskError::provider("epss down")));
        let scorer =
            CompositeScorer::new(RiskScoringConfig::sentinelx_default().unwrap(), bands()).unwrap();
        let uc = CalculateRiskUseCase::new(scorer, Arc::new(epss), Arc::new(kev));
        let err = uc
            .execute(RiskCalculationInput {
                cve: CveId::new("CVE-2024-00001").unwrap(),
                cvss: Some(CvssScore::v3_only(5.0).unwrap()),
                severity_hint: None,
                epss: None,
                kev: Some(false),
                exposure: ExposureLevel::Internal,
                criticality: AssetCriticality::Production,
                business_impact: BusinessImpact::Low,
                chain_amplifier: ChainAmplifier::identity(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, RiskError::Provider(_)));
    }
}
