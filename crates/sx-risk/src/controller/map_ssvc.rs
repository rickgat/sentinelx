//! [`MapSsvcUseCase`] — thin orchestrator around [`crate::service::SsvcMapper`].

use crate::error::RiskError;
use crate::model::{SsvcInput, SsvcRulebook};
use crate::service::SsvcMapper;
use crate::view::SsvcDecisionView;

/// Use case: map a single [`SsvcInput`] to a [`SsvcDecisionView`].
#[derive(Debug, Clone)]
pub struct MapSsvcUseCase {
    mapper: SsvcMapper,
}

impl MapSsvcUseCase {
    /// Build the use case from a rulebook.
    #[must_use]
    pub const fn new(rulebook: SsvcRulebook) -> Self {
        Self {
            mapper: SsvcMapper::new(rulebook),
        }
    }

    /// Execute the use case.
    pub fn execute(&self, input: SsvcInput) -> Result<SsvcDecisionView, RiskError> {
        let decision = self.mapper.map(input)?;
        Ok(SsvcDecisionView::new(input, decision))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::model::{
        AutomatableImpact, Exploitation, HumanImpact, MissionImpact, SsvcDecision, SsvcExposure,
    };

    #[test]
    fn execute_round_trips_input() {
        let uc = MapSsvcUseCase::new(SsvcRulebook::cisa_v2_default());
        let input = SsvcInput {
            exploitation: Exploitation::Active,
            exposure: SsvcExposure::Open,
            automatable: AutomatableImpact::Yes,
            mission_impact: MissionImpact::High,
            human_impact: HumanImpact::High,
        };
        let view = uc.execute(input).unwrap();
        assert_eq!(view.input, input);
        assert_eq!(view.decision, SsvcDecision::Act);
    }
}
