//! [`SsvcMapper`] — turns an [`SsvcInput`] into an [`SsvcDecision`] by
//! consulting the configured [`SsvcRulebook`].

use crate::error::RiskError;
use crate::model::{SsvcDecision, SsvcInput, SsvcRulebook};

/// Pure SSVC v2.0 decision mapper.
#[derive(Debug, Clone)]
pub struct SsvcMapper {
    rulebook: SsvcRulebook,
}

impl SsvcMapper {
    /// Build the mapper. The supplied rulebook is taken verbatim — the
    /// CISA-published default is available via [`SsvcRulebook::cisa_v2_default`].
    #[must_use]
    pub const fn new(rulebook: SsvcRulebook) -> Self {
        Self { rulebook }
    }

    /// Borrow the underlying rulebook.
    #[must_use]
    pub const fn rulebook(&self) -> &SsvcRulebook {
        &self.rulebook
    }

    /// Resolve `input` to a decision by walking the rule list. The first
    /// rule whose match conditions are all satisfied wins; if no rule
    /// matches, the rulebook's `fallback` is returned.
    ///
    /// This function cannot fail under the current rulebook shape, but
    /// the result type carries [`RiskError`] for future-proofing (e.g.
    /// once we allow rules to express weighted preferences).
    #[allow(clippy::unnecessary_wraps)] // future-proofing: rulebook may fail to load
    pub fn map(&self, input: SsvcInput) -> Result<SsvcDecision, RiskError> {
        for rule in &self.rulebook.rules {
            if rule.exploitation.is_none_or(|v| v == input.exploitation)
                && rule.exposure.is_none_or(|v| v == input.exposure)
                && rule.automatable.is_none_or(|v| v == input.automatable)
                && rule
                    .mission_impact
                    .is_none_or(|v| v == input.mission_impact)
                && rule.human_impact.is_none_or(|v| v == input.human_impact)
            {
                return Ok(rule.decision);
            }
        }
        Ok(self.rulebook.fallback)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::model::{AutomatableImpact, Exploitation, HumanImpact, MissionImpact, SsvcExposure};

    fn mapper() -> SsvcMapper {
        SsvcMapper::new(SsvcRulebook::cisa_v2_default())
    }

    // ─────────────────────────────────────────────────────────────────
    // CISA SSVC v2 cardinal test vectors.
    //   1. Active + Open + Automatable + Mission=High → Act
    //   2. Active + Controlled + Automatable + Mission=Low → Track
    //   3. PoC + Small + Human=High → Track*
    //   4. None + Open + Automatable + Mission=High → Attend
    //   5. None + Small + (any) → Track
    //   6. Active + Small + No → Track
    //   7. PoC + Controlled + No (any) → Track
    // ─────────────────────────────────────────────────────────────────

    #[test]
    fn vector_active_open_yes_high_is_act() {
        let d = mapper()
            .map(SsvcInput {
                exploitation: Exploitation::Active,
                exposure: SsvcExposure::Open,
                automatable: AutomatableImpact::Yes,
                mission_impact: MissionImpact::High,
                human_impact: HumanImpact::High,
            })
            .unwrap();
        assert_eq!(d, SsvcDecision::Act);
    }

    #[test]
    fn vector_active_controlled_yes_low_is_track() {
        let d = mapper()
            .map(SsvcInput {
                exploitation: Exploitation::Active,
                exposure: SsvcExposure::Controlled,
                automatable: AutomatableImpact::Yes,
                mission_impact: MissionImpact::Low,
                human_impact: HumanImpact::Low,
            })
            .unwrap();
        assert_eq!(d, SsvcDecision::Track);
    }

    #[test]
    fn vector_poc_small_human_high_is_track_star() {
        let d = mapper()
            .map(SsvcInput {
                exploitation: Exploitation::Poc,
                exposure: SsvcExposure::Small,
                automatable: AutomatableImpact::No,
                mission_impact: MissionImpact::Low,
                human_impact: HumanImpact::High,
            })
            .unwrap();
        assert_eq!(d, SsvcDecision::TrackStar);
    }

    #[test]
    fn vector_none_open_yes_high_is_attend() {
        let d = mapper()
            .map(SsvcInput {
                exploitation: Exploitation::None,
                exposure: SsvcExposure::Open,
                automatable: AutomatableImpact::Yes,
                mission_impact: MissionImpact::High,
                human_impact: HumanImpact::Low,
            })
            .unwrap();
        assert_eq!(d, SsvcDecision::Attend);
    }

    #[test]
    fn vector_none_small_any_is_track() {
        let d = mapper()
            .map(SsvcInput {
                exploitation: Exploitation::None,
                exposure: SsvcExposure::Small,
                automatable: AutomatableImpact::No,
                mission_impact: MissionImpact::Medium,
                human_impact: HumanImpact::Low,
            })
            .unwrap();
        assert_eq!(d, SsvcDecision::Track);
    }

    #[test]
    fn vector_active_small_no_is_track() {
        let d = mapper()
            .map(SsvcInput {
                exploitation: Exploitation::Active,
                exposure: SsvcExposure::Small,
                automatable: AutomatableImpact::No,
                mission_impact: MissionImpact::High,
                human_impact: HumanImpact::High,
            })
            .unwrap();
        assert_eq!(d, SsvcDecision::Track);
    }

    #[test]
    fn vector_poc_controlled_no_is_track() {
        let d = mapper()
            .map(SsvcInput {
                exploitation: Exploitation::Poc,
                exposure: SsvcExposure::Controlled,
                automatable: AutomatableImpact::No,
                mission_impact: MissionImpact::High,
                human_impact: HumanImpact::Low,
            })
            .unwrap();
        assert_eq!(d, SsvcDecision::Track);
    }

    #[test]
    fn fallback_is_used_when_rulebook_is_exhausted() {
        // Empty rulebook -> always returns fallback.
        let book = SsvcRulebook {
            rules: vec![],
            fallback: SsvcDecision::Attend,
        };
        let mapper = SsvcMapper::new(book);
        let d = mapper
            .map(SsvcInput {
                exploitation: Exploitation::None,
                exposure: SsvcExposure::Small,
                automatable: AutomatableImpact::No,
                mission_impact: MissionImpact::Low,
                human_impact: HumanImpact::Low,
            })
            .unwrap();
        assert_eq!(d, SsvcDecision::Attend);
    }
}
