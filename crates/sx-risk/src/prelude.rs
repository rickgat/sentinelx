//! Curated re-exports for downstream crates.
//!
//! `use sx_risk::prelude::*;` brings in every type usually needed to wire
//! a risk-scoring pipeline.

pub use crate::controller::{CalculateRiskUseCase, MapSsvcUseCase, RiskCalculationInput};
pub use crate::error::RiskError;
pub use crate::model::{
    AutomatableImpact, BusinessImpact, ChainAmplifier, ChainAmplifierBand, ComponentScore,
    Exploitation, HumanImpact, MissionImpact, RiskInput, RiskScore, RiskScoringConfig, ScoreBand,
    SeverityBandScores, SsvcDecision, SsvcExposure, SsvcInput, SsvcRulebook,
};
pub use crate::service::{CompositeScorer, EpssProvider, KevProvider, SsvcMapper};
pub use crate::tenant_tuning::{
    in_memory_service, InMemoryAuditSink, InMemoryRecomputeQueue, InMemoryTuningStore,
    RecomputeJob, RecomputeQueue, TenantRiskTuningService, TenantTuningStore, TuningAuditEvent,
    TuningAuditSink,
};
pub use crate::view::{RiskBreakdownView, SsvcDecisionView};
pub use crate::{calculate_with_weights, RiskWeights};
