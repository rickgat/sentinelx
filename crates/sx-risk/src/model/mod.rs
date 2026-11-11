//! Domain models for the risk scoring engine.
//!
//! Every public type here is a pure data carrier — no I/O, no async, no
//! interior mutability. Construction enforces validation; once a value is
//! built it is guaranteed to satisfy its invariants for its lifetime.

pub mod component_score;
pub mod config;
pub mod risk_input;
pub mod risk_score;
pub mod ssvc;

pub use component_score::ComponentScore;
pub use config::{
    ChainAmplifierBand, RiskScoringConfig, ScoreBand, SeverityBandScores, SsvcRulebook,
};
pub use risk_input::{BusinessImpact, ChainAmplifier, RiskInput};
pub use risk_score::RiskScore;
pub use ssvc::{
    AutomatableImpact, Exploitation, HumanImpact, MissionImpact, SsvcDecision, SsvcExposure,
    SsvcInput,
};
