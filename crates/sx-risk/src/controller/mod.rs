//! Use-case orchestrators (controllers in the MVC sense).

pub mod calculate_risk;
pub mod map_ssvc;

pub use calculate_risk::{CalculateRiskUseCase, RiskCalculationInput};
pub use map_ssvc::MapSsvcUseCase;
