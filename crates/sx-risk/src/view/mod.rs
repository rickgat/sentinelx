//! View types — HTTP / report-friendly projections of the risk model.

pub mod risk_breakdown;
pub mod ssvc_view;

pub use risk_breakdown::RiskBreakdownView;
pub use ssvc_view::SsvcDecisionView;
