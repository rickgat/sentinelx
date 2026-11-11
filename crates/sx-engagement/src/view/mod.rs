//! Input / output DTOs for the use cases.
//!
//! Each use case in [`crate::controller`] takes one request view and returns
//! one response view. Views never carry domain methods; they are pure data.

pub mod create_engagement_request;
pub mod create_engagement_response;
pub mod kill_switch_event_view;
pub mod scope_decision_view;

pub use create_engagement_request::CreateEngagementRequest;
pub use create_engagement_response::CreateEngagementResponse;
pub use kill_switch_event_view::KillSwitchEventView;
pub use scope_decision_view::ScopeDecisionView;
