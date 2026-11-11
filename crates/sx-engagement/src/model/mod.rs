//! Domain model: pure data structures that carry the engagement contract.
//!
//! The aggregate root is [`engagement::Engagement`]. Value objects live in
//! sibling modules. Nothing in `model` performs I/O.

pub mod decision;
pub mod engagement;
pub mod intensity;
pub mod scope_request;
pub mod scope_target;
pub mod window;

pub use decision::ScopeDecision;
pub use engagement::{Engagement, EngagementApproval, EngagementStatus};
pub use intensity::ScanIntensity;
pub use scope_request::ScanRequest;
pub use scope_target::ScopeTarget;
pub use window::TimeWindow;
