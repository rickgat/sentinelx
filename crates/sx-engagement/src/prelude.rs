//! Common imports for downstream callers.
//!
//! `use sx_engagement::prelude::*;` pulls the most-used types into scope.

pub use crate::error::EngagementError;
pub use crate::model::{
    Engagement, EngagementApproval, EngagementStatus, ScanIntensity, ScanRequest, ScopeDecision,
    ScopeTarget, TimeWindow,
};
pub use crate::port::EngagementRepository;
pub use crate::service::{
    ApprovalPolicy, ApprovalThresholds, Clock, DenylistChecker, DenylistHit, FakeClock,
    InMemoryKillSwitch, KillReason, KillSwitch, KillSwitchEvent, KillSwitchScope, ScopeValidator,
    SystemClock,
};
pub use crate::view::{
    CreateEngagementRequest, CreateEngagementResponse, KillSwitchEventView, ScopeDecisionView,
};
