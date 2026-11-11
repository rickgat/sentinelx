//! Convenience re-exports for typical call sites.

pub use crate::error::ApiError;
pub use crate::middleware::auth::{AuthConfig, AuthenticatedUser};
pub use crate::middleware::cors::CorsConfig;
pub use crate::middleware::rate_limit::{RateLimitConfig, RateLimiterState};
pub use crate::port::{
    AssetRepositoryPort, AuthenticateUserInput, AuthenticateUserPort, CalculateRiskPort,
    DiscoveryPortError, EngagementPortError, EngagementServicePort, FindingRepositoryPort,
    KillSwitchPort, KillSwitchTrigger, LogoutPort, RefreshTokenPort, RiskPortError,
    RunDiscoveryPort, TenantRepositoryPort, TenantSummaryView, ValidateTokenPort,
};
pub use crate::router::{build_router, build_router_with_cors};
pub use crate::server::serve;
pub use crate::state::AppState;
pub use crate::view::envelope::{ApiErrorBody, ApiErrorEnvelope, ApiResponse, ResponseMeta};
pub use crate::view::pagination::{PageQuery, PageView};
