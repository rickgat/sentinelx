//! Domain services for the discovery layer.

pub mod rate_limiter;
pub mod registry;
pub mod safety_gate;
pub mod scanner;

pub use rate_limiter::{RateLimiter, RateLimiterConfig, TokenBucket};
pub use registry::ScannerRegistry;
pub use safety_gate::SafetyGate;
pub use scanner::{ScanContext, Scanner, ScannerCapabilities, ScannerId, TargetKind};
