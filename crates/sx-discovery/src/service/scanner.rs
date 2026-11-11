//! The [`Scanner`] trait and its supporting value objects.

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tokio::sync::Notify;

use crate::contracts::{EngagementId, KillSwitchScope, ScanIntensity, ScopeTarget, TenantId};
use crate::error::DiscoveryError;
use crate::model::scan_result::ScanResult;
use crate::service::rate_limiter::RateLimiter;

/// Strong wrapper around a scanner identifier.
///
/// Backed by a [`Cow<'static, str>`] so well-known scanner ids can be
/// represented as zero-allocation `&'static str` constants while still
/// round-tripping through `serde` as an owned string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ScannerId(Cow<'static, str>);

impl ScannerId {
    /// Wrap a `'static` id. Callers must guarantee uniqueness.
    #[must_use]
    pub const fn new(id: &'static str) -> Self {
        Self(Cow::Borrowed(id))
    }

    /// Wrap an owned id (used by `serde` and by adapters that load ids
    /// from configuration).
    #[must_use]
    pub const fn from_owned(id: String) -> Self {
        Self(Cow::Owned(id))
    }

    /// Borrow the underlying string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ScannerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Target kinds a scanner can handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    /// IP networks or single addresses.
    Ip,
    /// Domain names.
    Domain,
    /// URLs.
    Url,
}

impl TargetKind {
    /// Map a [`ScopeTarget`] to its [`TargetKind`].
    #[must_use]
    pub const fn of(target: &ScopeTarget) -> Self {
        match target {
            ScopeTarget::Cidr(_) | ScopeTarget::Ip(_) => Self::Ip,
            ScopeTarget::Domain(_) => Self::Domain,
            ScopeTarget::Url(_) => Self::Url,
        }
    }
}

/// Self-described capabilities of a scanner. Used by
/// [`crate::service::registry::ScannerRegistry::matching`] to filter the
/// scanner set for a given request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerCapabilities {
    /// Maximum intensity the scanner can be safely run at.
    pub max_intensity: ScanIntensity,
    /// Target kinds the scanner accepts.
    pub target_kinds: HashSet<TargetKind>,
    /// Soft, advisory upper bound on observations-per-second the scanner
    /// may emit. Purely informational — the registry does **not** enforce it.
    pub max_throughput_obs_per_sec: u32,
}

impl ScannerCapabilities {
    /// `true` if this scanner can accept the given target kind at the
    /// requested intensity.
    #[must_use]
    pub fn supports(&self, intensity: ScanIntensity, kind: TargetKind) -> bool {
        let intensity_ok = intensity_rank(intensity) <= intensity_rank(self.max_intensity);
        let kind_ok = self.target_kinds.contains(&kind);
        intensity_ok && kind_ok
    }
}

const fn intensity_rank(i: ScanIntensity) -> u8 {
    match i {
        ScanIntensity::Passive => 0,
        ScanIntensity::Light => 1,
        ScanIntensity::Standard => 2,
        ScanIntensity::Aggressive => 3,
    }
}

/// Per-invocation context handed to every scanner.
///
/// The context carries everything a scanner needs to behave safely:
/// the tenant / engagement it runs under, the requested intensity, a handle
/// to the rate limiter it must consume tokens from, a kill-switch
/// notification handle, and an absolute deadline.
#[derive(Debug, Clone)]
pub struct ScanContext {
    /// Tenant the scan runs for.
    pub tenant_id: TenantId,
    /// Engagement the scan runs under.
    pub engagement_id: EngagementId,
    /// Intensity the request was issued with.
    pub intensity: ScanIntensity,
    /// Shared handle to the rate limiter. Scanners MUST acquire one token
    /// per emitted network request.
    pub rate_limiter: Arc<RateLimiter>,
    /// Kill switch notifier — wake-up source for cancellation.
    pub kill_signal: Arc<Notify>,
    /// Logical kill-switch scopes the context subscribes to. Inspected by
    /// the orchestrator before each step.
    pub kill_scopes: Vec<KillSwitchScope>,
    /// Wall-clock deadline. Scanners SHOULD compare against this before
    /// every blocking call.
    pub deadline: OffsetDateTime,
}

/// The single polymorphic abstraction every concrete scanner implements.
#[async_trait]
pub trait Scanner: Send + Sync + fmt::Debug {
    /// Stable identifier, used by the registry and as a tracing field.
    fn id(&self) -> ScannerId;

    /// Capabilities advertised to the registry / scheduler.
    fn capabilities(&self) -> ScannerCapabilities;

    /// Run the scan against `target` under `ctx`.
    ///
    /// Implementations MUST:
    /// - Acquire a rate-limit token per outgoing request.
    /// - Honor `ctx.deadline` and `ctx.kill_signal`.
    /// - Never panic; map any I/O error into [`DiscoveryError`].
    async fn scan(
        &self,
        ctx: ScanContext,
        target: ScopeTarget,
    ) -> Result<ScanResult, DiscoveryError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_kind_classification() {
        let d = ScopeTarget::Domain(
            crate::contracts::Fqdn::new("example.com")
                .unwrap_or_else(|_| unreachable!("static input")),
        );
        assert_eq!(TargetKind::of(&d), TargetKind::Domain);
    }

    #[test]
    fn capabilities_filter_intensity() {
        let caps = ScannerCapabilities {
            max_intensity: ScanIntensity::Light,
            target_kinds: std::iter::once(TargetKind::Domain).collect(),
            max_throughput_obs_per_sec: 10,
        };
        assert!(caps.supports(ScanIntensity::Passive, TargetKind::Domain));
        assert!(caps.supports(ScanIntensity::Light, TargetKind::Domain));
        assert!(!caps.supports(ScanIntensity::Standard, TargetKind::Domain));
        assert!(!caps.supports(ScanIntensity::Light, TargetKind::Ip));
    }
}
