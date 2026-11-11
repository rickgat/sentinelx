//! Minimal local copies of the contracts that `sx-core` and `sx-engagement`
//! will eventually expose to the rest of the system.
//!
//! Why are these here?
//!
//! `sx-discovery` is built in parallel with the domain crates. At the time
//! this crate compiles, the sibling crates' `lib.rs` files are intentional
//! placeholders — none of the value objects, entities, or services they
//! contain are reachable through their public API yet.
//!
//! To keep this crate fully testable in isolation (and to make wiring with
//! the real implementations a single import swap later), every type in this
//! module mirrors the agreed-upon contract: identical names, identical
//! semantics, and a fully-async public surface.
//!
//! Downstream code that already has the real `sx_core` / `sx_engagement`
//! types should construct the local types from those (the structs are
//! `Clone + Send + Sync` and use only stable serde-compatible primitives).

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::sync::Notify;
use url::Url;
use uuid::Uuid;

use crate::error::DiscoveryError;

/// Tenant identifier (UUID v7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TenantId(Uuid);

impl TenantId {
    /// Wrap an existing UUID.
    #[must_use]
    pub const fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    /// Borrow the underlying UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Generate a new time-ordered identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for TenantId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TenantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Engagement identifier (UUID v7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EngagementId(Uuid);

impl EngagementId {
    /// Wrap an existing UUID.
    #[must_use]
    pub const fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    /// Borrow the underlying UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Generate a new time-ordered identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for EngagementId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EngagementId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Asset identifier (UUID v7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AssetId(Uuid);

impl AssetId {
    /// Generate a new time-ordered identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Wrap an existing UUID.
    #[must_use]
    pub const fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    /// Borrow the underlying UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for AssetId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AssetId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A normalised fully-qualified domain name (lowercased, no trailing dot).
///
/// Mirrors `sx_core::value_object::fqdn::Fqdn`. Validation is RFC 1035-lite:
/// non-empty, length cap, at least two labels, no all-numeric TLD.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Fqdn(String);

impl Fqdn {
    /// Build and validate an FQDN.
    pub fn new(input: impl AsRef<str>) -> Result<Self, DiscoveryError> {
        const MAX_FQDN_LENGTH: usize = 253;
        const MAX_LABEL_LENGTH: usize = 63;

        let raw = input.as_ref();
        let trimmed = raw.strip_suffix('.').unwrap_or(raw);
        let lower = trimmed.to_ascii_lowercase();
        if lower.is_empty() {
            return Err(DiscoveryError::config("fqdn is empty"));
        }
        if lower.len() > MAX_FQDN_LENGTH {
            return Err(DiscoveryError::config(format!(
                "fqdn exceeds {MAX_FQDN_LENGTH} bytes",
            )));
        }
        let labels: Vec<&str> = lower.split('.').collect();
        if labels.len() < 2 {
            return Err(DiscoveryError::config("fqdn must have at least two labels"));
        }
        for label in &labels {
            if label.is_empty()
                || label.len() > MAX_LABEL_LENGTH
                || label.starts_with('-')
                || label.ends_with('-')
            {
                return Err(DiscoveryError::config(format!(
                    "invalid fqdn label: {label}",
                )));
            }
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(DiscoveryError::config(format!(
                    "label has illegal characters: {label}",
                )));
            }
        }
        if let Some(tld) = labels.last() {
            if tld.chars().all(|c| c.is_ascii_digit()) {
                return Err(DiscoveryError::config(format!(
                    "tld cannot be all-numeric: {tld}",
                )));
            }
        }
        Ok(Self(lower))
    }

    /// Borrow the canonical (lowercase) form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Fqdn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A single entry describing an in-scope target.
///
/// Mirrors `sx_core::value_object::scope::ScopeTarget`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ScopeTarget {
    /// An IP network range, IPv4 or IPv6.
    Cidr(IpNet),
    /// A domain name (host or zone). Subdomain matching is up to the matcher.
    Domain(Fqdn),
    /// A URL — host / path scope (e.g. for web app testing).
    Url(Url),
    /// A single IP address — convenience for testing.
    Ip(IpAddr),
}

impl ScopeTarget {
    /// Canonical string form, used as a key in per-target rate limiter
    /// buckets and as a tracing field.
    #[must_use]
    pub fn canonical_key(&self) -> String {
        match self {
            Self::Cidr(c) => format!("cidr:{c}"),
            Self::Domain(d) => format!("domain:{d}"),
            Self::Url(u) => format!("url:{u}"),
            Self::Ip(ip) => format!("ip:{ip}"),
        }
    }
}

impl fmt::Display for ScopeTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical_key())
    }
}

/// Engagement intensity tier. Higher tiers permit more aggressive probing —
/// for Phase 1, only [`ScanIntensity::Passive`] and [`ScanIntensity::Light`]
/// are supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanIntensity {
    /// Read-only / DNS-only.
    Passive,
    /// Single low-traffic probes (default).
    Light,
    /// Higher-volume but still non-destructive.
    Standard,
    /// Reserved — never enabled in Phase 1.
    Aggressive,
}

/// A request to run discovery against an engagement.
///
/// Mirrors `sx_engagement::ScanRequest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRequest {
    /// Tenant scope.
    pub tenant_id: TenantId,
    /// Engagement under which the scan runs.
    pub engagement_id: EngagementId,
    /// The targets that should be considered.
    pub targets: Vec<ScopeTarget>,
    /// Intensity tier of the request.
    pub intensity: ScanIntensity,
}

/// A minimal `Engagement` shim — the field set this crate needs is just
/// the allowed scope + denylist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Engagement {
    /// Identifier of the engagement.
    pub id: EngagementId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Allowed scope entries.
    pub allowed_scope: Vec<ScopeTarget>,
    /// Denylist entries — always rejected regardless of allow list overlap.
    pub denylist: Vec<ScopeTarget>,
    /// Maximum intensity permitted by the engagement's signed authorisation.
    pub max_intensity: ScanIntensity,
}

/// Validates that a probe target falls inside an engagement's allowed scope
/// and is not on the denylist.
///
/// Mirrors `sx_engagement::ScopeValidator`. Implementations live in
/// `sx-engagement` for production and in [`InMemoryScopeValidator`] /
/// test helpers here for unit tests.
#[async_trait]
pub trait ScopeValidator: Send + Sync + fmt::Debug {
    /// Return `Ok(())` if `target` is permitted by `engagement`'s rules.
    async fn validate(
        &self,
        engagement: &Engagement,
        target: &ScopeTarget,
    ) -> Result<(), DiscoveryError>;
}

/// Default in-process validator: enforces the rule
/// **denylist beats allow list**, and an empty allow list means everything
/// is out of scope.
#[derive(Debug, Default, Clone)]
pub struct InMemoryScopeValidator;

#[async_trait]
impl ScopeValidator for InMemoryScopeValidator {
    async fn validate(
        &self,
        engagement: &Engagement,
        target: &ScopeTarget,
    ) -> Result<(), DiscoveryError> {
        if engagement
            .denylist
            .iter()
            .any(|d| target_matches(d, target))
        {
            return Err(DiscoveryError::safety_gate(format!(
                "denied by denylist: {target}",
            )));
        }
        if engagement.allowed_scope.is_empty() {
            return Err(DiscoveryError::safety_gate(
                "no allowed scope entries for engagement",
            ));
        }
        let in_scope = engagement
            .allowed_scope
            .iter()
            .any(|s| target_matches(s, target));
        if !in_scope {
            return Err(DiscoveryError::safety_gate(format!(
                "target not in allowed scope: {target}",
            )));
        }
        Ok(())
    }
}

fn target_matches(rule: &ScopeTarget, candidate: &ScopeTarget) -> bool {
    match (rule, candidate) {
        (ScopeTarget::Cidr(net), ScopeTarget::Ip(ip)) => net.contains(ip),
        (ScopeTarget::Cidr(rule_net), ScopeTarget::Cidr(cand_net)) => {
            rule_net.contains(&cand_net.network()) && rule_net.prefix_len() <= cand_net.prefix_len()
        }
        (ScopeTarget::Domain(rule_d), ScopeTarget::Domain(cand_d)) => {
            cand_d == rule_d || cand_d.as_str().ends_with(&format!(".{}", rule_d.as_str()))
        }
        (ScopeTarget::Url(rule_u), ScopeTarget::Url(cand_u)) => {
            rule_u.host_str() == cand_u.host_str() && cand_u.path().starts_with(rule_u.path())
        }
        (ScopeTarget::Domain(rule_d), ScopeTarget::Url(cand_u)) => cand_u
            .host_str()
            .is_some_and(|h| h == rule_d.as_str() || h.ends_with(&format!(".{}", rule_d.as_str()))),
        _ => false,
    }
}

/// Scope at which a kill switch can be tripped.
///
/// Mirrors `sx_engagement::KillSwitchScope`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchScope {
    /// Trip every active probe in the platform.
    Global,
    /// Trip every active probe for a single tenant.
    Tenant(TenantId),
    /// Trip every active probe for a single engagement.
    Engagement(EngagementId),
}

/// Asynchronous, multi-subscriber kill switch.
///
/// Mirrors `sx_engagement::KillSwitch`. The trait deliberately does **not**
/// expose `trip(...)` to the discovery crate — only `is_tripped` and
/// `subscribe` are needed at probe sites.
#[async_trait]
pub trait KillSwitch: Send + Sync + fmt::Debug {
    /// `true` if the switch is currently tripped at any of `scopes`.
    async fn is_tripped(&self, scopes: &[KillSwitchScope]) -> bool;

    /// Subscribe to future trips at any of `scopes`. The returned [`Notify`]
    /// is notified exactly once for every trip event.
    fn subscribe(&self, scopes: &[KillSwitchScope]) -> Arc<Notify>;
}

/// In-process kill switch used in tests and as a sane default in
/// single-tenant deployments. Mirrors `sx_engagement::InMemoryKillSwitch`.
///
/// State is held behind a [`std::sync::Mutex`] so that `subscribe` can
/// register synchronously without an `await` point.
#[derive(Debug, Default)]
pub struct InMemoryKillSwitch {
    state: std::sync::Mutex<KillSwitchState>,
}

#[derive(Debug, Default)]
struct KillSwitchState {
    tripped: HashSet<KillSwitchScope>,
    subscribers: Vec<(Vec<KillSwitchScope>, Arc<Notify>)>,
}

impl InMemoryKillSwitch {
    /// Build an empty (un-tripped) kill switch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Trip the switch at the given scope. Wakes every matching subscriber.
    pub fn trip(&self, scope: &KillSwitchScope) {
        let waiters: Vec<Arc<Notify>> = {
            let mut state = match self.state.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            state.tripped.insert(scope.clone());
            state
                .subscribers
                .iter()
                .filter(|(subs_scopes, _)| subs_scopes.iter().any(|s| s == scope))
                .map(|(_, n)| Arc::clone(n))
                .collect()
        };
        for w in waiters {
            w.notify_waiters();
        }
    }
}

#[async_trait]
impl KillSwitch for InMemoryKillSwitch {
    async fn is_tripped(&self, scopes: &[KillSwitchScope]) -> bool {
        let state = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        scopes.iter().any(|s| state.tripped.contains(s))
    }

    fn subscribe(&self, scopes: &[KillSwitchScope]) -> Arc<Notify> {
        let notify = Arc::new(Notify::new());
        let mut state = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        state
            .subscribers
            .push((scopes.to_vec(), Arc::clone(&notify)));
        notify
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn in_memory_validator_rejects_when_denied() {
        let engagement = Engagement {
            id: EngagementId::new(),
            tenant_id: TenantId::new(),
            allowed_scope: vec![ScopeTarget::Domain(Fqdn::new("example.com").unwrap())],
            denylist: vec![ScopeTarget::Domain(
                Fqdn::new("internal.example.com").unwrap(),
            )],
            max_intensity: ScanIntensity::Light,
        };
        let target = ScopeTarget::Domain(Fqdn::new("internal.example.com").unwrap());
        let v = InMemoryScopeValidator;
        let res = v.validate(&engagement, &target).await;
        assert!(matches!(res, Err(DiscoveryError::SafetyGate(_))));
    }

    #[tokio::test]
    async fn in_memory_validator_allows_subdomain() {
        let engagement = Engagement {
            id: EngagementId::new(),
            tenant_id: TenantId::new(),
            allowed_scope: vec![ScopeTarget::Domain(Fqdn::new("example.com").unwrap())],
            denylist: vec![],
            max_intensity: ScanIntensity::Light,
        };
        let target = ScopeTarget::Domain(Fqdn::new("api.example.com").unwrap());
        InMemoryScopeValidator
            .validate(&engagement, &target)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn kill_switch_reports_tripped() {
        let switch = InMemoryKillSwitch::new();
        let scope = KillSwitchScope::Global;
        assert!(!switch.is_tripped(std::slice::from_ref(&scope)).await);
        switch.trip(&scope);
        assert!(switch.is_tripped(&[scope]).await);
    }

    #[test]
    fn fqdn_validation_rejects_garbage() {
        assert!(Fqdn::new("").is_err());
        assert!(Fqdn::new("nodot").is_err());
        assert!(Fqdn::new("under_score.com").is_err());
        assert!(Fqdn::new("example.com").is_ok());
    }
}
