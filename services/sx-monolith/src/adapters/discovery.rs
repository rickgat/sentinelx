//! Discovery adapter.
//!
//! Real Phase-1.5 implementation of the
//! [`sx_api::port::RunDiscoveryPort`]. The adapter owns:
//!
//! 1. A [`SafetyGate`] wrapping the (Phase-0) always-allow
//!    [`InMemoryScopeValidator`] and the *shared* kill switch that the
//!    monolith's engagement bundle exposes.
//! 2. A composite [`RateLimiter`] (global concurrency + per-target token
//!    bucket).
//! 3. A [`ScannerRegistry`] populated with the four scanners shipped today:
//!    `DnsResolverScanner`, `TcpPortProbeScanner`, `HttpFingerprintScanner`
//!    and (when `grype` is installed) `ScaScanner`.
//! 4. A [`RunDiscoveryUseCase`] composed from the above.
//!
//! ## Persistence
//!
//! Engagement lookups go through an `Arc<dyn EngagementRepository>` handed
//! in by the composition root. Today that points at the monolith's
//! in-memory store (see [`super::engagement::EngagementBundle`]); when the
//! Postgres repository is wired in, the only thing that changes is the
//! trait object passed to [`build`].
//!
//! ## Intensity mapping
//!
//! The `sx-engagement` [`SxScanIntensity`](sx_engagement::model::intensity::ScanIntensity)
//! ladder is richer than the discovery contract ladder. The mapping below
//! is monotonic — a strictly-greater engagement intensity never maps down:
//!
//! | `sx-engagement` intensity | discovery [`DiscScanIntensity`] |
//! |---------------------------|---------------------------------|
//! | `Theoretical`             | `Passive`                       |
//! | `PassiveValidation`       | `Passive`                       |
//! | `SafeInteractive`         | `Light`                         |
//! | `ActiveExploit`           | `Standard`                      |
//! | `RedTeam`                 | `Aggressive`                    |
//!
//! Discovery scanners shipped in Phase 1.5 only register up to
//! `Standard`, so a `RedTeam` engagement is still gated by the safety
//! pipeline's intensity cap before any scanner sees the request.
//!
//! ## Scope-target translation
//!
//! Discovery only consumes IP/Domain/Url/Cidr targets. The richer
//! `sx-engagement` [`SxScopeTarget`] enum has two variants — `Arn` and
//! `RepoUrl` — that no discovery scanner accepts today; they are dropped
//! with a `tracing::warn!`.
//!
//! | `sx-engagement` variant | discovery variant            |
//! |-------------------------|------------------------------|
//! | `Cidr(IpNet)`           | `Cidr(IpNet)`                |
//! | `IpV4(Ipv4Addr)`        | `Ip(IpAddr)`                 |
//! | `IpV6(Ipv6Addr)`        | `Ip(IpAddr)`                 |
//! | `Domain(String)`        | `Domain(Fqdn)` (validated)   |
//! | `Url(Url)`              | `Url(Url)`                   |
//! | `Arn(_)`                | *dropped (warn)*             |
//! | `RepoUrl(_)`            | *dropped (warn)*             |

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sx_api::port::{DiscoveryPortError, RunDiscoveryPort};
use sx_core::value_object::ids::{EngagementId as CoreEngagementId, TenantId as CoreTenantId};
use sx_discovery::contracts::{
    Engagement as DiscEngagement, EngagementId as DiscEngagementId, Fqdn, InMemoryScopeValidator,
    ScanIntensity as DiscScanIntensity, ScanRequest, ScopeTarget as DiscScopeTarget,
    TenantId as DiscTenantId,
};
use sx_discovery::controller::run_discovery::RunDiscoveryUseCase;
use sx_discovery::scanner::{
    DnsResolverScanner, DnsScannerConfig, HttpFingerprintConfig, HttpFingerprintScanner,
    ScaScanner, ScaScannerConfig, TcpPortProbeConfig, TcpPortProbeScanner,
};
use sx_discovery::service::rate_limiter::{RateLimiter, RateLimiterConfig};
use sx_discovery::service::registry::ScannerRegistry;
use sx_discovery::service::safety_gate::SafetyGate;
use sx_discovery::service::scanner::Scanner;
use sx_engagement::model::engagement::EngagementStatus;
use sx_engagement::model::intensity::ScanIntensity as SxScanIntensity;
use sx_engagement::model::scope_target::ScopeTarget as SxScopeTarget;
use sx_engagement::port::EngagementRepository;
use sx_engagement::service::kill_switch::KillSwitch;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use uuid::Uuid;

/// Per-scanner wall-clock deadline.
const SCANNER_DEADLINE: Duration = Duration::from_secs(60);

/// Bounded concurrency across `(scanner, target)` pairs.
const BOUNDED_CONCURRENCY: usize = 8;

/// Default search paths for the optional `grype` SCA binary.
const GRYPE_SEARCH_PATHS: &[&str] = &["/usr/local/bin/grype", "/opt/homebrew/bin/grype"];

/// Build the discovery adapter.
///
/// The adapter wires the discovery use-case against the shared
/// `engagement_repo` and `kill_switch` provided by the monolith
/// composition root.
///
/// # Errors
///
/// Returns an error if rate-limiter / scanner registration fails (all
/// validation is static so failure here indicates a bug, not user input).
pub(crate) fn build(
    engagement_repo: Arc<dyn EngagementRepository>,
    kill_switch: Arc<dyn KillSwitch>,
) -> anyhow::Result<Arc<dyn RunDiscoveryPort>> {
    let use_case = build_use_case(kill_switch)?;
    Ok(Arc::new(DiscoveryAdapter {
        engagement_repo,
        use_case: Arc::new(use_case),
        runs: Mutex::new(HashMap::new()),
    }))
}

/// Construct the discovery [`RunDiscoveryUseCase`] with the full safety
/// pipeline + production scanner registry.
fn build_use_case(kill_switch: Arc<dyn KillSwitch>) -> anyhow::Result<RunDiscoveryUseCase> {
    // 1. Safety gate.
    //    The validator is the Phase-0 in-memory allow-everything stub; the
    //    long-term plan is to swap in the real `sx_engagement::ScopeValidator`
    //    here. The kill switch, however, is already the production handle the
    //    rest of the monolith trips and observes.
    let validator = Arc::new(InMemoryScopeValidator);
    let bridged_kill = Arc::new(KillSwitchBridge::new(kill_switch));
    let gate = SafetyGate::new(validator, bridged_kill);

    // 2. Rate limiter.
    let limiter_cfg = RateLimiterConfig {
        max_concurrent_probes: 8,
        per_target_rps_limit: 4,
        per_target_burst: 4,
    };
    let limiter = RateLimiter::new(limiter_cfg)
        .map_err(|e| anyhow::anyhow!("discovery rate limiter init failed: {e}"))?;

    // 3. Scanner registry.
    let mut registry = ScannerRegistry::new();
    register_default_scanners(&mut registry)?;

    // 4. Use case.
    let uc = RunDiscoveryUseCase::new(
        Arc::new(registry),
        gate,
        Arc::new(limiter),
        SCANNER_DEADLINE,
        BOUNDED_CONCURRENCY,
    )
    .map_err(|e| anyhow::anyhow!("discovery use-case init failed: {e}"))?;
    Ok(uc)
}

/// Register the four scanners shipped in Phase 1.5. Scanners not yet
/// implemented (`WebAppScanner`, `SecretScanner`, `CspmScanner`) will plug
/// into this exact function — append-only.
fn register_default_scanners(registry: &mut ScannerRegistry) -> anyhow::Result<()> {
    register_dns_scanner(registry)?;
    register_tcp_port_probe_scanner(registry)?;
    register_http_fingerprint_scanner(registry)?;
    register_sca_scanner_if_available(registry);
    Ok(())
}

/// Register the [`DnsResolverScanner`] with the production resolver set.
fn register_dns_scanner(registry: &mut ScannerRegistry) -> anyhow::Result<()> {
    let cfg = DnsScannerConfig {
        resolvers: vec![
            SocketAddr::from(([1, 1, 1, 1], 53)),
            SocketAddr::from(([9, 9, 9, 9], 53)),
        ],
        query_timeout: Duration::from_secs(3),
    };
    let s = DnsResolverScanner::new(cfg).map_err(|e| anyhow::anyhow!("dns scanner init: {e}"))?;
    registry
        .register(Arc::new(s) as Arc<dyn Scanner>)
        .map_err(|e| anyhow::anyhow!("dns scanner register: {e}"))
}

/// Register the [`TcpPortProbeScanner`] with the standard port allow list.
fn register_tcp_port_probe_scanner(registry: &mut ScannerRegistry) -> anyhow::Result<()> {
    let cfg = TcpPortProbeConfig {
        ports: vec![22, 25, 80, 443, 8080, 8443],
        connect_timeout: Duration::from_secs(2),
        banner_read_timeout: Duration::from_secs(1),
        max_banner_bytes: 256,
    };
    let s = TcpPortProbeScanner::new(cfg)
        .map_err(|e| anyhow::anyhow!("tcp port probe scanner init: {e}"))?;
    registry
        .register(Arc::new(s) as Arc<dyn Scanner>)
        .map_err(|e| anyhow::anyhow!("tcp port probe scanner register: {e}"))
}

/// Register the [`HttpFingerprintScanner`].
fn register_http_fingerprint_scanner(registry: &mut ScannerRegistry) -> anyhow::Result<()> {
    let cfg = HttpFingerprintConfig {
        user_agent: "SentinelX-Disco/0.1".to_owned(),
        request_timeout: Duration::from_secs(5),
        max_redirects: 2,
        default_scheme: "https".to_owned(),
    };
    let s = HttpFingerprintScanner::new(cfg)
        .map_err(|e| anyhow::anyhow!("http fingerprint scanner init: {e}"))?;
    registry
        .register(Arc::new(s) as Arc<dyn Scanner>)
        .map_err(|e| anyhow::anyhow!("http fingerprint scanner register: {e}"))
}

/// Optionally register the [`ScaScanner`] — only when a `grype` binary is
/// present at one of the [`GRYPE_SEARCH_PATHS`]. Init / registration
/// failures degrade to a warning; they never abort boot.
fn register_sca_scanner_if_available(registry: &mut ScannerRegistry) {
    let Some(grype) = find_grype() else {
        tracing::info!("sca scanner skipped: grype not found");
        return;
    };
    register_sca_scanner_with_path(registry, grype);
}

/// Build + register a single configured SCA scanner at the resolved
/// `grype_binary` path. Logs any init or registration failure as a
/// warning rather than aborting boot.
fn register_sca_scanner_with_path(registry: &mut ScannerRegistry, grype_binary: PathBuf) {
    let cfg = ScaScannerConfig {
        grype_binary,
        exec_timeout: Duration::from_secs(60),
    };
    let scanner = match ScaScanner::new(cfg) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, "sca scanner init failed");
            return;
        }
    };
    if let Err(e) = registry.register(Arc::new(scanner) as Arc<dyn Scanner>) {
        tracing::warn!(error = %e, "sca scanner registration failed");
    }
}

/// Probe well-known absolute paths for a `grype` binary.
fn find_grype() -> Option<PathBuf> {
    GRYPE_SEARCH_PATHS
        .iter()
        .map(Path::new)
        .find(|p| p.is_file())
        .map(Path::to_path_buf)
}

// ----- Adapter -----------------------------------------------------------

/// `RunDiscoveryPort` implementation.
struct DiscoveryAdapter {
    engagement_repo: Arc<dyn EngagementRepository>,
    use_case: Arc<RunDiscoveryUseCase>,
    runs: Mutex<HashMap<String, RunSummary>>,
}

/// Bookkeeping record stored after a successful discovery run.
#[derive(Debug, Clone)]
#[allow(dead_code)] // observability fields read by future API surface
struct RunSummary {
    /// UUID v7 returned to the caller.
    run_id: String,
    /// Tenant the run executed under.
    tenant_id: String,
    /// Engagement the run executed under.
    engagement_id: String,
    /// Wall-clock start of `use_case.execute(..)`.
    started_at: OffsetDateTime,
    /// Wall-clock end of `use_case.execute(..)`, `None` if execution failed.
    ended_at: Option<OffsetDateTime>,
    /// Total observations summed across all scanner results.
    observation_count: usize,
    /// Number of per-target / per-scanner errors logged by the use case.
    error_count: usize,
    /// `true` if the run was cut short by the kill switch.
    killed: bool,
}

#[async_trait]
impl RunDiscoveryPort for DiscoveryAdapter {
    async fn run(
        &self,
        tenant_id: &str,
        engagement_id: &str,
    ) -> Result<String, DiscoveryPortError> {
        // 1. Parse identifiers.
        let tenant = CoreTenantId::from_str(tenant_id)
            .map_err(|e| DiscoveryPortError::Invalid(format!("tenant_id: {e}")))?;
        let engagement = CoreEngagementId::from_str(engagement_id)
            .map_err(|e| DiscoveryPortError::Invalid(format!("engagement_id: {e}")))?;

        // 2. Look up engagement.
        let loaded = self
            .engagement_repo
            .find_by_id(tenant, engagement)
            .await
            .map_err(|e| DiscoveryPortError::Internal(format!("engagement lookup: {e}")))?
            .ok_or_else(|| DiscoveryPortError::Forbidden("engagement not found".to_owned()))?;

        // 3. Status check.
        if loaded.status != EngagementStatus::Active {
            return Err(DiscoveryPortError::Forbidden(
                "engagement not active".to_owned(),
            ));
        }

        // 4. Translate scope targets.
        let targets = translate_scope(&loaded.scope);

        // 5. Build the discovery-side `Engagement` mirror.
        let intensity = map_intensity(loaded.max_intensity);
        let disc_engagement = DiscEngagement {
            id: DiscEngagementId::from_uuid(loaded.id.into_uuid()),
            tenant_id: DiscTenantId::from_uuid(loaded.tenant_id.into_uuid()),
            allowed_scope: targets.clone(),
            denylist: Vec::new(),
            max_intensity: intensity,
        };

        // 6. Build the `ScanRequest`.
        let scan_req = ScanRequest {
            tenant_id: disc_engagement.tenant_id,
            engagement_id: disc_engagement.id,
            targets,
            intensity,
        };

        // 7. Execute.
        let started_at = OffsetDateTime::now_utc();
        let output = self
            .use_case
            .execute(&disc_engagement, &scan_req, None)
            .await
            .map_err(|e| DiscoveryPortError::Internal(format!("discovery: {e}")))?;
        let ended_at = OffsetDateTime::now_utc();

        // 8. Bookkeeping.
        let observations: usize = output
            .results
            .iter()
            .map(sx_discovery::model::ScanResult::observation_count)
            .sum();
        let errors = output.errors.len();
        let killed = output.killed;
        let run_id = Uuid::now_v7().to_string();

        {
            let mut runs = self.runs.lock().await;
            runs.insert(
                run_id.clone(),
                RunSummary {
                    run_id: run_id.clone(),
                    tenant_id: tenant_id.to_owned(),
                    engagement_id: engagement_id.to_owned(),
                    started_at,
                    ended_at: Some(ended_at),
                    observation_count: observations,
                    error_count: errors,
                    killed,
                },
            );
        }

        // 9. Structured completion log.
        tracing::info!(
            run_id = %run_id,
            tenant_id = %tenant_id,
            engagement_id = %engagement_id,
            observations = observations,
            errors = errors,
            killed = killed,
            "discovery.run.complete"
        );

        Ok(run_id)
    }
}

// ----- Intensity & scope-target translation ------------------------------

/// Monotonic mapping from `sx-engagement` intensity ladder to the
/// discovery-side ladder. See the module doc table for rationale.
const fn map_intensity(intensity: SxScanIntensity) -> DiscScanIntensity {
    match intensity {
        SxScanIntensity::Theoretical | SxScanIntensity::PassiveValidation => {
            DiscScanIntensity::Passive
        }
        SxScanIntensity::SafeInteractive => DiscScanIntensity::Light,
        SxScanIntensity::ActiveExploit => DiscScanIntensity::Standard,
        SxScanIntensity::RedTeam => DiscScanIntensity::Aggressive,
    }
}

/// Translate the engagement-side scope into discovery-side targets,
/// dropping unsupported variants with a warning.
fn translate_scope(scope: &[SxScopeTarget]) -> Vec<DiscScopeTarget> {
    scope.iter().filter_map(translate_one_target).collect()
}

/// Translate a single engagement-side [`SxScopeTarget`] into a
/// discovery-side [`DiscScopeTarget`]. Returns `None` for variants no
/// discovery scanner consumes; the caller logs the drop.
fn translate_one_target(t: &SxScopeTarget) -> Option<DiscScopeTarget> {
    match t {
        SxScopeTarget::Cidr(net) => Some(DiscScopeTarget::Cidr(*net)),
        SxScopeTarget::IpV4(ip) => Some(DiscScopeTarget::Ip(IpAddr::V4(*ip))),
        SxScopeTarget::IpV6(ip) => Some(DiscScopeTarget::Ip(IpAddr::V6(*ip))),
        SxScopeTarget::Domain(d) => translate_domain_target(d),
        SxScopeTarget::Url(u) => Some(DiscScopeTarget::Url(u.clone())),
        SxScopeTarget::Arn(a) => {
            tracing::warn!(arn = %a, "dropping arn target: no discovery scanner consumes arn");
            None
        }
        SxScopeTarget::RepoUrl(r) => {
            tracing::warn!(repo = %r, "dropping repo_url target: no discovery scanner consumes repo urls");
            None
        }
    }
}

/// Build an [`Fqdn`] from a raw domain string, logging + dropping invalid
/// inputs. Extracted from [`translate_one_target`] to keep the cognitive
/// complexity inside clippy's pedantic ceiling.
fn translate_domain_target(d: &str) -> Option<DiscScopeTarget> {
    match Fqdn::new(d) {
        Ok(f) => Some(DiscScopeTarget::Domain(f)),
        Err(e) => {
            tracing::warn!(domain = %d, error = %e, "dropping invalid domain target");
            None
        }
    }
}

// ----- Kill switch bridge ------------------------------------------------

/// Bridges the `sx-engagement` [`KillSwitch`] (broadcast-channel based) to
/// the discovery-crate [`sx_discovery::contracts::KillSwitch`] (notify
/// based). The bridge polls `is_tripped` synchronously for the gate
/// check, and exposes a fresh `Notify` per subscription that is fired
/// when the underlying broadcast receiver yields a `KillSwitchEvent` for
/// any of the subscribed scopes.
#[derive(Debug)]
struct KillSwitchBridge {
    inner: Arc<dyn KillSwitch>,
}

impl KillSwitchBridge {
    fn new(inner: Arc<dyn KillSwitch>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl sx_discovery::contracts::KillSwitch for KillSwitchBridge {
    async fn is_tripped(&self, scopes: &[sx_discovery::contracts::KillSwitchScope]) -> bool {
        for s in scopes {
            // The discovery enum lacks the (tenant, engagement) pairing the
            // engagement crate carries; we map to `Global` / `Tenant(_)` and
            // skip discovery-side `Engagement(_)` (the engagement crate's
            // `Engagement(tenant, id)` form is not reconstructable here
            // because we lack the tenant binding).
            let mapped = match s {
                sx_discovery::contracts::KillSwitchScope::Global => {
                    sx_engagement::service::kill_switch::KillSwitchScope::Global
                }
                sx_discovery::contracts::KillSwitchScope::Tenant(tid) => {
                    sx_engagement::service::kill_switch::KillSwitchScope::Tenant(
                        sx_core::value_object::ids::TenantId::from_uuid(*tid.as_uuid()),
                    )
                }
                sx_discovery::contracts::KillSwitchScope::Engagement(_) => continue,
            };
            match self.inner.is_tripped(mapped).await {
                Ok(true) => return true,
                Ok(false) => {}
                Err(e) => {
                    tracing::warn!(error = %e, "kill switch is_tripped query failed");
                }
            }
        }
        false
    }

    fn subscribe(
        &self,
        scopes: &[sx_discovery::contracts::KillSwitchScope],
    ) -> Arc<tokio::sync::Notify> {
        let notify = Arc::new(tokio::sync::Notify::new());
        let mut rx = self.inner.subscribe();
        let scopes = scopes.to_vec();
        let notify_clone = Arc::clone(&notify);
        tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        if scope_matches(&event.scope, &scopes) {
                            notify_clone.notify_waiters();
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Conservative: notify on lag so observers re-check
                        // `is_tripped` rather than miss a trip event.
                        notify_clone.notify_waiters();
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
        notify
    }
}

/// Returns `true` if the engagement-side `event_scope` overlaps any of the
/// discovery-side `subscribed` scopes.
fn scope_matches(
    event_scope: &sx_engagement::service::kill_switch::KillSwitchScope,
    subscribed: &[sx_discovery::contracts::KillSwitchScope],
) -> bool {
    use sx_discovery::contracts::KillSwitchScope as DScope;
    use sx_engagement::service::kill_switch::KillSwitchScope as ESScope;
    for s in subscribed {
        let hit = match (event_scope, s) {
            (ESScope::Global, _) | (_, DScope::Global) => true,
            (ESScope::Tenant(t1), DScope::Tenant(t2)) => t1.as_uuid() == t2.as_uuid(),
            (ESScope::Engagement(_, eid), DScope::Engagement(eid2)) => {
                eid.as_uuid() == eid2.as_uuid()
            }
            _ => false,
        };
        if hit {
            return true;
        }
    }
    false
}

// ----- Tests --------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    use super::*;
    use sx_engagement::error::EngagementError;
    use sx_engagement::model::engagement::Engagement as SxEngagement;
    use sx_engagement::model::window::TimeWindow;
    use time::Duration as TimeDuration;
    use tokio::sync::broadcast;

    /// Build a `RunDiscoveryUseCase` with an empty registry — used by the
    /// "no scanners match" test. Lets us exercise the adapter end-to-end
    /// without firing real network calls.
    fn build_empty_use_case() -> RunDiscoveryUseCase {
        let validator = Arc::new(InMemoryScopeValidator);
        let kill = Arc::new(NeverTrippedKill);
        let gate = SafetyGate::new(validator, kill);
        let limiter = RateLimiter::new(RateLimiterConfig {
            max_concurrent_probes: 1,
            per_target_rps_limit: 1,
            per_target_burst: 1,
        })
        .unwrap();
        RunDiscoveryUseCase::new(
            Arc::new(ScannerRegistry::new()),
            gate,
            Arc::new(limiter),
            Duration::from_secs(5),
            1,
        )
        .unwrap()
    }

    /// Stub kill switch for tests — never tripped, no subscribers wake.
    #[derive(Debug)]
    struct NeverTrippedKill;

    #[async_trait]
    impl sx_discovery::contracts::KillSwitch for NeverTrippedKill {
        async fn is_tripped(&self, _: &[sx_discovery::contracts::KillSwitchScope]) -> bool {
            false
        }
        fn subscribe(
            &self,
            _: &[sx_discovery::contracts::KillSwitchScope],
        ) -> Arc<tokio::sync::Notify> {
            Arc::new(tokio::sync::Notify::new())
        }
    }

    /// Fake `EngagementRepository` used by tests.
    #[derive(Debug, Default)]
    struct FakeRepo {
        rows: StdMutex<HashMap<(CoreTenantId, CoreEngagementId), SxEngagement>>,
        fail_lookup: bool,
    }

    impl FakeRepo {
        fn insert(&self, e: SxEngagement) {
            self.rows.lock().unwrap().insert((e.tenant_id, e.id), e);
        }
    }

    #[async_trait]
    impl EngagementRepository for FakeRepo {
        async fn create(&self, e: &SxEngagement) -> Result<(), EngagementError> {
            self.rows
                .lock()
                .unwrap()
                .insert((e.tenant_id, e.id), e.clone());
            Ok(())
        }
        async fn find_by_id(
            &self,
            tenant_id: CoreTenantId,
            id: CoreEngagementId,
        ) -> Result<Option<SxEngagement>, EngagementError> {
            if self.fail_lookup {
                return Err(EngagementError::internal("forced failure"));
            }
            Ok(self.rows.lock().unwrap().get(&(tenant_id, id)).cloned())
        }
        async fn update(&self, _e: &SxEngagement) -> Result<(), EngagementError> {
            Ok(())
        }
    }

    /// Test-only kill switch shim implementing `sx_engagement::KillSwitch`.
    /// Always reports un-tripped; subscribers receive a no-op channel.
    #[derive(Debug)]
    struct StubKill {
        tx: broadcast::Sender<sx_engagement::service::kill_switch::KillSwitchEvent>,
    }

    impl StubKill {
        fn new() -> Self {
            let (tx, _rx) = broadcast::channel(4);
            Self { tx }
        }
    }

    #[async_trait]
    impl KillSwitch for StubKill {
        async fn trip(
            &self,
            _scope: sx_engagement::service::kill_switch::KillSwitchScope,
            _reason: sx_engagement::service::kill_switch::KillReason,
        ) -> Result<(), EngagementError> {
            Ok(())
        }
        async fn is_tripped(
            &self,
            _scope: sx_engagement::service::kill_switch::KillSwitchScope,
        ) -> Result<bool, EngagementError> {
            Ok(false)
        }
        fn subscribe(
            &self,
        ) -> broadcast::Receiver<sx_engagement::service::kill_switch::KillSwitchEvent> {
            self.tx.subscribe()
        }
    }

    fn make_engagement(
        tenant: CoreTenantId,
        status: EngagementStatus,
        scope: Vec<SxScopeTarget>,
    ) -> SxEngagement {
        let now = OffsetDateTime::now_utc();
        let window = TimeWindow::new(now, now + TimeDuration::hours(1)).unwrap();
        let mut e = SxEngagement::new_draft(
            CoreEngagementId::new(),
            tenant,
            "test",
            scope,
            window,
            SxScanIntensity::PassiveValidation,
            now,
        )
        .unwrap();
        if status != EngagementStatus::Draft {
            // Walk the FSM forward — Draft → Active is the only allowed first hop.
            e.transition_to(EngagementStatus::Active, now + TimeDuration::seconds(1))
                .unwrap();
            if status != EngagementStatus::Active {
                e.transition_to(status, now + TimeDuration::seconds(2))
                    .unwrap();
            }
        }
        e
    }

    fn adapter_with_use_case(
        repo: Arc<dyn EngagementRepository>,
        uc: RunDiscoveryUseCase,
    ) -> DiscoveryAdapter {
        DiscoveryAdapter {
            engagement_repo: repo,
            use_case: Arc::new(uc),
            runs: Mutex::new(HashMap::new()),
        }
    }

    #[test]
    fn intensity_mapping_is_monotonic() {
        let ladder = [
            SxScanIntensity::Theoretical,
            SxScanIntensity::PassiveValidation,
            SxScanIntensity::SafeInteractive,
            SxScanIntensity::ActiveExploit,
            SxScanIntensity::RedTeam,
        ];
        let mut last_rank: i32 = -1;
        for (i, sx) in ladder.iter().enumerate() {
            let mapped = map_intensity(*sx);
            let rank: i32 = match mapped {
                DiscScanIntensity::Passive => 0,
                DiscScanIntensity::Light => 1,
                DiscScanIntensity::Standard => 2,
                DiscScanIntensity::Aggressive => 3,
            };
            assert!(
                rank >= last_rank,
                "intensity mapping not monotonic at index {i}: {sx:?} -> {mapped:?}",
            );
            last_rank = rank;
        }
        // Spot-check the extremes.
        assert!(matches!(
            map_intensity(SxScanIntensity::Theoretical),
            DiscScanIntensity::Passive
        ));
        assert!(matches!(
            map_intensity(SxScanIntensity::RedTeam),
            DiscScanIntensity::Aggressive
        ));
    }

    #[test]
    fn scope_target_translation_drops_arn() {
        let scope = vec![
            SxScopeTarget::Domain("example.com".to_owned()),
            SxScopeTarget::Arn("arn:aws:s3:::bucket".to_owned()),
            SxScopeTarget::RepoUrl("https://github.com/o/r.git".to_owned()),
        ];
        let out = translate_scope(&scope);
        assert_eq!(out.len(), 1, "arn + repo_url should both be dropped");
        assert!(matches!(
            out.first().expect("len is 1"),
            DiscScopeTarget::Domain(_)
        ));
    }

    #[tokio::test]
    async fn run_returns_invalid_for_bad_uuid() {
        let repo: Arc<dyn EngagementRepository> = Arc::new(FakeRepo::default());
        let adapter = adapter_with_use_case(repo, build_empty_use_case());
        let err = adapter.run("not-a-uuid", "also-not").await.unwrap_err();
        assert!(matches!(err, DiscoveryPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn run_returns_forbidden_when_engagement_missing() {
        let repo: Arc<dyn EngagementRepository> = Arc::new(FakeRepo::default());
        let adapter = adapter_with_use_case(repo, build_empty_use_case());
        let tenant = CoreTenantId::new();
        let engagement = CoreEngagementId::new();
        let err = adapter
            .run(&tenant.to_string(), &engagement.to_string())
            .await
            .unwrap_err();
        assert!(matches!(err, DiscoveryPortError::Forbidden(_)));
    }

    #[tokio::test]
    async fn run_returns_forbidden_when_engagement_inactive() {
        let repo = Arc::new(FakeRepo::default());
        let tenant = CoreTenantId::new();
        let eng = make_engagement(
            tenant,
            EngagementStatus::Draft,
            vec![SxScopeTarget::Domain("example.com".to_owned())],
        );
        let engagement_id = eng.id;
        repo.insert(eng);
        let adapter = adapter_with_use_case(repo, build_empty_use_case());
        let err = adapter
            .run(&tenant.to_string(), &engagement_id.to_string())
            .await
            .unwrap_err();
        let DiscoveryPortError::Forbidden(msg) = err else {
            unreachable!("expected DiscoveryPortError::Forbidden");
        };
        assert!(msg.contains("not active"), "got: {msg}");
    }

    #[tokio::test]
    async fn run_returns_run_id_for_active_engagement_with_no_scanners_matching() {
        let repo = Arc::new(FakeRepo::default());
        let tenant = CoreTenantId::new();
        let eng = make_engagement(
            tenant,
            EngagementStatus::Active,
            vec![SxScopeTarget::Domain("example.com".to_owned())],
        );
        let engagement_id = eng.id;
        repo.insert(eng);
        let adapter = adapter_with_use_case(repo, build_empty_use_case());
        let run_id = adapter
            .run(&tenant.to_string(), &engagement_id.to_string())
            .await
            .expect("active engagement + empty registry should succeed");
        // run_id is a valid UUID v7 string.
        assert!(Uuid::parse_str(&run_id).is_ok());

        // Summary recorded with zero observations / errors.
        let runs = adapter.runs.lock().await;
        let summary = runs.get(&run_id).expect("summary stored");
        assert_eq!(summary.observation_count, 0);
        assert_eq!(summary.error_count, 0);
        assert!(!summary.killed);
    }

    #[tokio::test]
    async fn kill_switch_bridge_reports_untripped_by_default() {
        use sx_discovery::contracts::KillSwitch as DiscKillSwitch;
        let kill: Arc<dyn KillSwitch> = Arc::new(StubKill::new());
        let bridge = KillSwitchBridge::new(kill);
        let tripped = DiscKillSwitch::is_tripped(
            &bridge,
            &[sx_discovery::contracts::KillSwitchScope::Global],
        )
        .await;
        assert!(!tripped);
    }
}
