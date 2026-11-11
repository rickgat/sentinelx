//! AI Red Team chain-composer adapter.
//!
//! Wires [`sx_autonomy::redteam::compose`] behind the
//! [`sx_api::port::RedteamPort`]. The adapter is intentionally thin:
//!
//! 1. Parse the request's `engagement_id` as a UUID under the supplied
//!    tenant id (the controller sources `tenant_id` from the bearer token).
//! 2. Look up the engagement via the shared `EngagementRepository`. A
//!    missing engagement surfaces as [`Phase3PortError::NotFound`].
//! 3. Derive a [`TargetSpec`] from the engagement's scope: the target is
//!    flagged as `internet_facing` when at least one scope entry is a
//!    `Url` or `Domain` (or a public IP/CIDR); otherwise the spec is
//!    treated as `internal`. The platform tag is `web` when any scope
//!    entry is a URL, otherwise empty (the embedded catalogue contains
//!    plenty of platform-agnostic entries so an empty list is fine).
//!    The maximum intensity is always capped at `SafeInteractive` — the
//!    composer hard-fails non-safe-mode entries anyway, so this is a
//!    redundant but explicit guard.
//! 4. Call [`compose`] against the static [`EmbeddedCatalogue`] with
//!    `max_steps` taken from the request.
//! 5. Project the resulting [`AttackChain`] into the
//!    [`RedteamChainView`] wire shape, computing `chain_score` via the
//!    shipped scoring helper (product of step confidences, floored at
//!    `1e-6`).
//!
//! ## Safety contract
//!
//! - No `unsafe` — the workspace already forbids it; the adapter does not
//!   introduce any.
//! - No `unwrap`/`expect`/`panic!` on production paths; every fallible
//!   call routes through [`Phase3PortError`].
//! - The composer never emits unsafe (`ActiveExploit`-required) techniques
//!   even if a catalogue offered them — the embedded catalogue here is the
//!   shipped safe-mode list.

use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use sx_api::port::{Phase3PortError, RedteamPort};
use sx_api::view::redteam_view::{ChainStepView, RedteamChainView, RedteamComposeRequest};
use sx_autonomy::redteam::chain::AttackChain;
use sx_autonomy::redteam::scoring::chain_score;
use sx_autonomy::redteam::selector::{compose, EmbeddedCatalogue, TargetSpec};
use sx_core::value_object::ids::{EngagementId, TenantId};
use sx_core::value_object::intensity::ScanIntensity;
use sx_engagement::model::scope_target::ScopeTarget;
use sx_engagement::port::EngagementRepository;

/// Maximum number of steps the HTTP layer will ever pass through. Mirrors
/// the view-layer validator (1..=14). The adapter re-checks defensively
/// because validation is a wire-layer concern; if a future caller skips it
/// we still clamp.
const MAX_STEPS_CEIL: u8 = 14;

/// Bundle returned by [`build`]. Currently a single field but kept as a
/// struct so future Red Team capabilities (e.g. multi-target composers,
/// custom catalogues) can be added without breaking the call site.
pub(crate) struct RedteamBundle {
    /// The trait object the API state slot binds to.
    pub redteam: Arc<dyn RedteamPort>,
}

/// Build the Red Team adapter against the supplied engagement repository.
///
/// The repository must support `find_by_id(tenant, engagement)`. The
/// adapter does not own the repository — it holds an `Arc` reference and
/// shares it with the rest of the composition root.
pub(crate) fn build(engagement_repo: Arc<dyn EngagementRepository>) -> RedteamBundle {
    let adapter = RedteamAdapter {
        engagement_repo,
        catalogue: EmbeddedCatalogue,
    };
    RedteamBundle {
        redteam: Arc::new(adapter),
    }
}

/// `RedteamPort` implementation.
struct RedteamAdapter {
    engagement_repo: Arc<dyn EngagementRepository>,
    catalogue: EmbeddedCatalogue,
}

#[async_trait]
impl RedteamPort for RedteamAdapter {
    async fn compose(
        &self,
        tenant_id: &str,
        req: RedteamComposeRequest,
    ) -> Result<RedteamChainView, Phase3PortError> {
        // 1. Parse identifiers. Bad inputs surface as Invalid (422).
        let tenant = parse_tenant(tenant_id)?;
        let engagement_id = parse_engagement_id(&req.engagement_id)?;

        // 2. Look up the engagement. Missing rows are NotFound (404).
        let engagement = self
            .engagement_repo
            .find_by_id(tenant, engagement_id)
            .await
            .map_err(|e| Phase3PortError::Dependency(format!("engagement lookup: {e}")))?
            .ok_or(Phase3PortError::NotFound)?;

        // 3. Derive the TargetSpec from the engagement's scope.
        let target = derive_target_spec(&engagement.scope);

        // 4. Compose the chain with a defensively-clamped max_steps.
        let max_steps = req.max_steps.min(MAX_STEPS_CEIL);
        let chain = compose(&target, &self.catalogue, max_steps);

        // 5. Project into the wire shape.
        Ok(project_chain(&chain))
    }
}

/// Translate a list of scope targets into a [`TargetSpec`].
///
/// Heuristics:
/// - `internet_facing` is `true` when any scope entry is a `Url`, `Domain`,
///   or a public IP (`IpV4` / `IpV6` / `Cidr`). The current implementation
///   classifies any non-`Domain`/non-`Url` IP as internal-only because the
///   composer's embedded catalogue does not yet distinguish public vs.
///   RFC1918 ranges — a future refinement can call into
///   `IpAddr::is_global` once stabilised.
/// - `platforms` includes `"web"` when any scope entry is a `Url`. The
///   embedded catalogue is otherwise platform-agnostic, so leaving the
///   list empty when no URL is in scope yields broad coverage.
/// - `max_intensity` is always `SafeInteractive`. The composer hard-fails
///   anything above this; setting it explicitly makes the policy obvious
///   in the trace.
fn derive_target_spec(scope: &[ScopeTarget]) -> TargetSpec {
    let internet_facing = scope.iter().any(is_internet_facing);
    let mut platforms: Vec<&'static str> = Vec::new();
    if scope.iter().any(|t| matches!(t, ScopeTarget::Url(_))) {
        platforms.push("web");
    }
    TargetSpec::new(platforms, internet_facing, ScanIntensity::SafeInteractive)
}

/// Return `true` when the scope entry suggests an internet-facing target.
const fn is_internet_facing(t: &ScopeTarget) -> bool {
    matches!(t, ScopeTarget::Url(_) | ScopeTarget::Domain(_))
}

/// Project an [`AttackChain`] into the [`RedteamChainView`] wire shape.
fn project_chain(chain: &AttackChain) -> RedteamChainView {
    let steps = chain
        .steps
        .iter()
        .map(|s| ChainStepView {
            phase: s.phase.to_string(),
            technique_id: s.technique_id.clone(),
            confidence: s.confidence,
        })
        .collect();
    let score = chain_score(chain);
    RedteamChainView {
        steps,
        chain_score: score,
    }
}

fn parse_tenant(s: &str) -> Result<TenantId, Phase3PortError> {
    let id = uuid::Uuid::from_str(s)
        .map_err(|_| Phase3PortError::Invalid("invalid tenant id".to_owned()))?;
    Ok(TenantId::from_uuid(id))
}

fn parse_engagement_id(s: &str) -> Result<EngagementId, Phase3PortError> {
    let id = uuid::Uuid::from_str(s)
        .map_err(|_| Phase3PortError::Invalid("invalid engagement id".to_owned()))?;
    Ok(EngagementId::from_uuid(id))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::float_cmp,
    clippy::cast_possible_wrap
)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    use super::*;
    use sx_autonomy::redteam::scoring::MIN_CHAIN_SCORE;
    use sx_engagement::error::EngagementError;
    use sx_engagement::model::engagement::{Engagement, EngagementStatus};
    use sx_engagement::model::intensity::ScanIntensity as SxScanIntensity;
    use sx_engagement::model::window::TimeWindow;
    use time::Duration as TimeDuration;
    use time::OffsetDateTime;

    /// In-memory repo used in tests.
    #[derive(Debug, Default)]
    struct FakeRepo {
        rows: StdMutex<HashMap<(TenantId, EngagementId), Engagement>>,
    }

    impl FakeRepo {
        fn insert(&self, e: Engagement) {
            self.rows.lock().unwrap().insert((e.tenant_id, e.id), e);
        }
    }

    #[async_trait]
    impl EngagementRepository for FakeRepo {
        async fn create(&self, e: &Engagement) -> Result<(), EngagementError> {
            self.rows
                .lock()
                .unwrap()
                .insert((e.tenant_id, e.id), e.clone());
            Ok(())
        }
        async fn find_by_id(
            &self,
            tenant: TenantId,
            id: EngagementId,
        ) -> Result<Option<Engagement>, EngagementError> {
            Ok(self.rows.lock().unwrap().get(&(tenant, id)).cloned())
        }
        async fn update(&self, _e: &Engagement) -> Result<(), EngagementError> {
            Ok(())
        }
    }

    fn make_engagement(tenant: TenantId, eid: EngagementId, scope: Vec<ScopeTarget>) -> Engagement {
        let now = OffsetDateTime::UNIX_EPOCH;
        let window = TimeWindow::new(now, now + TimeDuration::hours(2)).unwrap();
        let mut e = Engagement::new_draft(
            eid,
            tenant,
            "redteam test",
            scope,
            window,
            SxScanIntensity::SafeInteractive,
            now,
        )
        .unwrap();
        e.transition_to(EngagementStatus::Active, now + TimeDuration::seconds(1))
            .unwrap();
        e
    }

    fn fixed_tenant() -> TenantId {
        TenantId::from_uuid(uuid::Uuid::parse_str("01010101-0101-0101-0101-010101010101").unwrap())
    }

    fn fixed_engagement() -> EngagementId {
        EngagementId::from_uuid(
            uuid::Uuid::parse_str("a0000000-0000-0000-0000-000000000001").unwrap(),
        )
    }

    fn web_url() -> ScopeTarget {
        ScopeTarget::Url(url::Url::parse("https://example.com").unwrap())
    }

    #[tokio::test]
    async fn missing_engagement_returns_not_found() {
        let repo: Arc<dyn EngagementRepository> = Arc::new(FakeRepo::default());
        let bundle = build(repo);
        let req = RedteamComposeRequest {
            engagement_id: fixed_engagement().to_string(),
            max_steps: 8,
        };
        let err = bundle
            .redteam
            .compose(&fixed_tenant().to_string(), req)
            .await
            .expect_err("missing engagement must error");
        assert!(matches!(err, Phase3PortError::NotFound));
    }

    #[tokio::test]
    async fn bad_engagement_uuid_is_invalid() {
        let repo: Arc<dyn EngagementRepository> = Arc::new(FakeRepo::default());
        let bundle = build(repo);
        let req = RedteamComposeRequest {
            engagement_id: "not-a-uuid".into(),
            max_steps: 4,
        };
        let err = bundle
            .redteam
            .compose(&fixed_tenant().to_string(), req)
            .await
            .expect_err("bad uuid must error");
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    #[tokio::test]
    async fn bad_tenant_uuid_is_invalid() {
        let repo: Arc<dyn EngagementRepository> = Arc::new(FakeRepo::default());
        let bundle = build(repo);
        let req = RedteamComposeRequest {
            engagement_id: fixed_engagement().to_string(),
            max_steps: 4,
        };
        let err = bundle
            .redteam
            .compose("not-a-uuid", req)
            .await
            .expect_err("bad tenant uuid must error");
        assert!(matches!(err, Phase3PortError::Invalid(_)));
    }

    #[tokio::test]
    async fn produces_monotonic_phases_for_web_target() {
        let repo = Arc::new(FakeRepo::default());
        let tenant = fixed_tenant();
        let eid = fixed_engagement();
        repo.insert(make_engagement(tenant, eid, vec![web_url()]));
        let bundle = build(repo as Arc<dyn EngagementRepository>);
        let req = RedteamComposeRequest {
            engagement_id: eid.to_string(),
            max_steps: 14,
        };
        let view = bundle
            .redteam
            .compose(&tenant.to_string(), req)
            .await
            .expect("compose should succeed");
        assert!(!view.steps.is_empty(), "expected a non-empty chain");
        // Phases are emitted as snake_case strings; compare by ordinal via
        // re-mapping. The composer guarantees monotonic non-decreasing
        // phases, which manifests in the wire shape as identical-or-later
        // canonical ordering when projected through `KillChainPhase::all`.
        let canonical: Vec<&str> = sx_autonomy::redteam::chain::KillChainPhase::all()
            .iter()
            .map(|p| match *p {
                sx_autonomy::redteam::chain::KillChainPhase::Reconnaissance => "reconnaissance",
                sx_autonomy::redteam::chain::KillChainPhase::ResourceDevelopment => {
                    "resource_development"
                }
                sx_autonomy::redteam::chain::KillChainPhase::InitialAccess => "initial_access",
                sx_autonomy::redteam::chain::KillChainPhase::Execution => "execution",
                sx_autonomy::redteam::chain::KillChainPhase::Persistence => "persistence",
                sx_autonomy::redteam::chain::KillChainPhase::PrivilegeEscalation => {
                    "privilege_escalation"
                }
                sx_autonomy::redteam::chain::KillChainPhase::DefenseEvasion => "defense_evasion",
                sx_autonomy::redteam::chain::KillChainPhase::CredentialAccess => {
                    "credential_access"
                }
                sx_autonomy::redteam::chain::KillChainPhase::Discovery => "discovery",
                sx_autonomy::redteam::chain::KillChainPhase::LateralMovement => "lateral_movement",
                sx_autonomy::redteam::chain::KillChainPhase::Collection => "collection",
                sx_autonomy::redteam::chain::KillChainPhase::CommandAndControl => {
                    "command_and_control"
                }
                sx_autonomy::redteam::chain::KillChainPhase::Exfiltration => "exfiltration",
                sx_autonomy::redteam::chain::KillChainPhase::Impact => "impact",
            })
            .collect();
        let mut last_idx: i32 = -1;
        for s in &view.steps {
            let idx = canonical
                .iter()
                .position(|p| *p == s.phase.as_str())
                .map_or(usize::MAX, |i| i);
            assert!(
                idx as i32 >= last_idx,
                "phases not monotonic: {} after index {last_idx}",
                s.phase
            );
            last_idx = idx as i32;
        }
    }

    #[tokio::test]
    async fn chain_score_is_product_of_step_confidences() {
        let repo = Arc::new(FakeRepo::default());
        let tenant = fixed_tenant();
        let eid = fixed_engagement();
        repo.insert(make_engagement(tenant, eid, vec![web_url()]));
        let bundle = build(repo as Arc<dyn EngagementRepository>);
        let req = RedteamComposeRequest {
            engagement_id: eid.to_string(),
            max_steps: 5,
        };
        let view = bundle
            .redteam
            .compose(&tenant.to_string(), req)
            .await
            .expect("compose should succeed");
        let manual: f64 = view.steps.iter().map(|s| s.confidence).product();
        let expected = manual.max(MIN_CHAIN_SCORE);
        assert!((view.chain_score - expected).abs() < 1e-12);
    }

    #[tokio::test]
    async fn max_steps_three_emits_at_most_three_steps() {
        let repo = Arc::new(FakeRepo::default());
        let tenant = fixed_tenant();
        let eid = fixed_engagement();
        repo.insert(make_engagement(tenant, eid, vec![web_url()]));
        let bundle = build(repo as Arc<dyn EngagementRepository>);
        let req = RedteamComposeRequest {
            engagement_id: eid.to_string(),
            max_steps: 3,
        };
        let view = bundle
            .redteam
            .compose(&tenant.to_string(), req)
            .await
            .expect("compose should succeed");
        assert!(
            view.steps.len() <= 3,
            "expected <=3 steps, got {}",
            view.steps.len()
        );
    }

    #[test]
    fn derive_target_spec_flags_web_url_as_internet_facing() {
        let target = derive_target_spec(&[web_url()]);
        assert!(target.internet_facing);
        assert!(target.platforms.iter().any(|p| p == "web"));
        assert_eq!(target.max_intensity, ScanIntensity::SafeInteractive);
    }

    #[test]
    fn derive_target_spec_internal_only_when_no_domain_or_url() {
        let target = derive_target_spec(&[ScopeTarget::Cidr(
            ipnet::IpNet::from_str("10.0.0.0/8").unwrap(),
        )]);
        assert!(!target.internet_facing);
        // Empty platforms is fine — the embedded catalogue is largely
        // platform-agnostic.
        assert!(target.platforms.is_empty());
    }

    #[test]
    fn derive_target_spec_flags_domain_as_internet_facing() {
        let target = derive_target_spec(&[ScopeTarget::Domain("example.com".into())]);
        assert!(target.internet_facing);
        // No URL in scope -> no "web" platform tag.
        assert!(target.platforms.is_empty());
    }
}
