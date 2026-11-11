//! Concrete adapter behind [`sx_api::port::EngagementClonePort`].
//!
//! Backs `POST /v1/engagements/{id}/clone`: reads the source engagement
//! from the shared [`InMemoryEngagementRepository`], constructs a fresh
//! `Draft` engagement via [`Engagement::new_draft`] with a freshly
//! minted uuid (v7), and writes it back through
//! [`InMemoryEngagementRepository::seed_one`].
//!
//! ## Semantics
//!
//! - `scope` is copied verbatim from the source.
//! - `window` is shifted so the clone starts at `OffsetDateTime::now_utc()`
//!   and preserves the source's `(end - start)` duration verbatim.
//!   This avoids accidentally cloning an engagement whose authorisation
//!   window has already expired.
//! - `max_intensity` is preserved.
//! - `status` is always `Draft` — fresh aggregate, fresh approval ledger.
//! - When `req.new_name` is supplied the clone uses it as the name (the
//!   HTTP surface enforces `1..=200` chars). When `None`, the adapter
//!   mints the default `"{source.name} (clone)"`.
//!
//! ## Why a bundle
//!
//! Mirrors the convention used by the other write-side adapters
//! ([`crate::adapters::asset_write`], [`crate::adapters::tenant_write`]):
//! a single struct exposes the trait object so the composition root in
//! [`crate::adapters::mod`] can pick the port off one handle.
//!
//! ## Errors
//!
//! - `EngagementPortError::NotFound` — the source uuid does not match an
//!   engagement under `tenant_id`.
//! - `EngagementPortError::Invalid` — `tenant_id` or `source_id` are not
//!   parseable uuids; or the in-memory repo is mid-poison (the secondary
//!   guard around `seed_one` swallows the race silently — see the
//!   `seed_one` rationale on `InMemoryEngagementRepository`).
//! - `EngagementPortError::Dependency` — the source's window math
//!   overflowed (would require a window > i64 nanoseconds).
//! - `EngagementPortError::Internal` — `Engagement::new_draft` rejected
//!   the synthesised aggregate (e.g. an empty name slipped past the HTTP
//!   validator).

#![forbid(unsafe_code)]

use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use sx_api::port::{EngagementClonePort, EngagementPortError};
use sx_api::view::engagement_view::{CloneEngagementRequest, EngagementView};
use sx_core::value_object::ids::{EngagementId, TenantId};
use sx_engagement::model::engagement::{Engagement, EngagementStatus};
use sx_engagement::model::window::TimeWindow;
use sx_engagement::port::EngagementRepository;
use sx_engagement::EngagementError;
use time::OffsetDateTime;

// Concrete repo is used only by the tests (seed_one + direct find_by_id);
// the production clone path operates through the EngagementRepository trait.
#[cfg(test)]
use crate::adapters::engagement::InMemoryEngagementRepository;

/// Bundle exposing the single clone-side trait object.
pub(crate) struct EngagementCloneBundle {
    /// Trait object plugged into [`sx_api::AppState::engagement_clone`].
    pub clone_port: Arc<dyn EngagementClonePort>,
}

impl EngagementCloneBundle {
    /// Build the bundle from the shared in-memory engagement repository.
    ///
    /// The repository handle is *shared* with
    /// [`crate::adapters::engagement::EngagementBundle::repo`] so the
    /// clone-side adapter sees the same rows the read / transition
    /// adapters do.
    pub(crate) fn build(repo: Arc<dyn EngagementRepository>) -> Self {
        let adapter = InMemoryEngagementCloneAdapter { repo };
        Self {
            clone_port: Arc::new(adapter),
        }
    }
}

/// In-memory implementation of [`EngagementClonePort`] over the shared
/// [`InMemoryEngagementRepository`].
struct InMemoryEngagementCloneAdapter {
    repo: Arc<dyn EngagementRepository>,
}

#[async_trait]
impl EngagementClonePort for InMemoryEngagementCloneAdapter {
    #[allow(clippy::similar_names)]
    async fn clone_engagement(
        &self,
        tenant_id: &str,
        source_id: &str,
        req: CloneEngagementRequest,
    ) -> Result<EngagementView, EngagementPortError> {
        let tenant = parse_tenant(tenant_id)?;
        let source_eid = parse_engagement_id(source_id)?;
        let source = self
            .repo
            .find_by_id(tenant, source_eid)
            .await
            .map_err(domain_err)?
            .ok_or(EngagementPortError::NotFound)?;

        let now = OffsetDateTime::now_utc();
        let duration = source.window.end - source.window.start;
        let new_window = TimeWindow::new(now, now + duration).map_err(domain_err)?;

        let new_name = req
            .new_name
            .as_ref()
            .map_or_else(|| format!("{} (clone)", source.name), Clone::clone);

        let clone = Engagement::new_draft(
            EngagementId::new(),
            tenant,
            new_name,
            source.scope.clone(),
            new_window,
            source.max_intensity,
            now,
        )
        .map_err(domain_err)?;

        self.repo.create(&clone).await.map_err(domain_err)?;
        Ok(to_view(&clone))
    }
}

// ----- Conversion helpers -------------------------------------------------

fn parse_tenant(s: &str) -> Result<TenantId, EngagementPortError> {
    let id = uuid::Uuid::from_str(s)
        .map_err(|_| EngagementPortError::Invalid("invalid tenant id".into()))?;
    Ok(TenantId::from_uuid(id))
}

fn parse_engagement_id(s: &str) -> Result<EngagementId, EngagementPortError> {
    let id = uuid::Uuid::from_str(s)
        .map_err(|_| EngagementPortError::Invalid("invalid engagement id".into()))?;
    Ok(EngagementId::from_uuid(id))
}

fn domain_err(e: EngagementError) -> EngagementPortError {
    match e {
        EngagementError::InvalidInput(m) => EngagementPortError::Invalid(m),
        EngagementError::Repository(m) => EngagementPortError::Dependency(m),
        EngagementError::Internal(m) => EngagementPortError::Internal(m),
        other => EngagementPortError::Internal(other.to_string()),
    }
}

fn to_view(e: &Engagement) -> EngagementView {
    EngagementView {
        id: e.id.to_string(),
        tenant_id: e.tenant_id.to_string(),
        name: e.name.clone(),
        description: None,
        scopes: e.scope.iter().map(scope_to_string).collect(),
        status: status_to_string(e.status).to_owned(),
        created_at: e.created_at.to_string(),
        updated_at: e.updated_at.to_string(),
    }
}

fn scope_to_string(t: &sx_engagement::model::scope_target::ScopeTarget) -> String {
    use sx_engagement::model::scope_target::ScopeTarget;
    match t {
        ScopeTarget::Cidr(net) => net.to_string(),
        ScopeTarget::IpV4(ip) => ip.to_string(),
        ScopeTarget::IpV6(ip) => ip.to_string(),
        ScopeTarget::Domain(d) => d.clone(),
        ScopeTarget::Url(u) => u.to_string(),
        ScopeTarget::Arn(a) | ScopeTarget::RepoUrl(a) => a.clone(),
    }
}

const fn status_to_string(s: EngagementStatus) -> &'static str {
    match s {
        EngagementStatus::Draft => "draft",
        EngagementStatus::Active => "active",
        EngagementStatus::Paused => "paused",
        EngagementStatus::Completed => "completed",
        EngagementStatus::Aborted => "aborted",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sx_engagement::model::intensity::ScanIntensity;
    use sx_engagement::model::scope_target::ScopeTarget;
    use time::Duration;

    fn fixed_tenant() -> TenantId {
        TenantId::from_uuid(uuid::Uuid::parse_str("01010101-0101-0101-0101-010101010101").unwrap())
    }

    fn fixed_source_id() -> EngagementId {
        EngagementId::from_uuid(
            uuid::Uuid::parse_str("e0000001-0000-0000-0000-000000000000").unwrap(),
        )
    }

    fn sample_window_duration() -> Duration {
        Duration::hours(7)
    }

    fn seeded_source() -> Engagement {
        let start = OffsetDateTime::UNIX_EPOCH;
        let window = TimeWindow::new(start, start + sample_window_duration()).unwrap();
        Engagement::new_draft(
            fixed_source_id(),
            fixed_tenant(),
            "Pentest Alpha",
            vec![
                ScopeTarget::Domain("example.com".into()),
                ScopeTarget::Domain("api.example.com".into()),
            ],
            window,
            ScanIntensity::SafeInteractive,
            start,
        )
        .unwrap()
    }

    fn fixture() -> (
        InMemoryEngagementCloneAdapter,
        Arc<InMemoryEngagementRepository>,
        String,
        String,
    ) {
        let repo = Arc::new(InMemoryEngagementRepository::default());
        repo.seed_one(seeded_source());
        let adapter = InMemoryEngagementCloneAdapter {
            repo: Arc::clone(&repo) as Arc<dyn EngagementRepository>,
        };
        (
            adapter,
            repo,
            fixed_tenant().to_string(),
            fixed_source_id().to_string(),
        )
    }

    #[tokio::test]
    async fn clone_assigns_fresh_uuid() {
        let (adapter, _repo, tenant, source_id) = fixture();
        let view = adapter
            .clone_engagement(&tenant, &source_id, CloneEngagementRequest::default())
            .await
            .expect("clone succeeds");
        assert_ne!(view.id, source_id, "clone must mint a fresh uuid");
    }

    #[tokio::test]
    async fn clone_lands_in_draft_status() {
        let (adapter, _repo, tenant, source_id) = fixture();
        let view = adapter
            .clone_engagement(&tenant, &source_id, CloneEngagementRequest::default())
            .await
            .unwrap();
        assert_eq!(view.status, "draft");
    }

    #[tokio::test]
    async fn clone_copies_scope_verbatim() {
        let (adapter, _repo, tenant, source_id) = fixture();
        let view = adapter
            .clone_engagement(&tenant, &source_id, CloneEngagementRequest::default())
            .await
            .unwrap();
        let mut got = view.scopes;
        got.sort();
        let mut want = vec!["api.example.com".to_owned(), "example.com".to_owned()];
        want.sort();
        assert_eq!(got, want, "scope copied verbatim");
    }

    #[tokio::test]
    async fn clone_preserves_window_duration() {
        let (adapter, repo, tenant, source_id) = fixture();
        let view = adapter
            .clone_engagement(&tenant, &source_id, CloneEngagementRequest::default())
            .await
            .unwrap();
        // Look up the persisted aggregate so we can compute the
        // (end - start) duration on the real `TimeWindow` rather than
        // round-tripping through string parsing.
        let cloned_eid = EngagementId::from_uuid(uuid::Uuid::parse_str(&view.id).unwrap());
        let persisted = <InMemoryEngagementRepository as EngagementRepository>::find_by_id(
            repo.as_ref(),
            fixed_tenant(),
            cloned_eid,
        )
        .await
        .expect("repo find ok")
        .expect("clone persisted");
        let clone_duration = persisted.window.end - persisted.window.start;
        assert_eq!(
            clone_duration,
            sample_window_duration(),
            "window duration preserved",
        );
    }

    #[tokio::test]
    async fn clone_defaults_name_to_source_plus_clone_marker() {
        let (adapter, _repo, tenant, source_id) = fixture();
        let view = adapter
            .clone_engagement(&tenant, &source_id, CloneEngagementRequest::default())
            .await
            .unwrap();
        assert_eq!(view.name, "Pentest Alpha (clone)");
    }

    #[tokio::test]
    async fn clone_honours_new_name_override() {
        let (adapter, _repo, tenant, source_id) = fixture();
        let view = adapter
            .clone_engagement(
                &tenant,
                &source_id,
                CloneEngagementRequest {
                    new_name: Some("Renamed Engagement".into()),
                },
            )
            .await
            .unwrap();
        assert_eq!(view.name, "Renamed Engagement");
    }

    #[tokio::test]
    async fn clone_missing_source_is_not_found() {
        let repo = Arc::new(InMemoryEngagementRepository::default());
        let adapter = InMemoryEngagementCloneAdapter {
            repo: Arc::clone(&repo) as Arc<dyn EngagementRepository>,
        };
        let err = adapter
            .clone_engagement(
                &fixed_tenant().to_string(),
                &fixed_source_id().to_string(),
                CloneEngagementRequest::default(),
            )
            .await
            .expect_err("missing source must error");
        assert!(matches!(err, EngagementPortError::NotFound));
    }

    #[tokio::test]
    async fn clone_invalid_tenant_uuid_is_invalid() {
        let (adapter, _repo, _, source_id) = fixture();
        let err = adapter
            .clone_engagement("not-a-uuid", &source_id, CloneEngagementRequest::default())
            .await
            .expect_err("bad tenant must error");
        assert!(matches!(err, EngagementPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn clone_invalid_source_uuid_is_invalid() {
        let (adapter, _repo, tenant, _) = fixture();
        let err = adapter
            .clone_engagement(&tenant, "not-a-uuid", CloneEngagementRequest::default())
            .await
            .expect_err("bad source uuid must error");
        assert!(matches!(err, EngagementPortError::Invalid(_)));
    }
}
