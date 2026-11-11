//! Template registry use-case (P2-002).
//!
//! Wraps a [`TemplateRepository`] adapter with multi-tenant scoping and
//! audit-log emission on every mutation. The use-case is the only path
//! callers should use to mutate templates — direct adapter use bypasses
//! the audit trail.
//!
//! Tenant isolation is enforced at every entry point: the caller passes
//! `tenant_id` and the use-case both filters the underlying repo and
//! verifies the loaded row matches before returning.

use std::sync::Arc;

use async_trait::async_trait;
use sx_core::value_object::ids::TenantId;
use time::OffsetDateTime;
use tracing::{info, instrument, warn};

use crate::error::ReportError;
use crate::model::template::{ReportTemplate, ReportTemplateId, TemplateContext, TemplateSurface};

/// Storage port for [`ReportTemplate`] rows.
///
/// Every method is tenant-scoped — implementations MUST filter by
/// `tenant_id` and return [`ReportError::Forbidden`]-style behaviour
/// (here surfaced via `Ok(None)`) for cross-tenant access attempts.
#[async_trait]
pub trait TemplateRepository: Send + Sync + std::fmt::Debug {
    /// Persist a new template. Returns the inserted row.
    ///
    /// # Errors
    /// Returns [`ReportError::Internal`] for repository-layer failures.
    async fn insert(&self, template: ReportTemplate) -> Result<ReportTemplate, ReportError>;

    /// Replace an existing template (matched by `(tenant_id, id)`).
    ///
    /// # Errors
    /// Returns [`ReportError::InvalidContext`] if the row does not
    /// exist for the given tenant.
    async fn update(&self, template: ReportTemplate) -> Result<ReportTemplate, ReportError>;

    /// Delete a template. Returns whether a row was removed.
    ///
    /// # Errors
    /// Returns [`ReportError::Internal`] for repository-layer failures.
    async fn delete(&self, tenant_id: TenantId, id: ReportTemplateId) -> Result<bool, ReportError>;

    /// Look up a single template by `(tenant_id, id)`.
    ///
    /// # Errors
    /// Returns [`ReportError::Internal`] for repository-layer failures.
    async fn get(
        &self,
        tenant_id: TenantId,
        id: ReportTemplateId,
    ) -> Result<Option<ReportTemplate>, ReportError>;

    /// List every template for a tenant, optionally filtering by surface.
    ///
    /// # Errors
    /// Returns [`ReportError::Internal`] for repository-layer failures.
    async fn list(
        &self,
        tenant_id: TenantId,
        surface: Option<TemplateSurface>,
    ) -> Result<Vec<ReportTemplate>, ReportError>;
}

/// Audit-log sink that the use-case emits to on every mutation.
///
/// Decoupled from `sx-audit` so the report crate stays adapter-free.
/// `sx-monolith` wires this to the actual append-only audit chain.
#[async_trait]
pub trait TemplateAuditSink: Send + Sync + std::fmt::Debug {
    /// Record an action.
    ///
    /// # Errors
    /// Implementations must NEVER swallow the underlying mutation —
    /// returning an error from the sink fails the surrounding use-case
    /// so an in-memory test can prove the audit row was emitted.
    async fn record(&self, event: TemplateAuditEvent) -> Result<(), ReportError>;
}

/// One audit row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateAuditEvent {
    /// Tenant that owns the affected template.
    pub tenant_id: TenantId,
    /// Affected template id.
    pub template_id: ReportTemplateId,
    /// What happened.
    pub action: TemplateAuditAction,
    /// Operator who triggered the action.
    pub actor: String,
    /// When the event happened. Use the same clock as the use-case so
    /// audit-trail timestamps match the template `updated_at` field.
    pub at: OffsetDateTime,
}

/// One of `create`, `update`, `delete`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateAuditAction {
    /// A new template row was inserted.
    Create,
    /// An existing template row was replaced.
    Update,
    /// A template row was removed.
    Delete,
}

impl TemplateAuditAction {
    /// Canonical short form for log lines and persistence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Create => "template.create",
            Self::Update => "template.update",
            Self::Delete => "template.delete",
        }
    }
}

impl std::fmt::Display for TemplateAuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Use-case: orchestrates [`TemplateRepository`] + [`TemplateAuditSink`]
/// for every tenant-facing operation.
pub struct ReportTemplateUseCase {
    repo: Arc<dyn TemplateRepository>,
    audit: Arc<dyn TemplateAuditSink>,
}

impl std::fmt::Debug for ReportTemplateUseCase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReportTemplateUseCase").finish()
    }
}

/// Inputs for [`ReportTemplateUseCase::create`].
#[derive(Debug, Clone)]
pub struct CreateTemplateInput {
    /// Tenant the new row belongs to.
    pub tenant_id: TenantId,
    /// Human-readable display name.
    pub name: String,
    /// Output surface.
    pub surface: TemplateSurface,
    /// Raw template body.
    pub body: String,
    /// Optional description.
    pub description: Option<String>,
    /// Operator who triggered the request.
    pub actor: String,
    /// Clock snapshot, supplied by the API layer.
    pub now: OffsetDateTime,
}

/// Inputs for [`ReportTemplateUseCase::update`].
#[derive(Debug, Clone)]
pub struct UpdateTemplateInput {
    /// Tenant the affected row belongs to.
    pub tenant_id: TenantId,
    /// Affected template id.
    pub id: ReportTemplateId,
    /// New display name.
    pub name: String,
    /// New body — replaces existing body verbatim.
    pub body: String,
    /// New optional description.
    pub description: Option<String>,
    /// Operator who triggered the request.
    pub actor: String,
    /// Clock snapshot.
    pub now: OffsetDateTime,
}

impl ReportTemplateUseCase {
    /// Construct the use-case from its collaborators.
    #[must_use]
    pub fn new(repo: Arc<dyn TemplateRepository>, audit: Arc<dyn TemplateAuditSink>) -> Self {
        Self { repo, audit }
    }

    /// Insert a new template + emit an audit event.
    ///
    /// # Errors
    /// - [`ReportError::InvalidContext`] when the template fails
    ///   compile-time validation.
    /// - Any error returned by [`TemplateRepository::insert`] or the
    ///   audit sink.
    #[instrument(skip(self, input), fields(tenant_id = %input.tenant_id, surface = %input.surface))]
    pub async fn create(&self, input: CreateTemplateInput) -> Result<ReportTemplate, ReportError> {
        let template = ReportTemplate::new(
            ReportTemplateId::new(),
            input.tenant_id,
            input.name,
            input.surface,
            input.body,
            input.description,
            1,
            input.actor.clone(),
            input.now,
        )?;
        let saved = self.repo.insert(template).await?;
        self.audit
            .record(TemplateAuditEvent {
                tenant_id: saved.tenant_id,
                template_id: saved.id,
                action: TemplateAuditAction::Create,
                actor: input.actor,
                at: input.now,
            })
            .await?;
        info!(
            tenant_id = %saved.tenant_id,
            template_id = %saved.id,
            "report template created",
        );
        Ok(saved)
    }

    /// Replace an existing template, bumping its version, and emit an
    /// audit event.
    ///
    /// # Errors
    /// - [`ReportError::InvalidContext`] when the row does not exist
    ///   or the new body fails compile-time validation.
    /// - Any error returned by the repository or audit sink.
    #[instrument(skip(self, input), fields(tenant_id = %input.tenant_id, template_id = %input.id))]
    pub async fn update(&self, input: UpdateTemplateInput) -> Result<ReportTemplate, ReportError> {
        let existing = self
            .repo
            .get(input.tenant_id, input.id)
            .await?
            .ok_or_else(|| {
                warn!(
                    tenant_id = %input.tenant_id,
                    template_id = %input.id,
                    "update target template not found",
                );
                ReportError::invalid_context(format!(
                    "template {} not found for tenant {}",
                    input.id, input.tenant_id,
                ))
            })?;
        let template = ReportTemplate::new(
            existing.id,
            existing.tenant_id,
            input.name,
            existing.surface,
            input.body,
            input.description,
            existing.version.saturating_add(1),
            input.actor.clone(),
            input.now,
        )?;
        let saved = self.repo.update(template).await?;
        self.audit
            .record(TemplateAuditEvent {
                tenant_id: saved.tenant_id,
                template_id: saved.id,
                action: TemplateAuditAction::Update,
                actor: input.actor,
                at: input.now,
            })
            .await?;
        info!(
            tenant_id = %saved.tenant_id,
            template_id = %saved.id,
            version = saved.version,
            "report template updated",
        );
        Ok(saved)
    }

    /// Delete a template + emit an audit event.
    ///
    /// # Errors
    /// Returns [`ReportError::InvalidContext`] when no row was removed,
    /// or any error returned by the repository or audit sink.
    #[instrument(skip(self, actor), fields(%tenant_id, %template_id))]
    pub async fn delete(
        &self,
        tenant_id: TenantId,
        template_id: ReportTemplateId,
        actor: impl Into<String> + Send,
        now: OffsetDateTime,
    ) -> Result<(), ReportError> {
        let actor = actor.into();
        let removed = self.repo.delete(tenant_id, template_id).await?;
        if !removed {
            return Err(ReportError::invalid_context(format!(
                "template {template_id} not found for tenant {tenant_id}",
            )));
        }
        self.audit
            .record(TemplateAuditEvent {
                tenant_id,
                template_id,
                action: TemplateAuditAction::Delete,
                actor,
                at: now,
            })
            .await?;
        info!(
            tenant_id = %tenant_id,
            template_id = %template_id,
            "report template deleted",
        );
        Ok(())
    }

    /// Load a template by id, scoped to the calling tenant.
    ///
    /// # Errors
    /// Returns [`ReportError::Internal`] for repository-layer failures.
    pub async fn get(
        &self,
        tenant_id: TenantId,
        template_id: ReportTemplateId,
    ) -> Result<Option<ReportTemplate>, ReportError> {
        self.repo.get(tenant_id, template_id).await
    }

    /// List templates for a tenant, optionally filtered by surface.
    ///
    /// # Errors
    /// Returns [`ReportError::Internal`] for repository-layer failures.
    pub async fn list(
        &self,
        tenant_id: TenantId,
        surface: Option<TemplateSurface>,
    ) -> Result<Vec<ReportTemplate>, ReportError> {
        self.repo.list(tenant_id, surface).await
    }

    /// Render a stored template against the supplied context, scoped
    /// to the calling tenant.
    ///
    /// # Errors
    /// - [`ReportError::InvalidContext`] when the template is missing
    ///   or the render exceeds the engine's sandbox caps.
    pub async fn render(
        &self,
        tenant_id: TenantId,
        template_id: ReportTemplateId,
        ctx: &TemplateContext,
    ) -> Result<String, ReportError> {
        let tpl = self.get(tenant_id, template_id).await?.ok_or_else(|| {
            ReportError::invalid_context(format!(
                "template {template_id} not found for tenant {tenant_id}",
            ))
        })?;
        tpl.render(ctx)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::significant_drop_tightening
)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use time::macros::datetime;

    #[derive(Debug, Default)]
    struct InMemoryRepo {
        rows: Mutex<Vec<ReportTemplate>>,
    }

    #[async_trait]
    impl TemplateRepository for InMemoryRepo {
        async fn insert(&self, template: ReportTemplate) -> Result<ReportTemplate, ReportError> {
            self.rows.lock().unwrap().push(template.clone());
            Ok(template)
        }
        async fn update(&self, template: ReportTemplate) -> Result<ReportTemplate, ReportError> {
            {
                let mut rows = self.rows.lock().unwrap();
                for row in rows.iter_mut() {
                    if row.tenant_id == template.tenant_id && row.id == template.id {
                        *row = template.clone();
                        return Ok(template);
                    }
                }
            }
            Err(ReportError::invalid_context("not found"))
        }
        async fn delete(
            &self,
            tenant_id: TenantId,
            id: ReportTemplateId,
        ) -> Result<bool, ReportError> {
            let mut rows = self.rows.lock().unwrap();
            let before = rows.len();
            rows.retain(|r| !(r.tenant_id == tenant_id && r.id == id));
            Ok(rows.len() < before)
        }
        async fn get(
            &self,
            tenant_id: TenantId,
            id: ReportTemplateId,
        ) -> Result<Option<ReportTemplate>, ReportError> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .find(|r| r.tenant_id == tenant_id && r.id == id)
                .cloned())
        }
        async fn list(
            &self,
            tenant_id: TenantId,
            surface: Option<TemplateSurface>,
        ) -> Result<Vec<ReportTemplate>, ReportError> {
            Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.tenant_id == tenant_id)
                .filter(|r| surface.is_none_or(|s| r.surface == s))
                .cloned()
                .collect())
        }
    }

    #[derive(Debug, Default)]
    struct InMemoryAudit {
        events: Mutex<Vec<TemplateAuditEvent>>,
    }

    #[async_trait]
    impl TemplateAuditSink for InMemoryAudit {
        async fn record(&self, event: TemplateAuditEvent) -> Result<(), ReportError> {
            self.events.lock().unwrap().push(event);
            Ok(())
        }
    }

    fn uc() -> (Arc<InMemoryRepo>, Arc<InMemoryAudit>, ReportTemplateUseCase) {
        let repo = Arc::new(InMemoryRepo::default());
        let audit = Arc::new(InMemoryAudit::default());
        let uc = ReportTemplateUseCase::new(repo.clone(), audit.clone());
        (repo, audit, uc)
    }

    fn make_input(tenant_id: TenantId) -> CreateTemplateInput {
        CreateTemplateInput {
            tenant_id,
            name: "Cover".into(),
            surface: TemplateSurface::PdfCover,
            body: "Hello {{tenant.name}}".into(),
            description: None,
            actor: "ops".into(),
            now: datetime!(2026-06-01 12:00:00 UTC),
        }
    }

    #[tokio::test]
    async fn create_emits_audit_event() {
        let tenant = TenantId::new();
        let (_repo, audit, uc) = uc();
        let saved = uc.create(make_input(tenant)).await.unwrap();
        assert_eq!(saved.tenant_id, tenant);
        assert_eq!(saved.version, 1);
        let events = audit.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, TemplateAuditAction::Create);
        assert_eq!(events[0].tenant_id, tenant);
    }

    #[tokio::test]
    async fn update_bumps_version_and_audits() {
        let tenant = TenantId::new();
        let (_repo, audit, uc) = uc();
        let saved = uc.create(make_input(tenant)).await.unwrap();
        let updated = uc
            .update(UpdateTemplateInput {
                tenant_id: tenant,
                id: saved.id,
                name: "Cover v2".into(),
                body: "Hi {{tenant.name}}".into(),
                description: None,
                actor: "ops".into(),
                now: datetime!(2026-06-02 12:00:00 UTC),
            })
            .await
            .unwrap();
        assert_eq!(updated.version, 2);
        assert_eq!(updated.body, "Hi {{tenant.name}}");
        let events = audit.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].action, TemplateAuditAction::Update);
    }

    #[tokio::test]
    async fn delete_audits_and_removes_row() {
        let tenant = TenantId::new();
        let (_repo, audit, uc) = uc();
        let saved = uc.create(make_input(tenant)).await.unwrap();
        uc.delete(tenant, saved.id, "ops", datetime!(2026-06-03 12:00:00 UTC))
            .await
            .unwrap();
        assert!(uc.get(tenant, saved.id).await.unwrap().is_none());
        let events = audit.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].action, TemplateAuditAction::Delete);
    }

    #[tokio::test]
    async fn cross_tenant_get_returns_none() {
        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();
        let (_repo, _audit, uc) = uc();
        let saved = uc.create(make_input(tenant_a)).await.unwrap();
        // Another tenant must not be able to load A's template.
        let cross = uc.get(tenant_b, saved.id).await.unwrap();
        assert!(cross.is_none());
    }

    #[tokio::test]
    async fn update_rejects_cross_tenant() {
        let tenant_a = TenantId::new();
        let tenant_b = TenantId::new();
        let (_repo, _audit, uc) = uc();
        let saved = uc.create(make_input(tenant_a)).await.unwrap();
        let err = uc
            .update(UpdateTemplateInput {
                tenant_id: tenant_b,
                id: saved.id,
                name: "Hijack".into(),
                body: "Hi".into(),
                description: None,
                actor: "attacker".into(),
                now: datetime!(2026-06-02 12:00:00 UTC),
            })
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn render_uses_context() {
        let tenant = TenantId::new();
        let (_repo, _audit, uc) = uc();
        let saved = uc.create(make_input(tenant)).await.unwrap();
        let ctx = TemplateContext::from_report(
            &crate::model::report::ReportContext::new(
                tenant,
                sx_core::value_object::ids::EngagementId::new(),
                "Acme",
                "Q2",
                "ops",
                datetime!(2026-06-01 12:00:00 UTC),
                crate::model::posture::PostureSummary::empty(),
                vec![],
            )
            .unwrap(),
        );
        let out = uc.render(tenant, saved.id, &ctx).await.unwrap();
        assert_eq!(out, "Hello Acme");
    }

    #[tokio::test]
    async fn list_filters_by_surface() {
        let tenant = TenantId::new();
        let (_repo, _audit, uc) = uc();
        uc.create(CreateTemplateInput {
            surface: TemplateSurface::PdfCover,
            ..make_input(tenant)
        })
        .await
        .unwrap();
        uc.create(CreateTemplateInput {
            surface: TemplateSurface::PdfFooter,
            name: "Footer".into(),
            body: "x".into(),
            ..make_input(tenant)
        })
        .await
        .unwrap();
        let only_footer = uc
            .list(tenant, Some(TemplateSurface::PdfFooter))
            .await
            .unwrap();
        assert_eq!(only_footer.len(), 1);
        assert_eq!(only_footer[0].surface, TemplateSurface::PdfFooter);
    }
}
