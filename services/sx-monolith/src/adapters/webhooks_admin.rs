//! Per-tenant webhook signing-key rotation admin adapter (MED-003).
//!
//! [`InProcessWebhookKeyRotationAdmin`] wraps a fully-wired
//! [`sx_webhooks::WebhookKeyRotator`]. The composition root builds it over
//! a Postgres-backed [`sx_webhooks::SigningKeyStore`] (keys survive
//! restart) when the DB is enabled, or the in-memory store in dev, plus
//! the `SecretCipher` seam and a rotation audit sink. It surfaces rotator
//! results back through the port error surface. (MED-003 rotation is now
//! on by default — the former deterministic-422 `Disabled` adapter has
//! been retired.)

use async_trait::async_trait;
use chrono::SecondsFormat;
use std::str::FromStr;
use std::sync::Arc;

use sx_api::port::{WebhookKeyRotationAdminPort, WebhookKeyRotationPortError};
use sx_api::view::webhooks_admin_view::RotateWebhookKeyResponse;
use sx_audit::prelude::{Actor, ActorKind, AuditAction, NewAuditEvent, RecordAuditEventUseCase};
use sx_config::schema::WebhookSigningRotationConfig;
use sx_core::value_object::ids::TenantId as CoreTenantId;
use sx_webhooks::signing::audit::{RotationAuditEvent, RotationAuditSink};
use sx_webhooks::signing::rotator::{RotationError, RotationPolicy};
use sx_webhooks::WebhookKeyRotator;
use time::OffsetDateTime;

/// In-process adapter backed by a [`WebhookKeyRotator`] + a
/// configuration source. Per-tenant cadence + grace are resolved from
/// `cfg.for_tenant(tenant_id)` at request time so a config change
/// takes effect on the next force-rotate call without restart.
#[derive(Clone)]
pub struct InProcessWebhookKeyRotationAdmin {
    rotator: WebhookKeyRotator,
    cfg: Arc<WebhookSigningRotationConfig>,
}

impl std::fmt::Debug for InProcessWebhookKeyRotationAdmin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InProcessWebhookKeyRotationAdmin")
            .field("rotator", &self.rotator)
            .field("cfg.cadence_days", &self.cfg.cadence_days)
            .field("cfg.grace_days", &self.cfg.grace_days)
            .finish_non_exhaustive()
    }
}

impl InProcessWebhookKeyRotationAdmin {
    /// Construct from a built rotator + an immutable config snapshot.
    #[must_use]
    #[allow(dead_code)]
    pub fn new(rotator: WebhookKeyRotator, cfg: Arc<WebhookSigningRotationConfig>) -> Self {
        Self { rotator, cfg }
    }

    /// Wrap in an `Arc<dyn WebhookKeyRotationAdminPort>` for the
    /// AppState bag.
    #[must_use]
    #[allow(dead_code)]
    pub fn into_arc(self) -> Arc<dyn WebhookKeyRotationAdminPort> {
        Arc::new(self)
    }
}

#[async_trait]
impl WebhookKeyRotationAdminPort for InProcessWebhookKeyRotationAdmin {
    async fn force_rotate(
        &self,
        tenant_id: &str,
        actor: Option<String>,
    ) -> Result<RotateWebhookKeyResponse, WebhookKeyRotationPortError> {
        let trimmed = tenant_id.trim();
        if trimmed.is_empty() {
            return Err(WebhookKeyRotationPortError::Invalid(
                "tenant_id is required".into(),
            ));
        }
        let (cadence_days, grace_days) = self.cfg.for_tenant(trimmed);
        let policy = RotationPolicy::from_days(cadence_days, grace_days);
        let minted_at = chrono::Utc::now();
        let outcome = self
            .rotator
            .force_rotate(trimmed, policy, actor)
            .await
            .map_err(map_rotation_err)?;
        Ok(RotateWebhookKeyResponse {
            tenant_id: outcome.tenant_id,
            new_kid: outcome.new_kid.into_string(),
            previous_kid: outcome.previous_kid.map(sx_webhooks::Kid::into_string),
            previous_retire_at: outcome
                .previous_retire_at
                .map(|t| t.to_rfc3339_opts(SecondsFormat::Secs, true)),
            minted_at: minted_at.to_rfc3339_opts(SecondsFormat::Secs, true),
        })
    }
}

/// Durable rotation-audit sink — forwards every [`RotationAuditEvent`]
/// (one per mint / retire) into the hash-chained `sx-audit` trail via
/// [`RecordAuditEventUseCase`], mirroring the Falco `IngestionAuditChainSink`.
/// Signing-key rotations become tamper-evidently logged instead of living
/// only in a process-local buffer that evaporates on restart. A non-UUID
/// tenant id is logged and skipped (never panics); an append failure is
/// logged and swallowed so an audit-store hiccup never fails a rotation.
pub(crate) struct RotationAuditChainSink {
    recorder: Arc<RecordAuditEventUseCase>,
}

impl RotationAuditChainSink {
    pub(crate) fn new(recorder: Arc<RecordAuditEventUseCase>) -> Self {
        Self { recorder }
    }
}

impl std::fmt::Debug for RotationAuditChainSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotationAuditChainSink")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl RotationAuditSink for RotationAuditChainSink {
    async fn record(&self, event: RotationAuditEvent) {
        let Ok(tenant) = CoreTenantId::from_str(&event.tenant_id) else {
            tracing::warn!(
                target: "adapters.webhooks.audit",
                tenant_id = %event.tenant_id,
                "skipping sx-audit append for webhook key rotation: tenant id is not a UUID",
            );
            return;
        };
        let ts = OffsetDateTime::from_unix_timestamp(event.at.timestamp()).ok();
        let evt = NewAuditEvent {
            tenant_id: tenant,
            actor: Actor {
                kind: ActorKind::System,
                id: event
                    .actor
                    .clone()
                    .unwrap_or_else(|| "webhook-key-rotation".to_owned()),
                ip: None,
                user_agent: None,
            },
            action: AuditAction::Custom {
                code: format!("webhooks.{}", event.kind.code()),
            },
            resource_kind: "webhook_signing_key".to_owned(),
            resource_id: event.kid.as_str().to_owned(),
            before: None,
            after: Some(serde_json::json!({
                "kind": event.kind.code(),
                "kid": event.kid.as_str(),
                "companion_kid": event.companion_kid.as_ref().map(sx_webhooks::Kid::as_str),
                "reason": event.reason,
                "actor": event.actor,
            })),
            request_id: String::new(),
            ts,
        };
        if let Err(err) = self.recorder.record(evt).await {
            tracing::warn!(
                target: "adapters.webhooks.audit",
                error = %err,
                "sx-audit append failed for webhook key rotation; rotation still applied",
            );
        }
    }
}

fn map_rotation_err(err: RotationError) -> WebhookKeyRotationPortError {
    match err {
        RotationError::Store(e) => WebhookKeyRotationPortError::Dependency(format!("{e}")),
        RotationError::Cipher(e) => WebhookKeyRotationPortError::Dependency(format!("{e}")),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sx_webhooks::signing::audit::{InMemoryRotationAuditSink, RotationAuditSink};
    use sx_webhooks::signing::secret_cipher::{PlaintextCipher, SecretCipher};
    use sx_webhooks::signing::store::SigningKeyStore;
    use sx_webhooks::InMemorySigningKeyStore;

    fn build_rotator(
        store: Arc<dyn SigningKeyStore>,
    ) -> (WebhookKeyRotator, Arc<InMemoryRotationAuditSink>) {
        let cipher: Arc<dyn SecretCipher> = Arc::new(PlaintextCipher);
        let audit_inner: Arc<InMemoryRotationAuditSink> =
            Arc::new(InMemoryRotationAuditSink::new());
        let audit: Arc<dyn RotationAuditSink> = audit_inner.clone();
        (WebhookKeyRotator::new(store, cipher, audit), audit_inner)
    }

    #[tokio::test]
    async fn in_process_rotate_succeeds_and_records_audit() {
        let store: Arc<dyn SigningKeyStore> = Arc::new(InMemorySigningKeyStore::new());
        let (rotator, audit) = build_rotator(store.clone());
        let cfg = Arc::new(WebhookSigningRotationConfig::default());
        let adapter = InProcessWebhookKeyRotationAdmin::new(rotator, cfg);
        let view = adapter
            .force_rotate("tenant-x", Some("operator@example.com".into()))
            .await
            .unwrap();
        assert_eq!(view.tenant_id, "tenant-x");
        assert!(view.new_kid.starts_with("kid_"));
        assert!(view.previous_kid.is_none());
        assert!(view.previous_retire_at.is_none());
        // Audit recorded the mint with the actor.
        let evs = audit.events();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].actor.as_deref(), Some("operator@example.com"));
    }

    #[tokio::test]
    async fn in_process_rotate_emits_previous_kid_on_second_call() {
        let store: Arc<dyn SigningKeyStore> = Arc::new(InMemorySigningKeyStore::new());
        let (rotator, _audit) = build_rotator(store);
        let cfg = Arc::new(WebhookSigningRotationConfig::default());
        let adapter = InProcessWebhookKeyRotationAdmin::new(rotator, cfg);
        let first = adapter.force_rotate("t", None).await.unwrap();
        let second = adapter.force_rotate("t", None).await.unwrap();
        assert_eq!(second.previous_kid.as_deref(), Some(first.new_kid.as_str()));
        assert!(second.previous_retire_at.is_some());
    }

    #[tokio::test]
    async fn rejects_empty_tenant_id() {
        let store: Arc<dyn SigningKeyStore> = Arc::new(InMemorySigningKeyStore::new());
        let (rotator, _audit) = build_rotator(store);
        let cfg = Arc::new(WebhookSigningRotationConfig::default());
        let adapter = InProcessWebhookKeyRotationAdmin::new(rotator, cfg);
        let err = adapter.force_rotate("   ", None).await.unwrap_err();
        assert!(matches!(err, WebhookKeyRotationPortError::Invalid(_)));
    }

    #[tokio::test]
    async fn into_arc_yields_dyn_port() {
        let store: Arc<dyn SigningKeyStore> = Arc::new(InMemorySigningKeyStore::new());
        let (rotator, _audit) = build_rotator(store);
        let cfg = Arc::new(WebhookSigningRotationConfig::default());
        let port: Arc<dyn WebhookKeyRotationAdminPort> =
            InProcessWebhookKeyRotationAdmin::new(rotator, cfg).into_arc();
        let view = port.force_rotate("t", None).await.unwrap();
        assert!(view.new_kid.starts_with("kid_"));
    }

    #[tokio::test]
    async fn rotation_event_reaches_the_audit_chain() {
        use crate::adapters::audit_query::InMemoryAuditBufferSink;
        use sx_audit::prelude::{AuditSink, RecordAuditEventUseCase};

        // Rotator wired with the durable-audit sink over an in-memory
        // audit buffer (the same buffer the audit-query endpoints read).
        let buf = Arc::new(InMemoryAuditBufferSink::new());
        let recorder = Arc::new(RecordAuditEventUseCase::new(
            Arc::clone(&buf) as Arc<dyn AuditSink>
        ));
        let audit: Arc<dyn RotationAuditSink> = Arc::new(RotationAuditChainSink::new(recorder));
        let store: Arc<dyn SigningKeyStore> = Arc::new(InMemorySigningKeyStore::new());
        let cipher: Arc<dyn SecretCipher> = Arc::new(PlaintextCipher);
        let rotator = WebhookKeyRotator::new(store, cipher, audit);
        let cfg = Arc::new(WebhookSigningRotationConfig::default());
        let admin = InProcessWebhookKeyRotationAdmin::new(rotator, cfg);

        // A valid-UUID tenant so the chain sink does not skip.
        let tenant = "01010101-0101-0101-0101-010101010101";
        admin
            .force_rotate(tenant, Some("op@example.com".into()))
            .await
            .unwrap();

        let entries = buf.snapshot().await;
        assert_eq!(
            entries.len(),
            1,
            "a mint must produce one audit-chain entry"
        );
        let json = serde_json::to_string(&entries[0]).unwrap();
        assert!(
            json.contains("webhook_key_minted"),
            "audit entry carries the rotation action code; got {json}",
        );
    }

    /// Durability proof against a real Postgres: a force-rotated signing
    /// key persists so that, after a *fresh pool (restart-equivalent)*, the
    /// next rotation reports the earlier key as its `previous_kid` — only
    /// possible if the first key was read back from the DB. Gated on
    /// `TEST_DATABASE_URL` (silent no-op in CI).
    #[tokio::test]
    async fn pg_webhook_key_rotation_survives_restart() {
        use sx_storage::repository::webhook_signing_keys::build_pg_rotator;

        #[allow(clippy::disallowed_methods)]
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };

        let tenant = uuid::Uuid::new_v4();
        let tenant_s = tenant.to_string();
        let cfg = Arc::new(WebhookSigningRotationConfig::default());

        let mk_rotator = |pool: sqlx::PgPool| {
            let cipher: Arc<dyn SecretCipher> = Arc::new(PlaintextCipher);
            let audit: Arc<dyn RotationAuditSink> = Arc::new(InMemoryRotationAuditSink::new());
            build_pg_rotator(pool, 15_000, cipher, audit)
        };

        // Seed the tenant (FK target of webhook_signing_keys).
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("connect");
            sqlx::query(
                "INSERT INTO tenants (id, name, slug, tier) VALUES ($1, $2, $3, 'starter') \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(tenant)
            .bind(format!("wh-{tenant}"))
            .bind(format!("wh-{tenant}"))
            .execute(&pool)
            .await
            .expect("seed tenant");
        }

        // Process 1: mint the first signing key via force-rotate.
        let first_kid = {
            let pool = sqlx::PgPool::connect(&url).await.expect("connect");
            let admin = InProcessWebhookKeyRotationAdmin::new(mk_rotator(pool), cfg.clone());
            let r = admin
                .force_rotate(&tenant_s, Some("operator@example.com".into()))
                .await
                .expect("rotate 1");
            assert!(
                r.previous_kid.is_none(),
                "first rotation has no predecessor"
            );
            r.new_kid
        };

        // Process 2 (fresh pool): rotate again. The previous_kid must be
        // process 1's key — proving it was persisted across the restart.
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("reconnect");
            let admin = InProcessWebhookKeyRotationAdmin::new(mk_rotator(pool), cfg.clone());
            let r = admin.force_rotate(&tenant_s, None).await.expect("rotate 2");
            assert_eq!(
                r.previous_kid.as_deref(),
                Some(first_kid.as_str()),
                "prior signing key survived restart"
            );
        }

        // Cleanup: deleting the tenant cascades to webhook_signing_keys.
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("reconnect");
            sqlx::query("DELETE FROM tenants WHERE id = $1")
                .bind(tenant)
                .execute(&pool)
                .await
                .expect("cleanup tenant");
        }
    }
}
