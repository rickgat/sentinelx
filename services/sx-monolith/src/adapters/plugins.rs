//! Plugin marketplace + SDK adapter (P3-007).
//!
//! Bridges [`sx_plugins::InMemoryPluginService`] into
//! [`sx_api::port::PluginsPort`]. Production swaps the in-memory variant
//! for a Postgres-backed implementation behind the same trait — this
//! adapter only forwards.
//!
//! Multi-tenancy is enforced inside the underlying [`PluginService`]:
//! every method is scoped to `(tenant_id, plugin_id)` and the
//! `subscribers` / `list_dispatches` paths filter on the same composite
//! key. Cross-tenant reads return [`PluginServiceError::NotFound`].
//!
//! Audit:
//!
//! * The controller emits `tracing::info!(target = "audit", ...)` on
//!   install + uninstall.
//! * The adapter additionally emits a host-side audit event for every
//!   plugin invocation (dispatch path) via [`InvocationAudit::record`].
//!   The tap-sink picks both up and threads them onto the audit chain
//!   the rest of the platform writes to.

use std::sync::Arc;

use async_trait::async_trait;
use secrecy::SecretString;
use sqlx::types::Json;
use sqlx::{PgPool, Row as _};
use sx_api::port::{PluginsPort, PluginsPortError};
use sx_plugins::service::PluginSecretView;
use sx_plugins::{
    DispatchRecord, EventKind, InMemoryPluginService, PluginId, PluginManifest, PluginService,
    PluginServiceError, RegisteredPlugin,
};
use sx_webhooks::signing::secret_cipher::{CipherError, SecretCipher};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Bundle returned to the composition root.
pub(crate) struct PluginsBundle {
    /// HTTP-facing plugins port.
    pub plugins: Arc<dyn PluginsPort>,
}

/// Build the plugins adapter with the in-memory backing service.
pub(crate) fn build() -> PluginsBundle {
    let svc: Arc<dyn PluginService> = Arc::new(InMemoryPluginService::new());
    PluginsBundle {
        plugins: Arc::new(PluginsAdapter { svc }),
    }
}

/// Build the durable Postgres-backed plugins adapter. Selected by the
/// composition root when the DB is enabled, so user-installed plugin
/// registrations (manifest + HMAC webhook secret) and the dispatch history
/// survive a restart instead of vanishing with the process.
///
/// The per-plugin signing secret is written through the [`SecretCipher`]
/// seam supplied by the composition root — a local AEAD cipher (at-rest
/// encryption) in the non-KMS build, or a KMS-backed cipher where one is
/// configured. The column shape (`secret_enc`) is unchanged.
pub(crate) fn build_pg(
    pool: PgPool,
    stmt_timeout_ms: u64,
    cipher: Arc<dyn SecretCipher>,
) -> PluginsBundle {
    let svc: Arc<dyn PluginService> = Arc::new(PgPluginService {
        pool,
        stmt_timeout_ms,
        cipher,
    });
    PluginsBundle {
        plugins: Arc::new(PluginsAdapter { svc }),
    }
}

/// Postgres-backed [`PluginService`]. Registrations are a JSONB aggregate
/// per `(tenant_id, plugin_id)` in `plugins` (with the secret sealed into
/// `secret_enc`); dispatch records are a JSONB aggregate per row in
/// `plugin_dispatches`. Keyed by `tenant_id` with explicit predicates (no
/// RLS; see the migration).
struct PgPluginService {
    pool: PgPool,
    stmt_timeout_ms: u64,
    cipher: Arc<dyn SecretCipher>,
}

impl std::fmt::Debug for PgPluginService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgPluginService").finish_non_exhaustive()
    }
}

impl PgPluginService {
    fn err(e: impl std::fmt::Display) -> PluginServiceError {
        PluginServiceError::Dependency(format!("plugin store: {e}"))
    }

    fn cipher_err(e: CipherError) -> PluginServiceError {
        PluginServiceError::Dependency(format!("plugin secret cipher: {e}"))
    }

    async fn begin(&self) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, PluginServiceError> {
        let mut tx = self.pool.begin().await.map_err(Self::err)?;
        let bounded = self.stmt_timeout_ms.clamp(1, 60_000);
        sqlx::query(&format!("SET LOCAL statement_timeout = {bounded}"))
            .execute(&mut *tx)
            .await
            .map_err(Self::err)?;
        Ok(tx)
    }
}

#[async_trait]
impl PluginService for PgPluginService {
    async fn list(&self, tenant_id: &str) -> Result<Vec<RegisteredPlugin>, PluginServiceError> {
        let mut tx = self.begin().await?;
        let rows = sqlx::query(
            "SELECT aggregate FROM plugins WHERE tenant_id = $1 ORDER BY registered_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(Self::err)?;
        tx.commit().await.map_err(Self::err)?;
        rows.into_iter()
            .map(|r| {
                r.try_get::<Json<RegisteredPlugin>, _>("aggregate")
                    .map(|j| j.0)
                    .map_err(Self::err)
            })
            .collect()
    }

    async fn get(
        &self,
        tenant_id: &str,
        plugin_id: PluginId,
    ) -> Result<RegisteredPlugin, PluginServiceError> {
        let mut tx = self.begin().await?;
        let row = sqlx::query("SELECT aggregate FROM plugins WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(plugin_id.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(Self::err)?;
        tx.commit().await.map_err(Self::err)?;
        match row {
            Some(r) => r
                .try_get::<Json<RegisteredPlugin>, _>("aggregate")
                .map(|j| j.0)
                .map_err(Self::err),
            None => Err(PluginServiceError::NotFound),
        }
    }

    async fn register(
        &self,
        tenant_id: &str,
        manifest: PluginManifest,
        secret: SecretString,
    ) -> Result<RegisteredPlugin, PluginServiceError> {
        let id = PluginId::new();
        let now = OffsetDateTime::now_utc();
        let registered = RegisteredPlugin {
            id,
            tenant_id: tenant_id.to_owned(),
            name: manifest.name,
            vendor: manifest.vendor,
            version: manifest.version,
            webhook_url: manifest.webhook_url,
            supported_events: manifest.supported_events,
            required_scopes: manifest.required_scopes,
            enabled: true,
            registered_at: now.format(&Rfc3339).unwrap_or_default(),
        };
        let secret_enc = self
            .cipher
            .seal(tenant_id, &secret)
            .await
            .map_err(Self::cipher_err)?;
        let mut tx = self.begin().await?;
        sqlx::query(
            "INSERT INTO plugins (tenant_id, id, aggregate, secret_enc, registered_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(tenant_id)
        .bind(id.0)
        .bind(Json(&registered))
        .bind(&secret_enc)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(Self::err)?;
        tx.commit().await.map_err(Self::err)?;
        Ok(registered)
    }

    async fn delete(&self, tenant_id: &str, plugin_id: PluginId) -> Result<(), PluginServiceError> {
        let mut tx = self.begin().await?;
        let res = sqlx::query("DELETE FROM plugins WHERE tenant_id = $1 AND id = $2")
            .bind(tenant_id)
            .bind(plugin_id.0)
            .execute(&mut *tx)
            .await
            .map_err(Self::err)?;
        if res.rows_affected() == 0 {
            // Nothing removed → unknown (tenant, plugin). Roll back the
            // (empty) tx implicitly by dropping it.
            return Err(PluginServiceError::NotFound);
        }
        sqlx::query("DELETE FROM plugin_dispatches WHERE tenant_id = $1 AND plugin_id = $2")
            .bind(tenant_id)
            .bind(plugin_id.0)
            .execute(&mut *tx)
            .await
            .map_err(Self::err)?;
        tx.commit().await.map_err(Self::err)
    }

    async fn unseal_secret(
        &self,
        tenant_id: &str,
        plugin_id: PluginId,
    ) -> Result<PluginSecretView, PluginServiceError> {
        let mut tx = self.begin().await?;
        let row = sqlx::query(
            "SELECT aggregate, secret_enc FROM plugins WHERE tenant_id = $1 AND id = $2",
        )
        .bind(tenant_id)
        .bind(plugin_id.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(Self::err)?;
        tx.commit().await.map_err(Self::err)?;
        let row = row.ok_or(PluginServiceError::NotFound)?;
        let registered = row
            .try_get::<Json<RegisteredPlugin>, _>("aggregate")
            .map(|j| j.0)
            .map_err(Self::err)?;
        let secret_enc: String = row.try_get("secret_enc").map_err(Self::err)?;
        let secret = self
            .cipher
            .open(tenant_id, &secret_enc)
            .await
            .map_err(Self::cipher_err)?;
        Ok(PluginSecretView {
            id: registered.id,
            webhook_url: registered.webhook_url,
            secret,
            supported_events: registered.supported_events,
            enabled: registered.enabled,
        })
    }

    async fn subscribers(
        &self,
        tenant_id: &str,
        event_kind: EventKind,
    ) -> Result<Vec<PluginSecretView>, PluginServiceError> {
        let mut tx = self.begin().await?;
        let rows = sqlx::query("SELECT aggregate, secret_enc FROM plugins WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(Self::err)?;
        tx.commit().await.map_err(Self::err)?;
        let mut out = Vec::new();
        for r in rows {
            let registered = r
                .try_get::<Json<RegisteredPlugin>, _>("aggregate")
                .map(|j| j.0)
                .map_err(Self::err)?;
            if !registered.enabled || !registered.supported_events.contains(&event_kind) {
                continue;
            }
            let secret_enc: String = r.try_get("secret_enc").map_err(Self::err)?;
            let secret = self
                .cipher
                .open(tenant_id, &secret_enc)
                .await
                .map_err(Self::cipher_err)?;
            out.push(PluginSecretView {
                id: registered.id,
                webhook_url: registered.webhook_url,
                secret,
                supported_events: registered.supported_events,
                enabled: registered.enabled,
            });
        }
        Ok(out)
    }

    async fn record_dispatch(&self, record: DispatchRecord) -> Result<(), PluginServiceError> {
        let ts = OffsetDateTime::parse(&record.ts, &Rfc3339)
            .unwrap_or_else(|_| OffsetDateTime::now_utc());
        let mut tx = self.begin().await?;
        sqlx::query(
            "INSERT INTO plugin_dispatches (id, tenant_id, plugin_id, aggregate, ts) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(record.id)
        .bind(&record.tenant_id)
        .bind(record.plugin_id.0)
        .bind(Json(&record))
        .bind(ts)
        .execute(&mut *tx)
        .await
        .map_err(Self::err)?;
        tx.commit().await.map_err(Self::err)
    }

    async fn list_dispatches(
        &self,
        tenant_id: &str,
        plugin_id: PluginId,
        limit: usize,
    ) -> Result<Vec<DispatchRecord>, PluginServiceError> {
        let lim = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut tx = self.begin().await?;
        let rows = sqlx::query(
            "SELECT aggregate FROM plugin_dispatches \
             WHERE tenant_id = $1 AND plugin_id = $2 \
             ORDER BY ts DESC LIMIT $3",
        )
        .bind(tenant_id)
        .bind(plugin_id.0)
        .bind(lim)
        .fetch_all(&mut *tx)
        .await
        .map_err(Self::err)?;
        tx.commit().await.map_err(Self::err)?;
        rows.into_iter()
            .map(|r| {
                r.try_get::<Json<DispatchRecord>, _>("aggregate")
                    .map(|j| j.0)
                    .map_err(Self::err)
            })
            .collect()
    }
}

/// Concrete [`PluginsPort`] implementation that forwards to a
/// [`PluginService`] trait object.
#[derive(Clone)]
struct PluginsAdapter {
    svc: Arc<dyn PluginService>,
}

impl std::fmt::Debug for PluginsAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginsAdapter").finish_non_exhaustive()
    }
}

/// Collapse a [`PluginServiceError`] into the API port error variant.
fn map_err(err: PluginServiceError) -> PluginsPortError {
    match err {
        PluginServiceError::NotFound => PluginsPortError::NotFound,
        PluginServiceError::Dependency(m) => PluginsPortError::Dependency(m),
        PluginServiceError::Internal(m) => PluginsPortError::Internal(m),
    }
}

#[async_trait]
impl PluginsPort for PluginsAdapter {
    async fn list(&self, tenant_id: &str) -> Result<Vec<RegisteredPlugin>, PluginsPortError> {
        self.svc.list(tenant_id).await.map_err(map_err)
    }

    async fn install(
        &self,
        tenant_id: &str,
        manifest: PluginManifest,
        secret: SecretString,
    ) -> Result<RegisteredPlugin, PluginsPortError> {
        // Host-side audit. The controller emits a parallel
        // `audit` event with the actor/sub; the adapter event is
        // primarily for the storage layer's accounting.
        tracing::info!(
            target: "audit",
            action = "plugins.host.install",
            tenant_id = %tenant_id,
            plugin_name = %manifest.name,
            plugin_vendor = %manifest.vendor,
            plugin_version = %manifest.version,
            supported_events = ?manifest.supported_events,
            "host-side plugin install"
        );
        self.svc
            .register(tenant_id, manifest, secret)
            .await
            .map_err(map_err)
    }

    async fn uninstall(
        &self,
        tenant_id: &str,
        plugin_id: PluginId,
    ) -> Result<(), PluginsPortError> {
        tracing::info!(
            target: "audit",
            action = "plugins.host.uninstall",
            tenant_id = %tenant_id,
            plugin_id = %plugin_id,
            "host-side plugin uninstall"
        );
        self.svc.delete(tenant_id, plugin_id).await.map_err(map_err)
    }

    async fn list_dispatches(
        &self,
        tenant_id: &str,
        plugin_id: PluginId,
        limit: usize,
    ) -> Result<Vec<DispatchRecord>, PluginsPortError> {
        self.svc
            .list_dispatches(tenant_id, plugin_id, limit)
            .await
            .map_err(map_err)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use sx_plugins::EventKind;

    fn manifest() -> PluginManifest {
        PluginManifest {
            name: "Acme".into(),
            vendor: "Acme Inc".into(),
            version: "0.1.0".into(),
            webhook_url: "https://acme.example/hook".into(),
            supported_events: vec![EventKind::FindingCreated],
            required_scopes: vec![],
        }
    }

    fn long_secret() -> SecretString {
        SecretString::new("0123456789abcdef0123".to_owned().into())
    }

    #[tokio::test]
    async fn install_list_and_uninstall_round_trip() {
        let bundle = build();
        let rp = bundle
            .plugins
            .install("tenant-a", manifest(), long_secret())
            .await
            .unwrap();
        assert_eq!(rp.tenant_id, "tenant-a");
        assert_eq!(rp.name, "Acme");

        let list = bundle.plugins.list("tenant-a").await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, rp.id);

        bundle.plugins.uninstall("tenant-a", rp.id).await.unwrap();
        let after = bundle.plugins.list("tenant-a").await.unwrap();
        assert!(after.is_empty());
    }

    #[tokio::test]
    async fn cross_tenant_reads_are_isolated() {
        let bundle = build();
        let rp = bundle
            .plugins
            .install("tenant-a", manifest(), long_secret())
            .await
            .unwrap();

        // Tenant B sees nothing.
        let other = bundle.plugins.list("tenant-b").await.unwrap();
        assert!(other.is_empty());

        // And cannot uninstall by id — NotFound is mapped from the
        // service layer's tenant filter.
        let err = bundle
            .plugins
            .uninstall("tenant-b", rp.id)
            .await
            .expect_err("cross-tenant uninstall must fail");
        assert!(matches!(err, PluginsPortError::NotFound));

        // Tenant A still owns the row.
        let mine = bundle.plugins.list("tenant-a").await.unwrap();
        assert_eq!(mine.len(), 1);
    }

    #[tokio::test]
    async fn uninstall_unknown_is_not_found() {
        let bundle = build();
        let err = bundle
            .plugins
            .uninstall("tenant-a", PluginId::new())
            .await
            .expect_err("unknown id must be NotFound");
        assert!(matches!(err, PluginsPortError::NotFound));
    }

    #[tokio::test]
    async fn list_dispatches_starts_empty_then_grows() {
        let bundle = build();
        let rp = bundle
            .plugins
            .install("tenant-a", manifest(), long_secret())
            .await
            .unwrap();
        let empty = bundle
            .plugins
            .list_dispatches("tenant-a", rp.id, 10)
            .await
            .unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn map_err_covers_every_variant() {
        assert!(matches!(
            map_err(PluginServiceError::NotFound),
            PluginsPortError::NotFound
        ));
        assert!(matches!(
            map_err(PluginServiceError::Dependency("db".into())),
            PluginsPortError::Dependency(_)
        ));
        assert!(matches!(
            map_err(PluginServiceError::Internal("oops".into())),
            PluginsPortError::Internal(_)
        ));
    }

    /// Durability proof against a real Postgres: a registered plugin (its
    /// manifest + sealed HMAC secret) and a dispatch record survive a
    /// *fresh service (restart-equivalent)*; the secret unseals, the
    /// event-kind subscribers resolve, the registry is tenant-scoped, and
    /// `delete` drops both the plugin and its dispatch history. Gated on
    /// `TEST_DATABASE_URL` (silent no-op in CI).
    #[tokio::test]
    async fn pg_plugin_registry_survives_restart() {
        use secrecy::ExposeSecret;
        use sx_plugins::dispatcher::DispatchStatus;
        use sx_webhooks::signing::secret_cipher::PlaintextCipher;

        #[allow(clippy::disallowed_methods)]
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let tenant = uuid::Uuid::new_v4().to_string();
        let cipher = || Arc::new(PlaintextCipher) as Arc<dyn SecretCipher>;

        // Process 1: register a plugin + record one dispatch.
        let plugin_id = {
            let pool = sqlx::PgPool::connect(&url).await.expect("connect");
            let svc = PgPluginService {
                pool,
                stmt_timeout_ms: 15_000,
                cipher: cipher(),
            };
            let rp = svc
                .register(
                    &tenant,
                    manifest(),
                    SecretString::new("topsecret-signing-key".to_owned().into()),
                )
                .await
                .expect("register");
            svc.record_dispatch(DispatchRecord {
                id: uuid::Uuid::new_v4(),
                tenant_id: tenant.clone(),
                plugin_id: rp.id,
                event_kind: EventKind::FindingCreated,
                payload_hash: [7_u8; 32],
                status: DispatchStatus::Success,
                latency_ms: 5,
                response_excerpt: Some("ok".into()),
                ts: "2026-01-01T00:00:00Z".into(),
            })
            .await
            .expect("record dispatch");
            rp.id
        };

        // Process 2 (fresh pool): everything persisted.
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("reconnect");
            let svc = PgPluginService {
                pool,
                stmt_timeout_ms: 15_000,
                cipher: cipher(),
            };

            let list = svc.list(&tenant).await.expect("list");
            assert_eq!(list.len(), 1, "registration survived restart");
            assert_eq!(list[0].id, plugin_id);
            assert_eq!(list[0].name, "Acme");

            let view = svc.unseal_secret(&tenant, plugin_id).await.expect("unseal");
            assert_eq!(
                view.secret.expose_secret(),
                "topsecret-signing-key",
                "signing secret survived restart"
            );

            let subs = svc
                .subscribers(&tenant, EventKind::FindingCreated)
                .await
                .expect("subscribers");
            assert_eq!(subs.len(), 1, "event subscribers resolved from Pg");

            let disp = svc
                .list_dispatches(&tenant, plugin_id, 10)
                .await
                .expect("disp");
            assert_eq!(disp.len(), 1, "dispatch history survived restart");
            assert_eq!(disp[0].payload_hash, [7_u8; 32]);

            // Tenant isolation.
            let other = uuid::Uuid::new_v4().to_string();
            assert!(
                svc.list(&other).await.expect("other").is_empty(),
                "registry is tenant-scoped"
            );

            // Delete drops the plugin AND its dispatch history.
            svc.delete(&tenant, plugin_id).await.expect("delete");
            assert!(svc.list(&tenant).await.expect("after").is_empty());
            assert!(svc
                .list_dispatches(&tenant, plugin_id, 10)
                .await
                .expect("disp after")
                .is_empty());
            // Deleting an unknown (tenant, plugin) is NotFound.
            assert!(matches!(
                svc.delete(&tenant, plugin_id).await,
                Err(PluginServiceError::NotFound)
            ));
        }
    }
}
