//! [`PluginService`] trait + in-memory implementation.
//!
//! The service is the storage abstraction the HTTP controller and
//! adapter share — it owns the registered manifests, their secrets, and
//! the dispatch history. Production wires a Postgres-backed
//! implementation behind the same trait; the in-memory variant ships
//! for dev / standalone runs and tests.
//!
//! The in-memory variant uses a single `Mutex<InnerState>` guard for the
//! whole method body. Sub-millisecond critical sections are fine for the
//! per-request fan-out path; clippy's
//! `significant_drop_tightening` lint is suppressed at module scope.

#![allow(clippy::significant_drop_tightening)]

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::dispatcher::DispatchRecord;
#[cfg(test)]
use crate::dispatcher::DispatchStatus;
use crate::envelope::EventKind;
use crate::manifest::{PluginId, PluginManifest, RegisteredPlugin};

/// Errors surfaced by the plugin storage layer.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PluginServiceError {
    /// Plugin id is unknown for the supplied tenant.
    #[error("plugin not found")]
    NotFound,
    /// The dependency (storage) failed.
    #[error("dependency: {0}")]
    Dependency(String),
    /// Programmer error.
    #[error("internal: {0}")]
    Internal(String),
}

/// Snapshot of a registered plugin **with its secret**, returned to the
/// dispatcher when it needs to sign an envelope.
///
/// Callers MUST treat the `secret` as ephemeral — it lives on the heap
/// only for the duration of a single dispatch.
#[derive(Debug, Clone)]
pub struct PluginSecretView {
    /// Plugin id.
    pub id: PluginId,
    /// Webhook URL.
    pub webhook_url: String,
    /// HMAC signing secret.
    pub secret: SecretString,
    /// Event kinds the plugin subscribes to — used by the adapter to
    /// double-check the dispatch matches the registration.
    pub supported_events: Vec<EventKind>,
    /// Whether the plugin is currently enabled.
    pub enabled: bool,
}

/// Storage abstraction for registered plugins + their dispatch history.
#[async_trait]
pub trait PluginService: Send + Sync + std::fmt::Debug {
    /// List every plugin registered for `tenant_id`, newest-first.
    async fn list(&self, tenant_id: &str) -> Result<Vec<RegisteredPlugin>, PluginServiceError>;

    /// Look up a single plugin by id, scoped to `tenant_id`.
    async fn get(
        &self,
        tenant_id: &str,
        plugin_id: PluginId,
    ) -> Result<RegisteredPlugin, PluginServiceError>;

    /// Register a fresh plugin. The service mints a [`PluginId`] and
    /// stores the secret encrypted (via DEK pipeline in the Postgres
    /// adapter; in-memory variant just retains the `SecretString`).
    async fn register(
        &self,
        tenant_id: &str,
        manifest: PluginManifest,
        secret: SecretString,
    ) -> Result<RegisteredPlugin, PluginServiceError>;

    /// Remove a registered plugin. Returns `NotFound` when no row
    /// matches `(tenant_id, plugin_id)`.
    async fn delete(&self, tenant_id: &str, plugin_id: PluginId) -> Result<(), PluginServiceError>;

    /// Unseal the secret + webhook for a plugin (dispatcher path).
    async fn unseal_secret(
        &self,
        tenant_id: &str,
        plugin_id: PluginId,
    ) -> Result<PluginSecretView, PluginServiceError>;

    /// Resolve every plugin that subscribes to `event_kind` for
    /// `tenant_id` — used by the fan-out adapter.
    async fn subscribers(
        &self,
        tenant_id: &str,
        event_kind: EventKind,
    ) -> Result<Vec<PluginSecretView>, PluginServiceError>;

    /// Persist a dispatch outcome for later read-side surfacing.
    async fn record_dispatch(&self, record: DispatchRecord) -> Result<(), PluginServiceError>;

    /// Return the last `limit` dispatches for a plugin (newest-first).
    async fn list_dispatches(
        &self,
        tenant_id: &str,
        plugin_id: PluginId,
        limit: usize,
    ) -> Result<Vec<DispatchRecord>, PluginServiceError>;
}

/// In-memory [`PluginService`] — sufficient for dev / standalone runs
/// and the integration test suite. Production swaps this for a
/// Postgres-backed implementation.
pub struct InMemoryPluginService {
    inner: Mutex<InnerState>,
}

impl std::fmt::Debug for InMemoryPluginService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryPluginService")
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct InnerState {
    /// `(tenant_id, plugin_id) -> Stored`.
    plugins: HashMap<(String, PluginId), Stored>,
    /// `(tenant_id, plugin_id) -> dispatches` (newest pushed at front).
    dispatches: HashMap<(String, PluginId), Vec<DispatchRecord>>,
}

#[derive(Clone)]
struct Stored {
    registered: RegisteredPlugin,
    /// Cleartext secret. In Postgres-backed production this is held
    /// only as the DEK-wrapped ciphertext + unsealed per-request.
    secret: String,
}

impl Default for InMemoryPluginService {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryPluginService {
    /// Build an empty in-memory service.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(InnerState::default()),
        }
    }

    fn now_rfc3339() -> String {
        OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"))
    }
}

#[async_trait]
impl PluginService for InMemoryPluginService {
    async fn list(&self, tenant_id: &str) -> Result<Vec<RegisteredPlugin>, PluginServiceError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| PluginServiceError::Internal("plugins mutex poisoned".into()))?;
        let mut out: Vec<RegisteredPlugin> = guard
            .plugins
            .iter()
            .filter_map(|((t, _), s)| {
                if t == tenant_id {
                    Some(s.registered.clone())
                } else {
                    None
                }
            })
            .collect();
        // Newest-first.
        out.sort_by(|a, b| b.registered_at.cmp(&a.registered_at));
        Ok(out)
    }

    async fn get(
        &self,
        tenant_id: &str,
        plugin_id: PluginId,
    ) -> Result<RegisteredPlugin, PluginServiceError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| PluginServiceError::Internal("plugins mutex poisoned".into()))?;
        guard
            .plugins
            .get(&(tenant_id.to_owned(), plugin_id))
            .map(|s| s.registered.clone())
            .ok_or(PluginServiceError::NotFound)
    }

    async fn register(
        &self,
        tenant_id: &str,
        manifest: PluginManifest,
        secret: SecretString,
    ) -> Result<RegisteredPlugin, PluginServiceError> {
        let id = PluginId::new();
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
            registered_at: Self::now_rfc3339(),
        };
        let stored = Stored {
            registered: registered.clone(),
            secret: secret.expose_secret().to_owned(),
        };
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| PluginServiceError::Internal("plugins mutex poisoned".into()))?;
        guard.plugins.insert((tenant_id.to_owned(), id), stored);
        Ok(registered)
    }

    async fn delete(&self, tenant_id: &str, plugin_id: PluginId) -> Result<(), PluginServiceError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| PluginServiceError::Internal("plugins mutex poisoned".into()))?;
        let key = (tenant_id.to_owned(), plugin_id);
        if guard.plugins.remove(&key).is_some() {
            guard.dispatches.remove(&key);
            Ok(())
        } else {
            Err(PluginServiceError::NotFound)
        }
    }

    async fn unseal_secret(
        &self,
        tenant_id: &str,
        plugin_id: PluginId,
    ) -> Result<PluginSecretView, PluginServiceError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| PluginServiceError::Internal("plugins mutex poisoned".into()))?;
        let stored = guard
            .plugins
            .get(&(tenant_id.to_owned(), plugin_id))
            .ok_or(PluginServiceError::NotFound)?;
        Ok(PluginSecretView {
            id: stored.registered.id,
            webhook_url: stored.registered.webhook_url.clone(),
            secret: SecretString::new(stored.secret.clone().into()),
            supported_events: stored.registered.supported_events.clone(),
            enabled: stored.registered.enabled,
        })
    }

    async fn subscribers(
        &self,
        tenant_id: &str,
        event_kind: EventKind,
    ) -> Result<Vec<PluginSecretView>, PluginServiceError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| PluginServiceError::Internal("plugins mutex poisoned".into()))?;
        let mut out = Vec::new();
        for ((t, _), stored) in &guard.plugins {
            if t != tenant_id || !stored.registered.enabled {
                continue;
            }
            if stored.registered.supported_events.contains(&event_kind) {
                out.push(PluginSecretView {
                    id: stored.registered.id,
                    webhook_url: stored.registered.webhook_url.clone(),
                    secret: SecretString::new(stored.secret.clone().into()),
                    supported_events: stored.registered.supported_events.clone(),
                    enabled: stored.registered.enabled,
                });
            }
        }
        Ok(out)
    }

    async fn record_dispatch(&self, record: DispatchRecord) -> Result<(), PluginServiceError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| PluginServiceError::Internal("plugins mutex poisoned".into()))?;
        let key = (record.tenant_id.clone(), record.plugin_id);
        let entry = guard.dispatches.entry(key).or_default();
        entry.insert(0, record);
        // Cap the per-plugin history at 256 rows to avoid unbounded
        // growth in the in-memory variant.
        if entry.len() > 256 {
            entry.truncate(256);
        }
        Ok(())
    }

    async fn list_dispatches(
        &self,
        tenant_id: &str,
        plugin_id: PluginId,
        limit: usize,
    ) -> Result<Vec<DispatchRecord>, PluginServiceError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| PluginServiceError::Internal("plugins mutex poisoned".into()))?;
        let key = (tenant_id.to_owned(), plugin_id);
        let out = guard
            .dispatches
            .get(&key)
            .map_or_else(Vec::new, |v| v.iter().take(limit).cloned().collect());
        Ok(out)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use uuid::Uuid;

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

    #[tokio::test]
    async fn register_and_list_round_trip() {
        let svc = InMemoryPluginService::new();
        let rp = svc
            .register("t1", manifest(), SecretString::new("s".to_owned().into()))
            .await
            .unwrap();
        assert_eq!(rp.name, "Acme");
        assert_eq!(rp.tenant_id, "t1");
        assert!(rp.enabled);

        let items = svc.list("t1").await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, rp.id);
    }

    #[tokio::test]
    async fn list_is_tenant_scoped() {
        let svc = InMemoryPluginService::new();
        svc.register("t1", manifest(), SecretString::new("s".to_owned().into()))
            .await
            .unwrap();
        let items = svc.list("t2").await.unwrap();
        assert!(items.is_empty());
    }

    #[tokio::test]
    async fn delete_unknown_returns_not_found() {
        let svc = InMemoryPluginService::new();
        let id = PluginId(Uuid::new_v4());
        let err = svc.delete("t1", id).await.unwrap_err();
        assert!(matches!(err, PluginServiceError::NotFound));
    }

    #[tokio::test]
    async fn unseal_returns_secret() {
        let svc = InMemoryPluginService::new();
        let rp = svc
            .register(
                "t1",
                manifest(),
                SecretString::new("topsecret".to_owned().into()),
            )
            .await
            .unwrap();
        let view = svc.unseal_secret("t1", rp.id).await.unwrap();
        assert_eq!(view.secret.expose_secret(), "topsecret");
        assert_eq!(view.webhook_url, "https://acme.example/hook");
    }

    #[tokio::test]
    async fn subscribers_filters_by_event_kind() {
        let svc = InMemoryPluginService::new();
        svc.register("t1", manifest(), SecretString::new("s".to_owned().into()))
            .await
            .unwrap();
        let subs = svc
            .subscribers("t1", EventKind::FindingCreated)
            .await
            .unwrap();
        assert_eq!(subs.len(), 1);
        let none = svc
            .subscribers("t1", EventKind::BasCompleted)
            .await
            .unwrap();
        assert!(none.is_empty());
    }

    #[tokio::test]
    async fn dispatch_history_round_trip() {
        let svc = InMemoryPluginService::new();
        let rp = svc
            .register("t1", manifest(), SecretString::new("s".to_owned().into()))
            .await
            .unwrap();
        let rec = DispatchRecord {
            id: Uuid::new_v4(),
            tenant_id: "t1".into(),
            plugin_id: rp.id,
            event_kind: EventKind::FindingCreated,
            payload_hash: [0_u8; 32],
            status: DispatchStatus::Success,
            latency_ms: 12,
            response_excerpt: Some("ok".into()),
            ts: "2026-01-01T00:00:00Z".into(),
        };
        svc.record_dispatch(rec.clone()).await.unwrap();
        let out = svc.list_dispatches("t1", rp.id, 10).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, rec.id);
    }

    #[tokio::test]
    async fn delete_drops_dispatch_history() {
        let svc = InMemoryPluginService::new();
        let rp = svc
            .register("t1", manifest(), SecretString::new("s".to_owned().into()))
            .await
            .unwrap();
        svc.record_dispatch(DispatchRecord {
            id: Uuid::new_v4(),
            tenant_id: "t1".into(),
            plugin_id: rp.id,
            event_kind: EventKind::FindingCreated,
            payload_hash: [0_u8; 32],
            status: DispatchStatus::Success,
            latency_ms: 1,
            response_excerpt: None,
            ts: "2026-01-01T00:00:00Z".into(),
        })
        .await
        .unwrap();
        svc.delete("t1", rp.id).await.unwrap();
        let out = svc.list_dispatches("t1", rp.id, 10).await.unwrap();
        assert!(out.is_empty());
    }
}
