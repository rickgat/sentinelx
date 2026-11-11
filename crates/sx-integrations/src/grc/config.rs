//! Per-tenant GRC connection configuration store.
//!
//! The store keeps one row per `(tenant_id, kind)` — the
//! `grc_connections` table in `sx-storage`. For the MVP the
//! authoritative representation is held in memory (cheap clone of the
//! row metadata) while the actual API token / password lives inside a
//! [`sx_secrets::SecretsProvider`]-backed secret store. The metadata
//! row only holds the *secret path* — never the secret itself — so the
//! `Debug` surface and any future audit-replay tooling stays clean.
//!
//! ## Schema (logical)
//!
//! ```text
//! grc_connections(
//!   tenant_id   uuid not null,
//!   kind        text not null,   -- vanta | drata | servicenow
//!   instance_url text,            -- servicenow only
//!   user        text,             -- servicenow only
//!   secret_path text not null,   -- key into the secret store
//!   created_at  timestamptz not null,
//!   primary key (tenant_id, kind)
//! )
//! ```
//!
//! ## Token resolution
//!
//! At dispatch time the monolith adapter resolves the configured
//! connection into a concrete [`super::connector::GrcConnector`] by:
//!
//! 1. Loading the [`GrcConnectionConfig`] row from the in-memory store.
//! 2. Fetching the bearer token / password from the secret store via
//!    `SecretsProvider::get(secret_path)`.
//! 3. Constructing the vendor-specific connector with the freshly
//!    materialised credentials.
//!
//! Step 2 is intentionally per-dispatch — the token is never cached
//! inside the [`GrcConnectionConfig`] so a rotation upstream is
//! immediately observable to the next push.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sx_secrets::SecretsProvider;
use thiserror::Error;
use tokio::sync::Mutex;

use super::connector::GrcKind;

/// Errors surfaced by the config store + token resolver.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// No row for the requested `(tenant_id, kind)` tuple.
    #[error("no GRC connection configured for tenant")]
    NotFound,

    /// The secret-store path returned no value.
    #[error("secret store missing entry at `{path}`")]
    MissingSecret {
        /// Path that returned no value.
        path: String,
    },

    /// The secret store rejected the lookup on authn/authz grounds.
    #[error("secret store unauthorized")]
    SecretsUnauthorized,

    /// Any other failure surfaced by the secret store.
    #[error("secret store error: {0}")]
    Secrets(String),

    /// The connection metadata was malformed (e.g. `ServiceNow` row
    /// missing `instance_url`).
    #[error("invalid GRC connection metadata: {0}")]
    Invalid(String),
}

impl From<sx_secrets::SecretsError> for ConfigError {
    fn from(err: sx_secrets::SecretsError) -> Self {
        use sx_secrets::SecretsError as E;
        match err {
            E::NotFound(p) => Self::MissingSecret { path: p },
            E::Unauthorized => Self::SecretsUnauthorized,
            other => Self::Secrets(other.to_string()),
        }
    }
}

/// Per-tenant GRC connection row.
///
/// The row carries only the *metadata* the dispatcher needs to assemble
/// a connector; the actual credential lives in the
/// [`SecretsProvider`]-backed secret store at `secret_path`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrcConnectionConfig {
    /// Tenant uuid.
    pub tenant_id: String,
    /// Connector kind.
    pub kind: GrcKind,
    /// `ServiceNow` instance URL. Required when `kind == ServiceNow`,
    /// otherwise `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_url: Option<String>,
    /// `ServiceNow` basic-auth user. Required when `kind == ServiceNow`,
    /// otherwise `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Stable path into the [`SecretsProvider`] where the API
    /// token / password lives. Required for every kind.
    pub secret_path: String,
    /// RFC 3339 timestamp the row was inserted / replaced.
    pub created_at: String,
}

impl GrcConnectionConfig {
    /// Sanity-check the row shape for the configured kind. Returns
    /// [`ConfigError::Invalid`] when a required field is missing.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.secret_path.trim().is_empty() {
            return Err(ConfigError::Invalid("secret_path empty".into()));
        }
        if self.tenant_id.trim().is_empty() {
            return Err(ConfigError::Invalid("tenant_id empty".into()));
        }
        if self.kind == GrcKind::ServiceNow {
            let has_url = self
                .instance_url
                .as_ref()
                .is_some_and(|u| !u.trim().is_empty());
            let has_user = self.user.as_ref().is_some_and(|u| !u.trim().is_empty());
            if !has_url {
                return Err(ConfigError::Invalid(
                    "servicenow row missing instance_url".into(),
                ));
            }
            if !has_user {
                return Err(ConfigError::Invalid("servicenow row missing user".into()));
            }
        }
        Ok(())
    }
}

/// Async store of per-tenant GRC connections.
#[async_trait]
pub trait GrcConfigStore: Send + Sync + std::fmt::Debug {
    /// Fetch the row for `(tenant_id, kind)`, or `None` when nothing is
    /// configured.
    async fn get(
        &self,
        tenant_id: &str,
        kind: GrcKind,
    ) -> Result<Option<GrcConnectionConfig>, ConfigError>;

    /// Upsert the row keyed by `(tenant_id, kind)`. Returns the row
    /// after persistence.
    async fn upsert(&self, config: GrcConnectionConfig)
        -> Result<GrcConnectionConfig, ConfigError>;

    /// Delete the row for `(tenant_id, kind)`. Returns `true` when a
    /// row was removed, `false` when nothing was present.
    async fn delete(&self, tenant_id: &str, kind: GrcKind) -> Result<bool, ConfigError>;

    /// List every configured kind for `tenant_id`.
    async fn list_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<GrcConnectionConfig>, ConfigError>;
}

/// In-memory implementation of [`GrcConfigStore`]. Keyed on
/// `(tenant_id, kind)` — matches the production Postgres unique index.
#[derive(Default)]
pub struct InMemoryGrcConfigStore {
    rows: Mutex<HashMap<(String, GrcKind), GrcConnectionConfig>>,
}

impl std::fmt::Debug for InMemoryGrcConfigStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryGrcConfigStore")
            .finish_non_exhaustive()
    }
}

impl InMemoryGrcConfigStore {
    /// Construct an empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl GrcConfigStore for InMemoryGrcConfigStore {
    async fn get(
        &self,
        tenant_id: &str,
        kind: GrcKind,
    ) -> Result<Option<GrcConnectionConfig>, ConfigError> {
        let guard = self.rows.lock().await;
        Ok(guard.get(&(tenant_id.to_owned(), kind)).cloned())
    }

    async fn upsert(
        &self,
        config: GrcConnectionConfig,
    ) -> Result<GrcConnectionConfig, ConfigError> {
        config.validate()?;
        let key = (config.tenant_id.clone(), config.kind);
        {
            let mut guard = self.rows.lock().await;
            guard.insert(key, config.clone());
        }
        Ok(config)
    }

    async fn delete(&self, tenant_id: &str, kind: GrcKind) -> Result<bool, ConfigError> {
        let mut guard = self.rows.lock().await;
        Ok(guard.remove(&(tenant_id.to_owned(), kind)).is_some())
    }

    async fn list_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<GrcConnectionConfig>, ConfigError> {
        let mut out: Vec<GrcConnectionConfig> = {
            let guard = self.rows.lock().await;
            guard
                .values()
                .filter(|c| c.tenant_id == tenant_id)
                .cloned()
                .collect()
        };
        out.sort_by_key(|c| c.kind.as_wire());
        Ok(out)
    }
}

/// Materialise the bearer-style secret for `config` from `secrets`.
///
/// Surfaces [`ConfigError::MissingSecret`] when the store has no value
/// at `config.secret_path`.
pub async fn load_secret(
    secrets: &Arc<dyn SecretsProvider>,
    config: &GrcConnectionConfig,
) -> Result<SecretString, ConfigError> {
    config.validate()?;
    let value = secrets.get(&config.secret_path).await?;
    Ok(value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use sx_secrets::InMemoryProvider;

    fn vanta_config() -> GrcConnectionConfig {
        GrcConnectionConfig {
            tenant_id: "t-1".into(),
            kind: GrcKind::Vanta,
            instance_url: None,
            user: None,
            secret_path: "tenants/t-1/grc/vanta/api_key".into(),
            created_at: "2027-01-01T00:00:00Z".into(),
        }
    }

    fn servicenow_config() -> GrcConnectionConfig {
        GrcConnectionConfig {
            tenant_id: "t-1".into(),
            kind: GrcKind::ServiceNow,
            instance_url: Some("https://acme.service-now.com".into()),
            user: Some("ops".into()),
            secret_path: "tenants/t-1/grc/servicenow/password".into(),
            created_at: "2027-01-01T00:00:00Z".into(),
        }
    }

    #[tokio::test]
    async fn upsert_then_get_round_trips() {
        let store = InMemoryGrcConfigStore::new();
        let cfg = vanta_config();
        store.upsert(cfg.clone()).await.unwrap();
        let got = store.get("t-1", GrcKind::Vanta).await.unwrap();
        assert_eq!(got, Some(cfg));
    }

    #[tokio::test]
    async fn upsert_replaces_existing_row() {
        let store = InMemoryGrcConfigStore::new();
        store.upsert(vanta_config()).await.unwrap();
        let mut updated = vanta_config();
        updated.secret_path = "tenants/t-1/grc/vanta/api_key_v2".into();
        store.upsert(updated.clone()).await.unwrap();
        let got = store.get("t-1", GrcKind::Vanta).await.unwrap().unwrap();
        assert_eq!(got.secret_path, "tenants/t-1/grc/vanta/api_key_v2");
    }

    #[tokio::test]
    async fn delete_returns_false_when_missing() {
        let store = InMemoryGrcConfigStore::new();
        assert!(!store.delete("t-1", GrcKind::Vanta).await.unwrap());
    }

    #[tokio::test]
    async fn delete_returns_true_when_present() {
        let store = InMemoryGrcConfigStore::new();
        store.upsert(vanta_config()).await.unwrap();
        assert!(store.delete("t-1", GrcKind::Vanta).await.unwrap());
        assert_eq!(store.get("t-1", GrcKind::Vanta).await.unwrap(), None);
    }

    #[tokio::test]
    async fn list_for_tenant_is_sorted_and_scoped() {
        let store = InMemoryGrcConfigStore::new();
        store.upsert(vanta_config()).await.unwrap();
        store.upsert(servicenow_config()).await.unwrap();
        // Different tenant — must not be returned.
        let mut other = vanta_config();
        other.tenant_id = "t-2".into();
        store.upsert(other).await.unwrap();

        let list = store.list_for_tenant("t-1").await.unwrap();
        assert_eq!(list.len(), 2);
        // Sorted by wire string: "servicenow" < "vanta".
        assert_eq!(list[0].kind, GrcKind::ServiceNow);
        assert_eq!(list[1].kind, GrcKind::Vanta);
    }

    #[tokio::test]
    async fn servicenow_row_validation_requires_url_and_user() {
        let store = InMemoryGrcConfigStore::new();
        let mut bad = servicenow_config();
        bad.instance_url = None;
        let err = store.upsert(bad).await.unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));

        let mut bad2 = servicenow_config();
        bad2.user = Some("   ".into());
        let err = store.upsert(bad2).await.unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[tokio::test]
    async fn empty_secret_path_rejected() {
        let store = InMemoryGrcConfigStore::new();
        let mut bad = vanta_config();
        bad.secret_path = String::new();
        assert!(matches!(
            store.upsert(bad).await.unwrap_err(),
            ConfigError::Invalid(_)
        ));
    }

    #[tokio::test]
    async fn load_secret_resolves_via_provider() {
        let provider: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        provider
            .put(
                "tenants/t-1/grc/vanta/api_key",
                SecretString::from("vanta-key-shh".to_owned()),
            )
            .await
            .unwrap();
        let cfg = vanta_config();
        let secret = load_secret(&provider, &cfg).await.unwrap();
        assert_eq!(secret.expose_secret(), "vanta-key-shh");
    }

    #[tokio::test]
    async fn load_secret_missing_path_surfaces_missing_secret() {
        let provider: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        let cfg = vanta_config();
        let err = load_secret(&provider, &cfg).await.unwrap_err();
        match err {
            ConfigError::MissingSecret { path } => {
                assert!(path.contains("vanta"));
            }
            other => panic!("expected MissingSecret, got {other:?}"),
        }
    }
}
