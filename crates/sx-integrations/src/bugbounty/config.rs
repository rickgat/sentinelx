//! Per-tenant bug-bounty connection configuration store.
//!
//! Mirrors the layout of [`crate::grc::config`]:
//!
//! * The store keeps one row per `(tenant_id, kind, program_handle)` —
//!   conceptually the `bug_bounty_connections` table in `sx-storage`.
//! * Credentials are *never* held in the row. The row stores only the
//!   metadata + a `secret_path` into a [`SecretsProvider`]-backed secret
//!   store that holds the actual API token (and, for HackerOne, the
//!   companion API username).
//! * Each platform has its **own** credential schema. HackerOne requires
//!   an `api_username` field; Bugcrowd does not — the schema is
//!   normalised onto a single [`BugBountyConnectionConfig`] row by
//!   capturing the username inline (it is not a secret) and the token
//!   under `secret_path`.
//!
//! ## Schema (logical)
//!
//! ```text
//! bug_bounty_connections(
//!   tenant_id      uuid not null,
//!   kind           text not null,   -- hackerone | bugcrowd
//!   program_handle text not null,   -- platform-side program identifier
//!   api_username   text,            -- hackerone only
//!   webhook_secret_path text not null, -- key into secret store for HMAC secret
//!   token_secret_path   text not null, -- key into secret store for API token
//!   created_at     timestamptz not null,
//!   primary key (tenant_id, kind, program_handle)
//! )
//! ```
//!
//! ## Token resolution
//!
//! Token + webhook secret materialisation is per-dispatch — the secrets
//! are never cached inside the row so an upstream rotation is immediately
//! observable on the next push / next inbound webhook verification.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sx_secrets::SecretsProvider;
use thiserror::Error;
use tokio::sync::Mutex;

use super::connector::BugBountyKind;

/// Errors surfaced by the config store + secret resolver.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// No row for the requested `(tenant_id, kind, program_handle)`
    /// tuple.
    #[error("no bug-bounty connection configured for tenant")]
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

    /// The connection metadata was malformed (e.g. HackerOne row missing
    /// `api_username`, or any field blank).
    #[error("invalid bug-bounty connection metadata: {0}")]
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

/// Per-tenant bug-bounty connection row.
///
/// The row carries only the *metadata* the dispatcher needs to assemble
/// a connector. The actual API token + the inbound HMAC webhook secret
/// live in the [`SecretsProvider`]-backed secret store at their
/// respective `*_secret_path` keys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BugBountyConnectionConfig {
    /// Tenant uuid.
    pub tenant_id: String,
    /// Connector kind.
    pub kind: BugBountyKind,
    /// Platform-side program handle (e.g. HackerOne `program.handle`,
    /// Bugcrowd engagement uuid).
    pub program_handle: String,
    /// HackerOne API username. Required when `kind == HackerOne`,
    /// `None` for Bugcrowd. Not a secret — it identifies the API user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_username: Option<String>,
    /// Stable path into the [`SecretsProvider`] where the inbound webhook
    /// HMAC secret lives. Required for every kind.
    pub webhook_secret_path: String,
    /// Stable path into the [`SecretsProvider`] where the API token (or
    /// HackerOne basic-auth password) lives. Required for every kind.
    pub token_secret_path: String,
    /// RFC 3339 timestamp the row was inserted / replaced.
    pub created_at: String,
}

impl BugBountyConnectionConfig {
    /// Sanity-check the row shape for the configured kind. Returns
    /// [`ConfigError::Invalid`] when a required field is missing.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.tenant_id.trim().is_empty() {
            return Err(ConfigError::Invalid("tenant_id empty".into()));
        }
        if self.program_handle.trim().is_empty() {
            return Err(ConfigError::Invalid("program_handle empty".into()));
        }
        if self.webhook_secret_path.trim().is_empty() {
            return Err(ConfigError::Invalid("webhook_secret_path empty".into()));
        }
        if self.token_secret_path.trim().is_empty() {
            return Err(ConfigError::Invalid("token_secret_path empty".into()));
        }
        if self.kind == BugBountyKind::HackerOne {
            let has_user = self
                .api_username
                .as_ref()
                .is_some_and(|u| !u.trim().is_empty());
            if !has_user {
                return Err(ConfigError::Invalid(
                    "hackerone row missing api_username".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Async store of per-tenant bug-bounty connections.
#[async_trait]
pub trait BugBountyConfigStore: Send + Sync + std::fmt::Debug {
    /// Fetch the row for `(tenant_id, kind, program_handle)`, or `None`
    /// when nothing is configured.
    async fn get(
        &self,
        tenant_id: &str,
        kind: BugBountyKind,
        program_handle: &str,
    ) -> Result<Option<BugBountyConnectionConfig>, ConfigError>;

    /// Upsert the row keyed by `(tenant_id, kind, program_handle)`.
    async fn upsert(
        &self,
        config: BugBountyConnectionConfig,
    ) -> Result<BugBountyConnectionConfig, ConfigError>;

    /// Delete the row for `(tenant_id, kind, program_handle)`. Returns
    /// `true` when a row was removed.
    async fn delete(
        &self,
        tenant_id: &str,
        kind: BugBountyKind,
        program_handle: &str,
    ) -> Result<bool, ConfigError>;

    /// List every configured connection for `tenant_id`.
    async fn list_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<BugBountyConnectionConfig>, ConfigError>;
}

/// In-memory implementation of [`BugBountyConfigStore`]. Keyed on
/// `(tenant_id, kind, program_handle)` — matches the production Postgres
/// unique index.
#[derive(Default)]
pub struct InMemoryBugBountyConfigStore {
    rows: Mutex<HashMap<(String, BugBountyKind, String), BugBountyConnectionConfig>>,
}

impl std::fmt::Debug for InMemoryBugBountyConfigStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryBugBountyConfigStore")
            .finish_non_exhaustive()
    }
}

impl InMemoryBugBountyConfigStore {
    /// Construct an empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl BugBountyConfigStore for InMemoryBugBountyConfigStore {
    async fn get(
        &self,
        tenant_id: &str,
        kind: BugBountyKind,
        program_handle: &str,
    ) -> Result<Option<BugBountyConnectionConfig>, ConfigError> {
        let guard = self.rows.lock().await;
        Ok(guard
            .get(&(tenant_id.to_owned(), kind, program_handle.to_owned()))
            .cloned())
    }

    async fn upsert(
        &self,
        config: BugBountyConnectionConfig,
    ) -> Result<BugBountyConnectionConfig, ConfigError> {
        config.validate()?;
        let key = (
            config.tenant_id.clone(),
            config.kind,
            config.program_handle.clone(),
        );
        {
            let mut guard = self.rows.lock().await;
            guard.insert(key, config.clone());
        }
        Ok(config)
    }

    async fn delete(
        &self,
        tenant_id: &str,
        kind: BugBountyKind,
        program_handle: &str,
    ) -> Result<bool, ConfigError> {
        let mut guard = self.rows.lock().await;
        Ok(guard
            .remove(&(tenant_id.to_owned(), kind, program_handle.to_owned()))
            .is_some())
    }

    async fn list_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<BugBountyConnectionConfig>, ConfigError> {
        let mut out: Vec<BugBountyConnectionConfig> = {
            let guard = self.rows.lock().await;
            guard
                .values()
                .filter(|c| c.tenant_id == tenant_id)
                .cloned()
                .collect()
        };
        out.sort_by(|a, b| {
            a.kind
                .as_wire()
                .cmp(b.kind.as_wire())
                .then_with(|| a.program_handle.cmp(&b.program_handle))
        });
        Ok(out)
    }
}

/// Materialise the API-token secret for `config` from `secrets`.
///
/// Surfaces [`ConfigError::MissingSecret`] when the store has no value
/// at `config.token_secret_path`.
pub async fn load_token(
    secrets: &Arc<dyn SecretsProvider>,
    config: &BugBountyConnectionConfig,
) -> Result<SecretString, ConfigError> {
    config.validate()?;
    let value = secrets.get(&config.token_secret_path).await?;
    Ok(value)
}

/// Materialise the inbound webhook HMAC secret for `config` from
/// `secrets`.
pub async fn load_webhook_secret(
    secrets: &Arc<dyn SecretsProvider>,
    config: &BugBountyConnectionConfig,
) -> Result<SecretString, ConfigError> {
    config.validate()?;
    let value = secrets.get(&config.webhook_secret_path).await?;
    Ok(value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use sx_secrets::InMemoryProvider;

    fn hackerone_config() -> BugBountyConnectionConfig {
        BugBountyConnectionConfig {
            tenant_id: "t-1".into(),
            kind: BugBountyKind::HackerOne,
            program_handle: "acme".into(),
            api_username: Some("ops-api".into()),
            webhook_secret_path: "tenants/t-1/bb/hackerone/acme/webhook".into(),
            token_secret_path: "tenants/t-1/bb/hackerone/acme/token".into(),
            created_at: "2027-01-01T00:00:00Z".into(),
        }
    }

    fn bugcrowd_config() -> BugBountyConnectionConfig {
        BugBountyConnectionConfig {
            tenant_id: "t-1".into(),
            kind: BugBountyKind::Bugcrowd,
            program_handle: "acme-public".into(),
            api_username: None,
            webhook_secret_path: "tenants/t-1/bb/bugcrowd/acme-public/webhook".into(),
            token_secret_path: "tenants/t-1/bb/bugcrowd/acme-public/token".into(),
            created_at: "2027-01-01T00:00:00Z".into(),
        }
    }

    #[tokio::test]
    async fn upsert_then_get_round_trips() {
        let store = InMemoryBugBountyConfigStore::new();
        let cfg = hackerone_config();
        store.upsert(cfg.clone()).await.unwrap();
        let got = store
            .get("t-1", BugBountyKind::HackerOne, "acme")
            .await
            .unwrap();
        assert_eq!(got, Some(cfg));
    }

    #[tokio::test]
    async fn upsert_replaces_existing_row() {
        let store = InMemoryBugBountyConfigStore::new();
        store.upsert(hackerone_config()).await.unwrap();
        let mut updated = hackerone_config();
        updated.token_secret_path = "tenants/t-1/bb/hackerone/acme/token_v2".into();
        store.upsert(updated.clone()).await.unwrap();
        let got = store
            .get("t-1", BugBountyKind::HackerOne, "acme")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.token_secret_path, updated.token_secret_path);
    }

    #[tokio::test]
    async fn delete_returns_false_when_missing() {
        let store = InMemoryBugBountyConfigStore::new();
        assert!(!store
            .delete("t-1", BugBountyKind::HackerOne, "acme")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn delete_returns_true_when_present() {
        let store = InMemoryBugBountyConfigStore::new();
        store.upsert(hackerone_config()).await.unwrap();
        assert!(store
            .delete("t-1", BugBountyKind::HackerOne, "acme")
            .await
            .unwrap());
        assert_eq!(
            store
                .get("t-1", BugBountyKind::HackerOne, "acme")
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn list_for_tenant_is_sorted_and_scoped() {
        let store = InMemoryBugBountyConfigStore::new();
        store.upsert(hackerone_config()).await.unwrap();
        store.upsert(bugcrowd_config()).await.unwrap();
        // Different tenant — must not be returned.
        let mut other = hackerone_config();
        other.tenant_id = "t-2".into();
        store.upsert(other).await.unwrap();

        let list = store.list_for_tenant("t-1").await.unwrap();
        assert_eq!(list.len(), 2);
        // Sorted by wire string: "bugcrowd" < "hackerone".
        assert_eq!(list[0].kind, BugBountyKind::Bugcrowd);
        assert_eq!(list[1].kind, BugBountyKind::HackerOne);
    }

    #[tokio::test]
    async fn hackerone_row_validation_requires_api_username() {
        let store = InMemoryBugBountyConfigStore::new();
        let mut bad = hackerone_config();
        bad.api_username = None;
        let err = store.upsert(bad).await.unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));

        let mut bad2 = hackerone_config();
        bad2.api_username = Some("   ".into());
        let err = store.upsert(bad2).await.unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(_)));
    }

    #[tokio::test]
    async fn bugcrowd_row_does_not_require_api_username() {
        let store = InMemoryBugBountyConfigStore::new();
        let cfg = bugcrowd_config();
        assert!(cfg.api_username.is_none());
        store.upsert(cfg).await.unwrap();
    }

    #[tokio::test]
    async fn empty_required_fields_rejected() {
        let store = InMemoryBugBountyConfigStore::new();
        for mutate in [
            |c: &mut BugBountyConnectionConfig| c.program_handle = String::new(),
            |c: &mut BugBountyConnectionConfig| c.token_secret_path = String::new(),
            |c: &mut BugBountyConnectionConfig| c.webhook_secret_path = String::new(),
            |c: &mut BugBountyConnectionConfig| c.tenant_id = String::new(),
        ] {
            let mut bad = bugcrowd_config();
            mutate(&mut bad);
            assert!(matches!(
                store.upsert(bad).await.unwrap_err(),
                ConfigError::Invalid(_)
            ));
        }
    }

    #[tokio::test]
    async fn load_token_resolves_via_provider() {
        let provider: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        provider
            .put(
                "tenants/t-1/bb/hackerone/acme/token",
                SecretString::from("h1-token-shh".to_owned()),
            )
            .await
            .unwrap();
        let cfg = hackerone_config();
        let secret = load_token(&provider, &cfg).await.unwrap();
        assert_eq!(secret.expose_secret(), "h1-token-shh");
    }

    #[tokio::test]
    async fn load_webhook_secret_resolves_via_provider() {
        let provider: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        provider
            .put(
                "tenants/t-1/bb/bugcrowd/acme-public/webhook",
                SecretString::from("hmac-secret-shh".to_owned()),
            )
            .await
            .unwrap();
        let cfg = bugcrowd_config();
        let secret = load_webhook_secret(&provider, &cfg).await.unwrap();
        assert_eq!(secret.expose_secret(), "hmac-secret-shh");
    }

    #[tokio::test]
    async fn load_token_missing_path_surfaces_missing_secret() {
        let provider: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        let cfg = bugcrowd_config();
        let err = load_token(&provider, &cfg).await.unwrap_err();
        match err {
            ConfigError::MissingSecret { path } => {
                assert!(path.contains("bugcrowd"));
            }
            other => panic!("expected MissingSecret, got {other:?}"),
        }
    }
}
