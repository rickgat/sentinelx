//! Per-tenant chat-ops channel configuration store.
//!
//! Each row binds a tenant to a single Slack or Teams channel and points
//! at *two* `sx-secrets` paths:
//!
//! 1. `webhook_secret_path` — the outbound incoming-webhook URL
//!    (`https://hooks.slack.com/services/...` for Slack,
//!    `https://...logic.azure.com/...` for Teams power-automate).
//! 2. `signing_secret_path` *(Slack only)* — the workspace's Slack
//!    signing secret used to verify the `X-Slack-Signature` header on
//!    inbound slash commands.
//!
//! The row carries only *paths* into the secret store, never the raw
//! values themselves, so the `Debug` surface and any future audit-replay
//! tooling stays clean.
//!
//! ## Schema (logical)
//!
//! ```text
//! chat_channels(
//!   tenant_id              uuid not null,
//!   provider               text not null,        -- slack | teams
//!   channel                text not null,        -- tenant-local label
//!   webhook_secret_path    text not null,
//!   signing_secret_path    text,                 -- slack only
//!   created_at             timestamptz not null,
//!   primary key (tenant_id, provider, channel)
//! )
//! ```
//!
//! ## Token resolution
//!
//! Like the GRC config store, secret resolution is per-dispatch so an
//! upstream rotation is immediately observable to the next post.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sx_secrets::SecretsProvider;
use thiserror::Error;
use tokio::sync::Mutex;

use super::audit::ChatAuditProvider;

/// Errors surfaced by the config store + secret resolver.
#[derive(Debug, Error)]
pub enum ChatConfigError {
    /// No row for the requested `(tenant_id, provider, channel)` tuple.
    #[error("no chat channel configured for tenant")]
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

    /// The channel metadata was malformed (missing field, empty string,
    /// signing path missing on a Slack row, ...).
    #[error("invalid chat channel metadata: {0}")]
    Invalid(String),
}

impl From<sx_secrets::SecretsError> for ChatConfigError {
    fn from(err: sx_secrets::SecretsError) -> Self {
        use sx_secrets::SecretsError as E;
        match err {
            E::NotFound(p) => Self::MissingSecret { path: p },
            E::Unauthorized => Self::SecretsUnauthorized,
            other => Self::Secrets(other.to_string()),
        }
    }
}

/// Per-tenant chat channel row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChatChannelConfig {
    /// Tenant uuid.
    pub tenant_id: String,
    /// Provider the channel binds to.
    pub provider: ChatAuditProvider,
    /// Tenant-local label for the channel (e.g. `"secops"`,
    /// `"#alerts-prod"`). Used as the audit `channel` field.
    pub channel: String,
    /// Path into the [`SecretsProvider`] where the outbound webhook URL
    /// lives. Required for every row.
    pub webhook_secret_path: String,
    /// Path into the [`SecretsProvider`] where the Slack signing secret
    /// lives. Required when `provider == Slack` *and* the tenant uses
    /// inbound slash commands; `None` otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_secret_path: Option<String>,
    /// RFC 3339 timestamp the row was inserted / replaced.
    pub created_at: String,
}

impl ChatChannelConfig {
    /// Sanity-check the row shape for the configured provider.
    pub fn validate(&self) -> Result<(), ChatConfigError> {
        if self.tenant_id.trim().is_empty() {
            return Err(ChatConfigError::Invalid("tenant_id empty".into()));
        }
        if self.channel.trim().is_empty() {
            return Err(ChatConfigError::Invalid("channel empty".into()));
        }
        if self.webhook_secret_path.trim().is_empty() {
            return Err(ChatConfigError::Invalid("webhook_secret_path empty".into()));
        }
        if let Some(path) = &self.signing_secret_path {
            if path.trim().is_empty() {
                return Err(ChatConfigError::Invalid(
                    "signing_secret_path is empty string".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Async store of per-tenant chat channels.
#[async_trait]
pub trait ChatConfigStore: Send + Sync + std::fmt::Debug {
    /// Fetch the row for `(tenant_id, provider, channel)`, or `None`.
    async fn get(
        &self,
        tenant_id: &str,
        provider: ChatAuditProvider,
        channel: &str,
    ) -> Result<Option<ChatChannelConfig>, ChatConfigError>;

    /// Upsert the row keyed by `(tenant_id, provider, channel)`.
    async fn upsert(&self, config: ChatChannelConfig)
        -> Result<ChatChannelConfig, ChatConfigError>;

    /// Delete the row. Returns `true` when a row was removed.
    async fn delete(
        &self,
        tenant_id: &str,
        provider: ChatAuditProvider,
        channel: &str,
    ) -> Result<bool, ChatConfigError>;

    /// List every configured channel for `tenant_id`.
    async fn list_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<ChatChannelConfig>, ChatConfigError>;
}

/// In-memory implementation of [`ChatConfigStore`].
#[derive(Default)]
pub struct InMemoryChatConfigStore {
    rows: Mutex<HashMap<(String, ChatAuditProvider, String), ChatChannelConfig>>,
}

impl std::fmt::Debug for InMemoryChatConfigStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryChatConfigStore")
            .finish_non_exhaustive()
    }
}

impl InMemoryChatConfigStore {
    /// Construct an empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ChatConfigStore for InMemoryChatConfigStore {
    async fn get(
        &self,
        tenant_id: &str,
        provider: ChatAuditProvider,
        channel: &str,
    ) -> Result<Option<ChatChannelConfig>, ChatConfigError> {
        let guard = self.rows.lock().await;
        Ok(guard
            .get(&(tenant_id.to_owned(), provider, channel.to_owned()))
            .cloned())
    }

    async fn upsert(
        &self,
        config: ChatChannelConfig,
    ) -> Result<ChatChannelConfig, ChatConfigError> {
        config.validate()?;
        let key = (
            config.tenant_id.clone(),
            config.provider,
            config.channel.clone(),
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
        provider: ChatAuditProvider,
        channel: &str,
    ) -> Result<bool, ChatConfigError> {
        let mut guard = self.rows.lock().await;
        Ok(guard
            .remove(&(tenant_id.to_owned(), provider, channel.to_owned()))
            .is_some())
    }

    async fn list_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<ChatChannelConfig>, ChatConfigError> {
        let mut out: Vec<ChatChannelConfig> = {
            let guard = self.rows.lock().await;
            guard
                .values()
                .filter(|c| c.tenant_id == tenant_id)
                .cloned()
                .collect()
        };
        out.sort_by(|a, b| {
            (a.provider.as_wire(), a.channel.as_str())
                .cmp(&(b.provider.as_wire(), b.channel.as_str()))
        });
        Ok(out)
    }
}

/// Resolve the outbound webhook URL for `config` from `secrets`.
///
/// Returns a [`SecretString`] so the caller can hand it straight to the
/// notifier's constructor without ever stringifying the value into logs.
pub async fn load_webhook_url(
    secrets: &Arc<dyn SecretsProvider>,
    config: &ChatChannelConfig,
) -> Result<SecretString, ChatConfigError> {
    config.validate()?;
    let value = secrets.get(&config.webhook_secret_path).await?;
    Ok(value)
}

/// Resolve the Slack signing secret for `config` from `secrets`. Returns
/// `Ok(None)` when the row does not declare a signing path.
pub async fn load_signing_secret(
    secrets: &Arc<dyn SecretsProvider>,
    config: &ChatChannelConfig,
) -> Result<Option<SecretString>, ChatConfigError> {
    config.validate()?;
    let Some(path) = config.signing_secret_path.as_ref() else {
        return Ok(None);
    };
    let value = secrets.get(path).await?;
    Ok(Some(value))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use sx_secrets::InMemoryProvider;

    fn slack_row() -> ChatChannelConfig {
        ChatChannelConfig {
            tenant_id: "t-1".into(),
            provider: ChatAuditProvider::Slack,
            channel: "secops".into(),
            webhook_secret_path: "tenants/t-1/chat/slack/secops/webhook".into(),
            signing_secret_path: Some("tenants/t-1/chat/slack/signing".into()),
            created_at: "2027-01-01T00:00:00Z".into(),
        }
    }

    fn teams_row() -> ChatChannelConfig {
        ChatChannelConfig {
            tenant_id: "t-1".into(),
            provider: ChatAuditProvider::Teams,
            channel: "soc".into(),
            webhook_secret_path: "tenants/t-1/chat/teams/soc/webhook".into(),
            signing_secret_path: None,
            created_at: "2027-01-01T00:00:00Z".into(),
        }
    }

    #[tokio::test]
    async fn upsert_then_get_round_trips() {
        let store = InMemoryChatConfigStore::new();
        store.upsert(slack_row()).await.unwrap();
        let got = store
            .get("t-1", ChatAuditProvider::Slack, "secops")
            .await
            .unwrap();
        assert_eq!(got, Some(slack_row()));
    }

    #[tokio::test]
    async fn validation_rejects_empty_required_fields() {
        let store = InMemoryChatConfigStore::new();
        let mut bad = slack_row();
        bad.channel = String::new();
        assert!(matches!(
            store.upsert(bad).await.unwrap_err(),
            ChatConfigError::Invalid(_)
        ));

        let mut bad = slack_row();
        bad.webhook_secret_path = "   ".into();
        assert!(matches!(
            store.upsert(bad).await.unwrap_err(),
            ChatConfigError::Invalid(_)
        ));

        let mut bad = slack_row();
        bad.signing_secret_path = Some(String::new());
        assert!(matches!(
            store.upsert(bad).await.unwrap_err(),
            ChatConfigError::Invalid(_)
        ));
    }

    #[tokio::test]
    async fn list_for_tenant_is_scoped_and_sorted() {
        let store = InMemoryChatConfigStore::new();
        store.upsert(slack_row()).await.unwrap();
        store.upsert(teams_row()).await.unwrap();
        let mut other = slack_row();
        other.tenant_id = "t-2".into();
        store.upsert(other).await.unwrap();

        let list = store.list_for_tenant("t-1").await.unwrap();
        assert_eq!(list.len(), 2);
        // Sorted by (provider wire, channel) — slack < teams.
        assert_eq!(list[0].provider, ChatAuditProvider::Slack);
        assert_eq!(list[1].provider, ChatAuditProvider::Teams);
    }

    #[tokio::test]
    async fn load_webhook_url_returns_secret() {
        let provider: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        provider
            .put(
                "tenants/t-1/chat/slack/secops/webhook",
                SecretString::from("https://hooks.slack.com/services/AA/BB/CC".to_owned()),
            )
            .await
            .unwrap();
        let url = load_webhook_url(&provider, &slack_row()).await.unwrap();
        assert!(url.expose_secret().starts_with("https://hooks.slack.com/"));
    }

    #[tokio::test]
    async fn load_signing_secret_returns_none_when_path_absent() {
        let provider: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        let got = load_signing_secret(&provider, &teams_row()).await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn load_signing_secret_returns_value_when_path_present() {
        let provider: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        provider
            .put(
                "tenants/t-1/chat/slack/signing",
                SecretString::from("v0_signing_secret".to_owned()),
            )
            .await
            .unwrap();
        let got = load_signing_secret(&provider, &slack_row())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.expose_secret(), "v0_signing_secret");
    }

    #[tokio::test]
    async fn missing_secret_path_surfaces_missing_secret_error() {
        let provider: Arc<dyn SecretsProvider> = Arc::new(InMemoryProvider::new());
        let err = load_webhook_url(&provider, &slack_row()).await.unwrap_err();
        match err {
            ChatConfigError::MissingSecret { path } => {
                assert!(path.contains("webhook"));
            }
            other => panic!("expected MissingSecret, got {other:?}"),
        }
    }
}
