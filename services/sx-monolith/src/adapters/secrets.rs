//! Composition-root wiring for envelope-encryption KEK providers.
//!
//! The monolith reads [`sx_config::SecretsConfig`] and instantiates the
//! provider selected by `secrets.kek.provider`. The construction is
//! deliberately tolerant: when no provider is configured the function
//! returns `Ok(None)` so the rest of the composition root can continue
//! to bind the existing Vault Transit pipeline.
//!
//! Wiring `KekKind::AzureKv` (P1-007) is the only branch in this build;
//! AWS KMS (P1-005) and GCP Cloud KMS (P1-006) wire through their own
//! follow-up branches. The enum exists ahead of those so the dashboard
//! and observability surface have a stable shape to render against.

use std::sync::Arc;

use secrecy::ExposeSecret;
use sx_config::{AzureKekConfig, KekProviderKind, SecretsConfig};
use sx_secrets::kek::{AzureKeyVaultConfig, AzureKeyVaultKekProvider, KekError, KekProvider};

/// Stable discriminant for the active KEK backend.
///
/// `as_str` returns the same identifier used in the config schema
/// (`disabled`, `azure_kv`) so it can be rendered in the admin
/// dashboard without translation.
///
/// AWS KMS (P1-005) and GCP Cloud KMS (P1-006) variants live behind
/// their own feature branches and are added here in the same commit
/// that wires their adapters; this round only ships the `AzureKv`
/// branch end-to-end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KekKind {
    /// No cloud KEK active; falls back to the existing Vault Transit
    /// pipeline at the call site.
    Disabled,
    /// Azure Key Vault (P1-007).
    AzureKv,
}

impl KekKind {
    /// Stable identifier matching the config schema.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::AzureKv => "azure_kv",
        }
    }
}

impl From<KekProviderKind> for KekKind {
    fn from(kind: KekProviderKind) -> Self {
        match kind {
            KekProviderKind::Disabled => Self::Disabled,
            KekProviderKind::AzureKv => Self::AzureKv,
        }
    }
}

/// Outcome of [`build`]: the constructed provider (when any) together
/// with the discriminant used to render the dashboard label.
pub struct KekBundle {
    /// Active backend.
    pub kind: KekKind,
    /// Type-erased provider handle. `None` when `kind == Disabled` so
    /// the caller falls back to the existing Vault Transit pipeline.
    pub provider: Option<Arc<dyn KekProvider>>,
}

impl KekBundle {
    /// Render the provider name in the same shape the dashboard
    /// expects (snake_case, see [`KekKind::as_str`]).
    #[must_use]
    pub const fn provider_name(&self) -> &'static str {
        self.kind.as_str()
    }
}

impl std::fmt::Debug for KekBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `Arc<dyn KekProvider>` is intentionally opaque (the trait does
        // not require `Debug`); render the trait object as a stable
        // placeholder so tests can still call `expect_err` without
        // dragging a `Debug` bound onto `KekProvider`.
        f.debug_struct("KekBundle")
            .field("kind", &self.kind)
            .field("provider", &self.provider.as_ref().map(|_| "<attached>"))
            .finish()
    }
}

/// Wiring errors surfaced by [`build`].
#[derive(Debug, thiserror::Error)]
pub enum KekBuildError {
    /// The selected provider expects a sub-block that was not supplied.
    #[error("kek provider `{provider}` requires sub-block `{block}` to be configured")]
    MissingSubBlock {
        /// The provider name (e.g. `azure_kv`).
        provider: &'static str,
        /// The dotted path of the missing block (e.g. `secrets.kek.azure`).
        block: &'static str,
    },
    /// Underlying `sx-secrets` rejected the supplied configuration.
    #[error("kek provider construction failed: {0}")]
    Provider(#[from] KekError),
}

/// Build the active KEK bundle from the configured
/// [`sx_config::SecretsConfig`].
///
/// # Errors
///
/// Returns [`KekBuildError::MissingSubBlock`] when the configured
/// provider names a sub-block (e.g. `azure_kv` → `secrets.kek.azure`)
/// but the operator did not populate it, and [`KekBuildError::Provider`]
/// when `sx-secrets` rejects the resolved configuration (malformed
/// vault URL, empty client secret, …).
pub fn build(cfg: &SecretsConfig) -> Result<KekBundle, KekBuildError> {
    match cfg.kek.provider {
        KekProviderKind::Disabled => Ok(KekBundle {
            kind: KekKind::Disabled,
            provider: None,
        }),
        KekProviderKind::AzureKv => {
            let azure_cfg = cfg
                .kek
                .azure
                .as_ref()
                .ok_or(KekBuildError::MissingSubBlock {
                    provider: "azure_kv",
                    block: "secrets.kek.azure",
                })?;
            let provider = build_azure(azure_cfg)?;
            Ok(KekBundle {
                kind: KekKind::AzureKv,
                provider: Some(Arc::new(provider)),
            })
        }
    }
}

/// Translate [`AzureKekConfig`] into [`AzureKeyVaultConfig`] and
/// construct the provider. Kept separate so future wiring (AWS / GCP
/// branches) lands as sibling helpers without touching the dispatcher.
fn build_azure(cfg: &AzureKekConfig) -> Result<AzureKeyVaultKekProvider, KekError> {
    let secret = secrecy::SecretString::new(
        cfg.client_secret
            .expose_secret()
            .to_owned()
            .into_boxed_str(),
    );
    let mut provider_cfg = AzureKeyVaultConfig::new(
        cfg.vault_url.clone(),
        cfg.key_name.clone(),
        cfg.tenant_id.clone(),
        cfg.client_id.clone(),
        secret,
    );
    if let Some(version) = cfg.key_version.as_deref() {
        provider_cfg = provider_cfg.with_key_version(version);
    }
    AzureKeyVaultKekProvider::new(provider_cfg)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use secrecy::SecretString;
    use sx_config::{KekConfig, SecretsConfig};

    fn azure_cfg() -> AzureKekConfig {
        AzureKekConfig {
            vault_url: "https://my-vault.vault.azure.net".to_owned(),
            key_name: "k".to_owned(),
            key_version: None,
            tenant_id: "00000000-0000-0000-0000-000000000001".to_owned(),
            client_id: "00000000-0000-0000-0000-000000000002".to_owned(),
            client_secret: SecretString::new("secret".to_owned().into_boxed_str()),
        }
    }

    #[test]
    fn disabled_yields_no_provider() {
        let bundle = build(&SecretsConfig::default()).expect("disabled must succeed");
        assert_eq!(bundle.kind, KekKind::Disabled);
        assert!(bundle.provider.is_none());
        assert_eq!(bundle.provider_name(), "disabled");
    }

    #[test]
    fn azure_kv_builds_provider_from_config() {
        let cfg = SecretsConfig {
            kek: KekConfig {
                provider: KekProviderKind::AzureKv,
                azure: Some(azure_cfg()),
            },
        };
        let bundle = build(&cfg).expect("azure config must build");
        assert_eq!(bundle.kind, KekKind::AzureKv);
        assert_eq!(bundle.provider_name(), "azure_kv");
        let provider = bundle.provider.expect("provider must be present");
        assert_eq!(provider.provider_id(), "azure-kv");
    }

    #[test]
    fn azure_kv_without_sub_block_errors() {
        let cfg = SecretsConfig {
            kek: KekConfig {
                provider: KekProviderKind::AzureKv,
                azure: None,
            },
        };
        let err = build(&cfg).expect_err("missing sub-block must error");
        assert!(
            matches!(err, KekBuildError::MissingSubBlock { provider, block }
            if provider == "azure_kv" && block == "secrets.kek.azure")
        );
    }

    #[test]
    fn azure_kv_propagates_provider_rejection() {
        let mut bad = azure_cfg();
        // Force the sx-secrets layer to reject (non-https vault url is
        // accepted by the config-schema invariant check only when the
        // outer SecretsConfig::check_invariants runs; here we bypass
        // that and confirm the adapter still surfaces the inner error).
        bad.vault_url = "not-a-url".to_owned();
        let cfg = SecretsConfig {
            kek: KekConfig {
                provider: KekProviderKind::AzureKv,
                azure: Some(bad),
            },
        };
        let err = build(&cfg).expect_err("malformed vault url must error");
        assert!(matches!(err, KekBuildError::Provider(_)));
    }

    #[test]
    fn kek_kind_as_str_round_trips() {
        assert_eq!(KekKind::Disabled.as_str(), "disabled");
        assert_eq!(KekKind::AzureKv.as_str(), "azure_kv");
    }

    #[test]
    fn kek_kind_from_config_provider_kind_round_trips() {
        assert_eq!(KekKind::from(KekProviderKind::Disabled), KekKind::Disabled);
        assert_eq!(KekKind::from(KekProviderKind::AzureKv), KekKind::AzureKv);
    }
}
