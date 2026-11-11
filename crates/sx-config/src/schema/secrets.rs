//! Secrets / envelope-encryption configuration.
//!
//! The block is optional — when omitted, the monolith composition root
//! treats it as "no cloud KEK configured" and leaves the existing
//! Vault-Transit / in-memory path in place.
//!
//! When `kek.provider = "azure_kv"`, the loader requires a populated
//! [`AzureKekConfig`] sub-block whose fields map verbatim onto
//! `sx_secrets::kek::AzureKeyVaultConfig`. Operators using AWS KMS
//! (P1-005) or GCP Cloud KMS (P1-006) wire those providers up
//! separately; this round only ships the Azure variant.

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use validator::Validate;

/// Top-level secrets / envelope-encryption configuration.
#[derive(Debug, Clone, Deserialize, Validate, Default)]
#[serde(deny_unknown_fields)]
pub struct SecretsConfig {
    /// Key Encryption Key provider selection.
    #[serde(default)]
    #[validate(nested)]
    pub kek: KekConfig,
}

impl SecretsConfig {
    /// Cross-field invariants checked by the loader after `validate`.
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        self.kek.check_invariants()
    }
}

/// Enumerates the supported KEK backends.
///
/// The default is [`KekProviderKind::Disabled`]; in this state the
/// monolith does not attempt to construct a cloud KEK provider and
/// will continue to rely on the existing Vault Transit pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KekProviderKind {
    /// No cloud KEK configured. The composition root falls back to
    /// the existing Vault Transit pipeline.
    #[default]
    Disabled,
    /// Azure Key Vault (P1-007).
    AzureKv,
}

impl KekProviderKind {
    /// Stable, human-readable name surfaced through the admin dashboard.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::AzureKv => "azure_kv",
        }
    }
}

/// Key Encryption Key configuration.
///
/// The `provider` discriminant selects which of the optional sub-blocks
/// the composition root reads at boot. A mismatch between `provider`
/// and the supplied sub-block surfaces as
/// [`crate::ConfigError::MissingValue`] before the monolith starts.
#[derive(Debug, Clone, Deserialize, Validate, Default)]
#[serde(deny_unknown_fields)]
pub struct KekConfig {
    /// Which cloud KEK provider to use.
    #[serde(default)]
    pub provider: KekProviderKind,

    /// Azure Key Vault-specific configuration. Required when
    /// `provider = "azure_kv"`.
    #[serde(default)]
    #[validate(nested)]
    pub azure: Option<AzureKekConfig>,
}

impl KekConfig {
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        match self.provider {
            KekProviderKind::Disabled => Ok(()),
            KekProviderKind::AzureKv => self.azure.as_ref().map_or_else(
                || Err(crate::ConfigError::missing("secrets.kek.azure")),
                AzureKekConfig::check_invariants,
            ),
        }
    }
}

/// Azure Key Vault configuration block.
///
/// `vault_url` is the data-plane URL of the vault, e.g.
/// `https://my-vault.vault.azure.net`. `key_name` is the *name* of the
/// key inside the vault (not the full key identifier).
///
/// AAD service-principal authentication: `tenant_id` is the AAD tenant
/// the principal lives in, `client_id` the app-registration object id,
/// and `client_secret` the client secret value. The secret is wrapped in
/// [`SecretString`] so it is redacted in `Debug` and zeroised on drop.
#[derive(Debug, Clone, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct AzureKekConfig {
    /// Data-plane URL of the vault. MUST start with `https://`.
    pub vault_url: String,

    /// Name of the key inside the vault.
    pub key_name: String,

    /// Optional pinned key version. When unset, Key Vault selects the
    /// latest version on every wrap / unwrap.
    #[serde(default)]
    pub key_version: Option<String>,

    /// AAD tenant id (typically a UUID).
    pub tenant_id: String,

    /// Service-principal application (client) id.
    pub client_id: String,

    /// Service-principal client secret value.
    pub client_secret: SecretString,
}

impl AzureKekConfig {
    pub(crate) fn check_invariants(&self) -> Result<(), crate::ConfigError> {
        if self.vault_url.trim().is_empty() {
            return Err(crate::ConfigError::missing("secrets.kek.azure.vault_url"));
        }
        if !self.vault_url.starts_with("https://") {
            return Err(crate::ConfigError::invalid(
                "secrets.kek.azure.vault_url",
                "vault_url must start with https://",
            ));
        }
        if self.key_name.trim().is_empty() {
            return Err(crate::ConfigError::missing("secrets.kek.azure.key_name"));
        }
        if self.tenant_id.trim().is_empty() {
            return Err(crate::ConfigError::missing("secrets.kek.azure.tenant_id"));
        }
        if self.client_id.trim().is_empty() {
            return Err(crate::ConfigError::missing("secrets.kek.azure.client_id"));
        }
        if self.client_secret.expose_secret().is_empty() {
            return Err(crate::ConfigError::missing(
                "secrets.kek.azure.client_secret",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn valid_azure() -> AzureKekConfig {
        AzureKekConfig {
            vault_url: "https://my-vault.vault.azure.net".to_owned(),
            key_name: "sentinelx-kek".to_owned(),
            key_version: None,
            tenant_id: "00000000-0000-0000-0000-000000000001".to_owned(),
            client_id: "00000000-0000-0000-0000-000000000002".to_owned(),
            client_secret: SecretString::new("super-secret".to_owned().into_boxed_str()),
        }
    }

    #[test]
    fn disabled_provider_passes_invariants_without_any_sub_block() {
        let cfg = SecretsConfig::default();
        assert!(cfg.check_invariants().is_ok());
    }

    #[test]
    fn azure_kv_requires_azure_block() {
        let cfg = SecretsConfig {
            kek: KekConfig {
                provider: KekProviderKind::AzureKv,
                azure: None,
            },
        };
        let err = cfg.check_invariants().unwrap_err();
        assert!(
            matches!(err, crate::ConfigError::MissingValue { ref key } if key == "secrets.kek.azure"),
            "got {err:?}",
        );
    }

    #[test]
    fn azure_kv_with_valid_block_passes() {
        let cfg = SecretsConfig {
            kek: KekConfig {
                provider: KekProviderKind::AzureKv,
                azure: Some(valid_azure()),
            },
        };
        assert!(cfg.check_invariants().is_ok());
    }

    #[test]
    fn azure_kv_rejects_non_https_vault_url() {
        let cfg = SecretsConfig {
            kek: KekConfig {
                provider: KekProviderKind::AzureKv,
                azure: Some(AzureKekConfig {
                    vault_url: "http://my-vault.vault.azure.net".to_owned(),
                    ..valid_azure()
                }),
            },
        };
        let err = cfg.check_invariants().unwrap_err();
        assert!(
            matches!(err, crate::ConfigError::InvalidValue { ref key, .. } if key == "secrets.kek.azure.vault_url"),
            "got {err:?}",
        );
    }

    #[test]
    fn azure_kv_rejects_empty_mandatory_fields() {
        for (mutator, expected_key) in [
            (
                Box::new(|c: &mut AzureKekConfig| c.key_name = String::new())
                    as Box<dyn FnOnce(&mut AzureKekConfig)>,
                "secrets.kek.azure.key_name",
            ),
            (
                Box::new(|c: &mut AzureKekConfig| c.tenant_id = String::new()),
                "secrets.kek.azure.tenant_id",
            ),
            (
                Box::new(|c: &mut AzureKekConfig| c.client_id = String::new()),
                "secrets.kek.azure.client_id",
            ),
            (
                Box::new(|c: &mut AzureKekConfig| {
                    c.client_secret = SecretString::new(String::new().into_boxed_str());
                }),
                "secrets.kek.azure.client_secret",
            ),
        ] {
            let mut azure = valid_azure();
            mutator(&mut azure);
            let cfg = SecretsConfig {
                kek: KekConfig {
                    provider: KekProviderKind::AzureKv,
                    azure: Some(azure),
                },
            };
            let err = cfg.check_invariants().unwrap_err();
            assert!(
                matches!(err, crate::ConfigError::MissingValue { ref key } if key == expected_key),
                "expected MissingValue({expected_key}), got {err:?}",
            );
        }
    }

    #[test]
    fn kek_provider_kind_as_str_round_trips() {
        assert_eq!(KekProviderKind::Disabled.as_str(), "disabled");
        assert_eq!(KekProviderKind::AzureKv.as_str(), "azure_kv");
    }

    #[test]
    fn provider_kind_deserializes_snake_case() {
        let val: KekProviderKind =
            serde_json::from_str("\"azure_kv\"").expect("snake_case `azure_kv` must parse");
        assert_eq!(val, KekProviderKind::AzureKv);
        let val: KekProviderKind =
            serde_json::from_str("\"disabled\"").expect("snake_case `disabled` must parse");
        assert_eq!(val, KekProviderKind::Disabled);
    }
}
