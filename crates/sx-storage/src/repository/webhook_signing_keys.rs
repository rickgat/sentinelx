//! Postgres-backed [`SigningKeyStore`] for MED-003.
//!
//! Persists the per-tenant webhook HMAC key history in the
//! `webhook_signing_keys` table (FORCE-RLS keyed off
//! `app.current_tenant_id`). All reads / writes open a transaction,
//! `SET LOCAL app.current_tenant_id` via [`TenantContext`], and bind the
//! tenant id as a literal predicate in every `WHERE` clause for
//! defence-in-depth.
//!
//! ## Secret storage
//!
//! Secrets are stored **encrypted** in the `secret_enc` column. The
//! ciphertext is opaque to this repository — encryption / decryption
//! happens in [`sx_webhooks::SecretCipher`] (envelope-encryption via
//! `sx-secrets::EnvelopeKeyManager` in production). The repository only
//! sees ciphertext strings on insert and returns ciphertext on read; an
//! adapter wrapper (`EncryptedSigningKeyStore`, see below) handles the
//! `seal` / `open` round-trip so the rest of the system continues to
//! work with `SigningKey` (plaintext-in-`SecretString`).

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use sqlx::{PgPool, Row};
use sx_webhooks::signing::audit::RotationAuditSink;
use sx_webhooks::signing::secret_cipher::{CipherError, SecretCipher};
use sx_webhooks::{
    Kid, SigningKey, SigningKeyStore, SigningStoreError as StoreError, WebhookKeyRotator,
};
use uuid::Uuid;

use crate::tenant_context::TenantContext;

/// Postgres repository over `webhook_signing_keys`.
///
/// Stores ciphertext in `secret_enc`. Callers MUST go through the
/// [`EncryptedSigningKeyStore`] wrapper (which couples this repo with a
/// [`SecretCipher`]) — instances of this raw repo never decrypt on the
/// read side and never encrypt on the write side.
#[derive(Debug, Clone)]
pub struct PgWebhookSigningKeyRepository {
    pool: PgPool,
    stmt_timeout_ms: u64,
}

impl PgWebhookSigningKeyRepository {
    /// Build a repository handle. The `statement_timeout_ms` is applied
    /// to every transaction via `SET LOCAL`.
    #[must_use]
    pub const fn new(pool: PgPool, stmt_timeout_ms: u64) -> Self {
        Self {
            pool,
            stmt_timeout_ms,
        }
    }

    /// Borrow the underlying pool.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    fn parse_tenant(s: &str) -> Result<Uuid, StoreError> {
        Uuid::parse_str(s.trim()).map_err(|e| StoreError::backend(format!("tenant_id: {e}")))
    }

    /// Insert one row. `secret_enc` is opaque ciphertext (no decoding
    /// here).
    pub async fn insert_raw(
        &self,
        tenant_id: &str,
        kid: &str,
        secret_enc: &str,
        created_at: DateTime<Utc>,
        activated_at: DateTime<Utc>,
        retired_at: Option<DateTime<Utc>>,
    ) -> Result<(), StoreError> {
        let tenant_uuid = Self::parse_tenant(tenant_id)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StoreError::backend(e.to_string()))?;
        let tenant = crate::domain::value_object::TenantId::from_uuid(tenant_uuid);
        TenantContext::apply(&mut tx, tenant, self.stmt_timeout_ms)
            .await
            .map_err(|e| StoreError::backend(e.to_string()))?;

        sqlx::query(
            "INSERT INTO webhook_signing_keys \
                 (tenant_id, kid, secret_enc, created_at, activated_at, retired_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(tenant_uuid)
        .bind(kid)
        .bind(secret_enc)
        .bind(created_at)
        .bind(activated_at)
        .bind(retired_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| StoreError::backend(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| StoreError::backend(e.to_string()))?;
        Ok(())
    }

    /// Retire one row.
    pub async fn retire_raw(
        &self,
        tenant_id: &str,
        kid: &str,
        retired_at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let tenant_uuid = Self::parse_tenant(tenant_id)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StoreError::backend(e.to_string()))?;
        let tenant = crate::domain::value_object::TenantId::from_uuid(tenant_uuid);
        TenantContext::apply(&mut tx, tenant, self.stmt_timeout_ms)
            .await
            .map_err(|e| StoreError::backend(e.to_string()))?;

        let result = sqlx::query(
            "UPDATE webhook_signing_keys \
             SET retired_at = GREATEST(COALESCE(retired_at, $3), $3) \
             WHERE tenant_id = $1 AND kid = $2",
        )
        .bind(tenant_uuid)
        .bind(kid)
        .bind(retired_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| StoreError::backend(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(StoreError::NotFound);
        }

        tx.commit()
            .await
            .map_err(|e| StoreError::backend(e.to_string()))?;
        Ok(())
    }

    /// Return rows currently active at `now` for `tenant_id`. Returns
    /// `(kid, ciphertext, created_at, activated_at, retired_at)`.
    #[allow(clippy::type_complexity)]
    pub async fn active_raw(
        &self,
        tenant_id: &str,
        now: DateTime<Utc>,
    ) -> Result<
        Vec<(
            String,
            String,
            DateTime<Utc>,
            DateTime<Utc>,
            Option<DateTime<Utc>>,
        )>,
        StoreError,
    > {
        let tenant_uuid = Self::parse_tenant(tenant_id)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StoreError::backend(e.to_string()))?;
        let tenant = crate::domain::value_object::TenantId::from_uuid(tenant_uuid);
        TenantContext::apply(&mut tx, tenant, self.stmt_timeout_ms)
            .await
            .map_err(|e| StoreError::backend(e.to_string()))?;

        let rows = sqlx::query(
            "SELECT kid, secret_enc, created_at, activated_at, retired_at \
             FROM webhook_signing_keys \
             WHERE tenant_id = $1 \
               AND activated_at <= $2 \
               AND (retired_at IS NULL OR retired_at > $2) \
             ORDER BY activated_at DESC",
        )
        .bind(tenant_uuid)
        .bind(now)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| StoreError::backend(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| StoreError::backend(e.to_string()))?;

        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push((
                r.try_get("kid")
                    .map_err(|e| StoreError::backend(e.to_string()))?,
                r.try_get("secret_enc")
                    .map_err(|e| StoreError::backend(e.to_string()))?,
                r.try_get("created_at")
                    .map_err(|e| StoreError::backend(e.to_string()))?,
                r.try_get("activated_at")
                    .map_err(|e| StoreError::backend(e.to_string()))?,
                r.try_get("retired_at")
                    .map_err(|e| StoreError::backend(e.to_string()))?,
            ));
        }
        Ok(out)
    }

    /// Return every row for `tenant_id` regardless of state.
    #[allow(clippy::type_complexity)]
    pub async fn list_raw(
        &self,
        tenant_id: &str,
    ) -> Result<
        Vec<(
            String,
            String,
            DateTime<Utc>,
            DateTime<Utc>,
            Option<DateTime<Utc>>,
        )>,
        StoreError,
    > {
        let tenant_uuid = Self::parse_tenant(tenant_id)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StoreError::backend(e.to_string()))?;
        let tenant = crate::domain::value_object::TenantId::from_uuid(tenant_uuid);
        TenantContext::apply(&mut tx, tenant, self.stmt_timeout_ms)
            .await
            .map_err(|e| StoreError::backend(e.to_string()))?;

        let rows = sqlx::query(
            "SELECT kid, secret_enc, created_at, activated_at, retired_at \
             FROM webhook_signing_keys \
             WHERE tenant_id = $1 \
             ORDER BY activated_at ASC",
        )
        .bind(tenant_uuid)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| StoreError::backend(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| StoreError::backend(e.to_string()))?;

        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            out.push((
                r.try_get("kid")
                    .map_err(|e| StoreError::backend(e.to_string()))?,
                r.try_get("secret_enc")
                    .map_err(|e| StoreError::backend(e.to_string()))?,
                r.try_get("created_at")
                    .map_err(|e| StoreError::backend(e.to_string()))?,
                r.try_get("activated_at")
                    .map_err(|e| StoreError::backend(e.to_string()))?,
                r.try_get("retired_at")
                    .map_err(|e| StoreError::backend(e.to_string()))?,
            ));
        }
        Ok(out)
    }
}

/// Encrypted [`SigningKeyStore`] adapter wrapping a
/// [`PgWebhookSigningKeyRepository`] + a [`SecretCipher`].
///
/// Implements the workspace-wide [`SigningKeyStore`] trait the signer /
/// verifier / rotator depend on. Round-trips ciphertext to the
/// repository and plaintext (in `SecretString`) to the higher layers.
#[derive(Clone)]
pub struct EncryptedSigningKeyStore {
    repo: PgWebhookSigningKeyRepository,
    cipher: Arc<dyn SecretCipher>,
}

impl std::fmt::Debug for EncryptedSigningKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedSigningKeyStore")
            .field("repo", &self.repo)
            .finish_non_exhaustive()
    }
}

impl EncryptedSigningKeyStore {
    /// Build the encrypted store from its two collaborators.
    #[must_use]
    pub const fn new(repo: PgWebhookSigningKeyRepository, cipher: Arc<dyn SecretCipher>) -> Self {
        Self { repo, cipher }
    }

    async fn decrypt_secret(
        &self,
        tenant_id: &str,
        ciphertext: &str,
    ) -> Result<SecretString, StoreError> {
        self.cipher
            .open(tenant_id, ciphertext)
            .await
            .map_err(|e| map_cipher_err(&e))
    }
}

#[async_trait]
impl SigningKeyStore for EncryptedSigningKeyStore {
    async fn insert(&self, key: &SigningKey) -> Result<(), StoreError> {
        let ciphertext = self
            .cipher
            .seal(&key.tenant_id, &key.secret)
            .await
            .map_err(|e| map_cipher_err(&e))?;
        self.repo
            .insert_raw(
                &key.tenant_id,
                key.kid.as_str(),
                &ciphertext,
                key.created_at,
                key.activated_at,
                key.retired_at,
            )
            .await
    }

    async fn retire(
        &self,
        tenant_id: &str,
        kid: &Kid,
        retired_at: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        self.repo
            .retire_raw(tenant_id, kid.as_str(), retired_at)
            .await
    }

    async fn active(
        &self,
        tenant_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<SigningKey>, StoreError> {
        let rows = self.repo.active_raw(tenant_id, now).await?;
        let mut out = Vec::with_capacity(rows.len());
        for (kid, ciphertext, created_at, activated_at, retired_at) in rows {
            let secret = self.decrypt_secret(tenant_id, &ciphertext).await?;
            out.push(SigningKey {
                tenant_id: tenant_id.to_owned(),
                kid: Kid::new(kid),
                secret,
                created_at,
                activated_at,
                retired_at,
            });
        }
        Ok(out)
    }

    async fn list(&self, tenant_id: &str) -> Result<Vec<SigningKey>, StoreError> {
        let rows = self.repo.list_raw(tenant_id).await?;
        let mut out = Vec::with_capacity(rows.len());
        for (kid, ciphertext, created_at, activated_at, retired_at) in rows {
            let secret = self.decrypt_secret(tenant_id, &ciphertext).await?;
            out.push(SigningKey {
                tenant_id: tenant_id.to_owned(),
                kid: Kid::new(kid),
                secret,
                created_at,
                activated_at,
                retired_at,
            });
        }
        Ok(out)
    }
}

/// Build a fully wired [`WebhookKeyRotator`] backed by Postgres + the
/// supplied cipher + audit sink.
#[must_use]
pub fn build_pg_rotator(
    pool: PgPool,
    stmt_timeout_ms: u64,
    cipher: Arc<dyn SecretCipher>,
    audit: Arc<dyn RotationAuditSink>,
) -> WebhookKeyRotator {
    let repo = PgWebhookSigningKeyRepository::new(pool, stmt_timeout_ms);
    let store: Arc<dyn SigningKeyStore> =
        Arc::new(EncryptedSigningKeyStore::new(repo, cipher.clone()));
    WebhookKeyRotator::new(store, cipher, audit)
}

/// Convert a [`CipherError`] into a [`StoreError`].
///
/// Takes the cipher error by reference because the source value is
/// fully consumed by the surrounding `format!`. Callers wrap this in a
/// `|e| map_cipher_err(&e)` closure where `map_err` hands them ownership.
fn map_cipher_err(e: &CipherError) -> StoreError {
    StoreError::backend(format!("cipher: {e}"))
}

/// Allow `ExposeSecret` to be used in the cipher's debug/diagnostic
/// surfaces without leaking via these helpers — the trait is imported
/// solely so the dependency stays explicit in this module.
#[doc(hidden)]
#[allow(dead_code)]
fn _expose_secret_marker(s: &SecretString) -> &str {
    s.expose_secret()
}
