//! Per-tenant signing-key rotator (MED-003).
//!
//! Two entry points:
//!
//! - [`WebhookKeyRotator::force_rotate`] — admin-driven path used by
//!   `POST /v1/admin/webhooks/keys/rotate`. Mints a new key, schedules
//!   the previous active key for retirement at
//!   `now + grace_window`, and emits two audit events (`minted` + a
//!   future `retired` once the grace window expires — emitted on the
//!   actual retire pass by [`WebhookKeyRotator::sweep_retired`]).
//! - [`WebhookKeyRotator::tick`] — background-loop pass invoked by the
//!   monolith's rotation job. Iterates over a tenant list, checks
//!   whether each tenant's latest active key has aged past
//!   `cadence`, mints a replacement, schedules the old one for
//!   retirement, and sweeps any keys whose `retired_at` has now passed.
//!
//! ## Policy resolution
//!
//! Cadence + grace come from the [`RotationPolicy`] passed in at
//! construction time. The composition root builds one
//! `RotationPolicy::for_tenant` per tick, falling back to platform
//! defaults when no per-tenant override row exists in `sx-config`.
//!
//! ## Audit
//!
//! Every transition fires a [`crate::signing::audit::RotationAuditEvent`].
//! The sink is whatever the composition root wires in; the in-memory
//! sink is used in tests.

use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use thiserror::Error;
use tracing::{debug, info, warn};

use super::audit::{RotationAuditEvent, RotationAuditKind, RotationAuditSink};
use super::key::{Kid, SigningKey};
use super::secret_cipher::{CipherError, SecretCipher};
use super::store::{SigningKeyStore, StoreError};

/// Errors surfaced by the rotator.
#[derive(Debug, Error)]
pub enum RotationError {
    /// Underlying signing-key store rejected the operation.
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    /// Underlying envelope cipher (KMS / placeholder) failed.
    #[error("cipher error: {0}")]
    Cipher(#[from] CipherError),
}

/// Per-tenant rotation policy.
///
/// `cadence` is how often a tenant rotates; `grace_window` is how long
/// the previous key remains valid after a rotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationPolicy {
    /// Rotate after this many days.
    pub cadence: Duration,
    /// Old key remains valid this long after a rotation.
    pub grace_window: Duration,
}

impl RotationPolicy {
    /// Build a policy from `(cadence_days, grace_days)` — matches the
    /// shape `sx_config::WebhookSigningRotationConfig::for_tenant`
    /// returns.
    #[must_use]
    pub fn from_days(cadence_days: u32, grace_days: u32) -> Self {
        Self {
            cadence: Duration::days(i64::from(cadence_days)),
            grace_window: Duration::days(i64::from(grace_days)),
        }
    }

    /// Convenience — return the MED-003 default policy: 90 day cadence
    /// + 7 day grace.
    #[must_use]
    pub fn default_med003() -> Self {
        Self::from_days(90, 7)
    }
}

/// Result of one rotation pass for a single tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationOutcome {
    /// Tenant the rotation applies to.
    pub tenant_id: String,
    /// Kid that was minted.
    pub new_kid: Kid,
    /// Previous active kid, if any. `None` on the very first rotation
    /// (tenant had no keys at all).
    pub previous_kid: Option<Kid>,
    /// Wall-clock time at which the previous key will be retired.
    /// `None` when there was no previous key.
    pub previous_retire_at: Option<DateTime<Utc>>,
}

/// The rotator.
///
/// Clone is cheap — three `Arc` clones.
#[derive(Clone)]
pub struct WebhookKeyRotator {
    store: Arc<dyn SigningKeyStore>,
    cipher: Arc<dyn SecretCipher>,
    audit: Arc<dyn RotationAuditSink>,
}

impl std::fmt::Debug for WebhookKeyRotator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookKeyRotator")
            .field("store", &self.store)
            .field("audit", &self.audit)
            .finish_non_exhaustive()
    }
}

impl WebhookKeyRotator {
    /// Construct from already-built collaborators. The composition
    /// root passes `Arc<dyn ...>` so the rotator never sees concrete
    /// types.
    #[must_use]
    pub fn new(
        store: Arc<dyn SigningKeyStore>,
        cipher: Arc<dyn SecretCipher>,
        audit: Arc<dyn RotationAuditSink>,
    ) -> Self {
        Self {
            store,
            cipher,
            audit,
        }
    }

    /// Borrow the store handle. Used by the composition root + admin
    /// adapters that want to read state without going through the
    /// rotator.
    #[must_use]
    pub fn store(&self) -> &Arc<dyn SigningKeyStore> {
        &self.store
    }

    /// Force-rotate `tenant_id` *now*. Mints a fresh key and schedules
    /// the previous key (if any) for retirement at `now +
    /// policy.grace_window`. `actor` is the operator's subject claim,
    /// emitted in the audit event.
    ///
    /// # Errors
    ///
    /// Returns [`RotationError::Store`] on a backend failure.
    /// Returns [`RotationError::Cipher`] on an envelope-encryption
    /// failure.
    pub async fn force_rotate(
        &self,
        tenant_id: &str,
        policy: RotationPolicy,
        actor: Option<String>,
    ) -> Result<RotationOutcome, RotationError> {
        self.rotate_internal(tenant_id, policy, actor, "admin_force")
            .await
    }

    /// Background-loop entry point: rotate a single tenant if its
    /// latest active key has aged past `policy.cadence`. Also sweeps
    /// any retired keys whose `retired_at` has passed (emitting the
    /// matching audit event).
    ///
    /// Returns `Ok(None)` when the tenant did not need a rotation;
    /// `Ok(Some(outcome))` when it did.
    ///
    /// # Errors
    ///
    /// As for [`Self::force_rotate`].
    pub async fn tick(
        &self,
        tenant_id: &str,
        policy: RotationPolicy,
    ) -> Result<Option<RotationOutcome>, RotationError> {
        self.sweep_retired(tenant_id).await?;
        let now = Utc::now();
        let active = self.store.active(tenant_id, now).await?;
        match active.first() {
            // No active key at all — mint the first one.
            None => self
                .rotate_internal(tenant_id, policy, None, "first_mint")
                .await
                .map(Some),
            Some(latest) => {
                let age = now - latest.activated_at;
                if age >= policy.cadence {
                    debug!(
                        target: "sx_webhooks::signing::rotator",
                        tenant_id, age_secs = age.num_seconds(),
                        cadence_secs = policy.cadence.num_seconds(),
                        "tenant key past cadence; rotating"
                    );
                    self.rotate_internal(tenant_id, policy, None, "background_cadence")
                        .await
                        .map(Some)
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Sweep any keys for `tenant_id` whose `retired_at` is in the
    /// past — emit the audit event so the chain reflects the actual
    /// cutover moment. The row itself stays in the store (an aged-out
    /// key is permanent history); the verifier's `is_active_at` check
    /// already filters it from the accept set.
    ///
    /// # Errors
    ///
    /// Returns [`RotationError::Store`] on a backend failure.
    pub async fn sweep_retired(&self, tenant_id: &str) -> Result<(), RotationError> {
        let now = Utc::now();
        let all = self.store.list(tenant_id).await?;
        for k in all {
            if let Some(retired_at) = k.retired_at {
                if retired_at <= now {
                    // Already retired — emit audit only if we have not
                    // already (the audit sink is the source of truth
                    // for "did we emit this?"; we don't double-track
                    // here, the in-memory sink is idempotent enough
                    // for tests and the production sink dedupes by
                    // (tenant, kid, kind) at the sx-audit chain level).
                    self.audit
                        .record(RotationAuditEvent {
                            tenant_id: tenant_id.to_owned(),
                            kind: RotationAuditKind::Retired,
                            kid: k.kid,
                            companion_kid: None,
                            actor: None,
                            at: retired_at,
                            reason: "grace_window_expired",
                        })
                        .await;
                }
            }
        }
        Ok(())
    }

    async fn rotate_internal(
        &self,
        tenant_id: &str,
        policy: RotationPolicy,
        actor: Option<String>,
        reason: &'static str,
    ) -> Result<RotationOutcome, RotationError> {
        let stamp = Utc::now();
        let active = self.store.active(tenant_id, stamp).await?;
        let previous = active.into_iter().next();

        let fresh_key = self.mint_and_persist(tenant_id).await?;
        let new_kid = fresh_key.kid.clone();

        let (previous_kid, previous_retire_at) = self
            .schedule_retirement(tenant_id, previous.as_ref(), stamp, policy)
            .await?;

        self.audit
            .record(RotationAuditEvent {
                tenant_id: tenant_id.to_owned(),
                kind: RotationAuditKind::Minted,
                kid: new_kid.clone(),
                companion_kid: previous_kid.clone(),
                actor,
                at: stamp,
                reason,
            })
            .await;

        info!(
            target: "sx_webhooks::signing::rotator",
            tenant_id,
            new_kid = %new_kid,
            previous_kid = previous_kid.as_ref().map_or("-", Kid::as_str),
            reason,
            "webhook signing key rotated"
        );
        Ok(RotationOutcome {
            tenant_id: tenant_id.to_owned(),
            new_kid,
            previous_kid,
            previous_retire_at,
        })
    }

    async fn mint_and_persist(&self, tenant_id: &str) -> Result<SigningKey, RotationError> {
        let fresh_key = SigningKey::mint(tenant_id);
        let ciphertext = self.cipher.seal(tenant_id, &fresh_key.secret).await?;
        debug!(
            target: "sx_webhooks::signing::rotator",
            tenant_id, kid = %fresh_key.kid,
            ciphertext_len = ciphertext.len(),
            "new signing key minted; persisting"
        );
        self.store.insert(&fresh_key).await?;
        Ok(fresh_key)
    }

    async fn schedule_retirement(
        &self,
        tenant_id: &str,
        previous: Option<&SigningKey>,
        stamp: DateTime<Utc>,
        policy: RotationPolicy,
    ) -> Result<(Option<Kid>, Option<DateTime<Utc>>), RotationError> {
        let previous_kid = previous.map(|p| p.kid.clone());
        let previous_retire_at = previous.map(|_| stamp + policy.grace_window);
        if let (Some(prev), Some(retire_at)) = (previous, previous_retire_at) {
            if let Err(e) = self.store.retire(tenant_id, &prev.kid, retire_at).await {
                warn!(
                    target: "sx_webhooks::signing::rotator",
                    tenant_id, prev_kid = %prev.kid,
                    error = %e,
                    "failed to schedule previous key retirement"
                );
                return Err(RotationError::from(e));
            }
        }
        Ok((previous_kid, previous_retire_at))
    }
}

/// Convenience — the default background-tick interval. The composition
/// root may pass a different value pulled from `sx-config`.
#[must_use]
pub const fn default_tick_interval() -> StdDuration {
    StdDuration::from_secs(3_600)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::similar_names
)]
mod tests {
    use super::*;
    use crate::signing::audit::InMemoryRotationAuditSink;
    use crate::signing::secret_cipher::PlaintextCipher;
    use crate::signing::signer::WebhookSigner;
    use crate::signing::store::InMemorySigningKeyStore;
    use crate::signing::verifier::WebhookVerifier;

    fn build() -> (
        WebhookKeyRotator,
        Arc<InMemorySigningKeyStore>,
        Arc<InMemoryRotationAuditSink>,
    ) {
        let store: Arc<InMemorySigningKeyStore> = Arc::new(InMemorySigningKeyStore::new());
        let store_trait: Arc<dyn SigningKeyStore> = store.clone();
        let cipher: Arc<dyn SecretCipher> = Arc::new(PlaintextCipher);
        let audit_inner: Arc<InMemoryRotationAuditSink> =
            Arc::new(InMemoryRotationAuditSink::new());
        let audit_trait: Arc<dyn RotationAuditSink> = audit_inner.clone();
        let rotator = WebhookKeyRotator::new(store_trait, cipher, audit_trait);
        (rotator, store, audit_inner)
    }

    #[tokio::test]
    async fn force_rotate_first_call_mints_initial_key() {
        let (rot, store, audit) = build();
        let outcome = rot
            .force_rotate("t", RotationPolicy::default_med003(), Some("admin".into()))
            .await
            .unwrap();
        assert!(outcome.previous_kid.is_none());
        assert!(outcome.previous_retire_at.is_none());
        let active = store.active("t", Utc::now()).await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].kid, outcome.new_kid);
        let evs = audit.events();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, RotationAuditKind::Minted);
        assert_eq!(evs[0].reason, "admin_force");
        assert_eq!(evs[0].actor.as_deref(), Some("admin"));
    }

    #[tokio::test]
    async fn force_rotate_with_existing_key_creates_overlap() {
        let (rot, store, audit) = build();
        let first = rot
            .force_rotate("t", RotationPolicy::default_med003(), None)
            .await
            .unwrap();
        let second = rot
            .force_rotate("t", RotationPolicy::default_med003(), Some("op".into()))
            .await
            .unwrap();
        // Both kids active during the grace window.
        let active = store.active("t", Utc::now()).await.unwrap();
        assert_eq!(active.len(), 2, "both kids must overlap in grace window");
        assert_eq!(active[0].kid, second.new_kid);
        // The previous-kid retirement was scheduled in the future.
        assert_eq!(second.previous_kid.as_ref(), Some(&first.new_kid));
        assert!(second.previous_retire_at.unwrap() > Utc::now());
        // Audit recorded both mints.
        let mints: Vec<_> = audit
            .events()
            .into_iter()
            .filter(|e| matches!(e.kind, RotationAuditKind::Minted))
            .collect();
        assert_eq!(mints.len(), 2);
        assert_eq!(mints[1].companion_kid.as_ref(), Some(&first.new_kid));
    }

    #[tokio::test]
    async fn grace_window_verifier_accepts_both() {
        use hmac::Mac;
        use secrecy::ExposeSecret;
        let (rot, store, _audit) = build();
        let _first = rot
            .force_rotate("t", RotationPolicy::from_days(90, 7), None)
            .await
            .unwrap();
        let _second = rot
            .force_rotate("t", RotationPolicy::from_days(90, 7), None)
            .await
            .unwrap();
        let signer = WebhookSigner::new(store.clone());
        let verifier = WebhookVerifier::new(store.clone());
        // Signer picks the newest active.
        let signed = signer.sign("t", b"payload").await.unwrap();
        verifier
            .verify("t", &signed.kid, &signed.signature_hex, b"payload")
            .await
            .unwrap();
        // Old kid still accepted: sign by hand using the old key's
        // secret pulled out of the active list (index 1 == older).
        let active = store.active("t", Utc::now()).await.unwrap();
        let old = &active[1];
        let mut mac =
            hmac::Hmac::<sha2::Sha256>::new_from_slice(old.secret.expose_secret().as_bytes())
                .unwrap();
        mac.update(b"payload");
        let old_sig = hex::encode(mac.finalize().into_bytes());
        verifier
            .verify("t", &old.kid, &old_sig, b"payload")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn post_grace_old_kid_rejected() {
        let (rot, store, _audit) = build();
        let _first = rot
            .force_rotate("t", RotationPolicy::from_days(90, 0), None)
            .await
            .unwrap();
        // Grace = 0 → old kid retires at *now*. Sleep a beat so we're
        // strictly past the retire stamp.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let _second = rot
            .force_rotate("t", RotationPolicy::from_days(90, 0), None)
            .await
            .unwrap();
        // The old kid is now retired_at <= now → verifier rejects.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let active = store.active("t", Utc::now()).await.unwrap();
        assert_eq!(active.len(), 1, "old kid must be filtered post-grace");
    }

    #[tokio::test]
    async fn tick_no_op_when_recent_key_exists() {
        let (rot, store, _audit) = build();
        rot.force_rotate("t", RotationPolicy::default_med003(), None)
            .await
            .unwrap();
        let outcome = rot
            .tick("t", RotationPolicy::default_med003())
            .await
            .unwrap();
        assert!(outcome.is_none(), "must not rotate within cadence");
        assert_eq!(store.active("t", Utc::now()).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn tick_mints_initial_key_when_tenant_empty() {
        let (rot, store, audit) = build();
        let outcome = rot
            .tick("t", RotationPolicy::default_med003())
            .await
            .unwrap();
        assert!(outcome.is_some());
        assert_eq!(store.active("t", Utc::now()).await.unwrap().len(), 1);
        let evs = audit.events();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].reason, "first_mint");
    }

    #[tokio::test]
    async fn tick_rotates_when_key_past_cadence() {
        let (rot, store, audit) = build();
        // Seed an old key (activated 91 days ago).
        let mut key = SigningKey::mint("t");
        key.activated_at = Utc::now() - Duration::days(91);
        key.created_at = key.activated_at;
        store.insert(&key).await.unwrap();
        let outcome = rot
            .tick("t", RotationPolicy::default_med003())
            .await
            .unwrap()
            .expect("must rotate");
        assert_eq!(outcome.previous_kid.as_ref(), Some(&key.kid));
        let active = store.active("t", Utc::now()).await.unwrap();
        // Both rows still active during grace window.
        assert_eq!(active.len(), 2);
        // Audit recorded a mint with reason=background_cadence.
        let mint = audit
            .events()
            .into_iter()
            .find(|e| matches!(e.kind, RotationAuditKind::Minted))
            .unwrap();
        assert_eq!(mint.reason, "background_cadence");
    }

    #[tokio::test]
    async fn sweep_retired_emits_audit_for_aged_out_key() {
        let (rot, store, audit) = build();
        let now = Utc::now();
        // Seed a retired key.
        let mut key = SigningKey::mint("t");
        key.activated_at = now - Duration::days(30);
        key.created_at = key.activated_at;
        key.retired_at = Some(now - Duration::seconds(1));
        store.insert(&key).await.unwrap();
        rot.sweep_retired("t").await.unwrap();
        let evs = audit.events();
        assert!(evs
            .iter()
            .any(|e| matches!(e.kind, RotationAuditKind::Retired)
                && e.kid == key.kid
                && e.reason == "grace_window_expired"));
    }

    #[tokio::test]
    async fn tick_includes_sweep_on_entry() {
        let (rot, store, audit) = build();
        let now = Utc::now();
        let mut key = SigningKey::mint("t");
        key.activated_at = now - Duration::days(30);
        key.created_at = key.activated_at;
        key.retired_at = Some(now - Duration::seconds(1));
        store.insert(&key).await.unwrap();
        // Tick should sweep + see the tenant has no active key →
        // mint a first.
        let outcome = rot
            .tick("t", RotationPolicy::default_med003())
            .await
            .unwrap();
        assert!(outcome.is_some());
        let evs = audit.events();
        assert!(evs
            .iter()
            .any(|e| matches!(e.kind, RotationAuditKind::Retired)));
        assert!(evs
            .iter()
            .any(|e| matches!(e.kind, RotationAuditKind::Minted)));
    }
}
