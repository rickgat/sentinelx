//! Verify a `WebAuthn` registration response and persist the credential.

use std::sync::Arc;

use base64::Engine as _;
use time::OffsetDateTime;
use uuid::Uuid;
use webauthn_rs::prelude::{PasskeyRegistration, RegisterPublicKeyCredential};

use crate::controller::webauthn::build_service_for;
use crate::domain::{TenantId, UserId};
use crate::model::webauthn::{AttestationPolicy, StoredCredential};
use crate::port::{
    WebauthnAaguidPolicyRepository, WebauthnCredentialRepository, WebauthnMdsRepository,
    WebauthnRpRepository,
};
use crate::service::webauthn::{evaluate_aaguid_policy, AaguidDecision, MdsFetcher};
use crate::service::Clock;
use crate::IamError;

/// Inputs to [`RegisterFinishUseCase::execute`].
pub struct RegisterFinishInput {
    /// Tenant the registration is scoped to.
    pub tenant_id: TenantId,
    /// User registering the credential.
    pub user_id: UserId,
    /// Opaque state previously returned by `register_start`.
    pub state: PasskeyRegistration,
    /// Authenticator response from `navigator.credentials.create`.
    pub response: RegisterPublicKeyCredential,
    /// Optional user-set label (`"YubiKey 5"`, `"iPhone Touch ID"`, ...).
    pub label: Option<String>,
}

impl std::fmt::Debug for RegisterFinishInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterFinishInput")
            .field("tenant_id", &self.tenant_id.as_uuid())
            .field("user_id", &self.user_id.as_uuid())
            .field("label_present", &self.label.is_some())
            .finish_non_exhaustive()
    }
}

/// Output bundling the persisted credential's stable id.
#[derive(Debug, Clone)]
pub struct RegisterFinishOutput {
    /// Base64url-encoded credential id — what the caller emits as
    /// `cred_id` in the JWT claim on subsequent assertions.
    pub cred_id: String,
}

/// Use case: complete a registration ceremony.
pub struct RegisterFinishUseCase<C: Clock> {
    rp_repo: Arc<dyn WebauthnRpRepository>,
    cred_repo: Arc<dyn WebauthnCredentialRepository>,
    /// HIGH-002 — per-tenant AAGUID allow/block policy lookup. Optional
    /// for backward compatibility with P1-002 wiring; when absent the
    /// use case behaves as if every tenant has no policy rows (implicit
    /// allow).
    aaguid_policy_repo: Option<Arc<dyn WebauthnAaguidPolicyRepository>>,
    /// HIGH-002 — local FIDO MDS3 metadata cache. Optional; when absent
    /// the use case skips the unknown-AAGUID check.
    mds_repo: Option<Arc<dyn WebauthnMdsRepository>>,
    /// HIGH-002 — drives the staleness check + strict-unknown-AAGUID
    /// mode. Optional alongside [`Self::mds_repo`].
    mds_fetcher: Option<Arc<MdsFetcher>>,
    clock: Arc<C>,
}

impl<C: Clock> std::fmt::Debug for RegisterFinishUseCase<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisterFinishUseCase")
            .finish_non_exhaustive()
    }
}

impl<C: Clock> RegisterFinishUseCase<C> {
    /// Wire up the use case without HIGH-002 AAGUID enforcement. Kept
    /// for source-compat with the P1-002 wiring; callers that want the
    /// AAGUID blocklist + MDS3 freshness checks should use
    /// [`Self::with_aaguid_policy`].
    pub fn new(
        rp_repo: Arc<dyn WebauthnRpRepository>,
        cred_repo: Arc<dyn WebauthnCredentialRepository>,
        clock: Arc<C>,
    ) -> Self {
        Self {
            rp_repo,
            cred_repo,
            aaguid_policy_repo: None,
            mds_repo: None,
            mds_fetcher: None,
            clock,
        }
    }

    /// Wire up the use case with HIGH-002 AAGUID enforcement.
    ///
    /// `aaguid_policy_repo` is the per-tenant policy store; `mds_repo`
    /// is the cached FIDO MDS3 metadata table; `mds_fetcher` is the
    /// fetcher whose [`MdsFetcher::stale_for_longer_than`] +
    /// [`MdsFetcher::strict_unknown_aaguid`] drive the freshness +
    /// strict-mode behaviour.
    pub fn with_aaguid_policy(
        rp_repo: Arc<dyn WebauthnRpRepository>,
        cred_repo: Arc<dyn WebauthnCredentialRepository>,
        aaguid_policy_repo: Arc<dyn WebauthnAaguidPolicyRepository>,
        mds_repo: Arc<dyn WebauthnMdsRepository>,
        mds_fetcher: Arc<MdsFetcher>,
        clock: Arc<C>,
    ) -> Self {
        Self {
            rp_repo,
            cred_repo,
            aaguid_policy_repo: Some(aaguid_policy_repo),
            mds_repo: Some(mds_repo),
            mds_fetcher: Some(mds_fetcher),
            clock,
        }
    }

    /// Run the use case.
    pub async fn execute(
        &self,
        input: RegisterFinishInput,
    ) -> Result<RegisterFinishOutput, IamError> {
        let rp = self
            .rp_repo
            .get(input.tenant_id)
            .await?
            .ok_or_else(|| IamError::config("no webauthn relying-party for tenant"))?;
        let svc = build_service_for(&rp)?;

        let registered = svc
            .finish_registration(&input.state, &input.response)
            .map_err(|e| {
                tracing::warn!(
                    error = ?e,
                    tenant_id = %input.tenant_id.as_uuid(),
                    user_id = %input.user_id.as_uuid(),
                    "webauthn.register_finish verification failed",
                );
                IamError::InvalidCredentials
            })?;

        // HIGH-002 — AAGUID policy enforcement. The decision is logged
        // for every accept + every reject; rejects map onto
        // `IamError::Forbidden` with a `webauthn:aaguid` resource string
        // so the HTTP layer surfaces a 403 (not the generic 401 that
        // every other registration failure maps to). This makes the
        // failure operator-distinguishable from "bad attestation".
        let aaguid_uuid = registered
            .aaguid
            .map_or_else(uuid::Uuid::nil, uuid::Uuid::from_bytes);
        enforce_aaguid_policy(
            self.aaguid_policy_repo.as_deref(),
            self.mds_repo.as_deref(),
            self.mds_fetcher.as_deref(),
            input.tenant_id,
            input.user_id,
            aaguid_uuid,
        )
        .await?;

        // Encode cred_id for the JWT claim + stable lookup.
        let cred_id_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&registered.cred_id);

        // Round-trip the `Passkey` through serde_json so we can persist
        // the full state without the storage adapter depending on
        // `webauthn-rs`.
        let passkey_json = serde_json::to_value(&registered.passkey).map_err(|e| {
            tracing::warn!(error = ?e, "passkey serde failed");
            IamError::internal("webauthn passkey encode")
        })?;

        let stored = StoredCredential {
            id: Uuid::new_v4(),
            tenant_id: input.tenant_id,
            user_id: input.user_id,
            cred_id: cred_id_b64.clone(),
            cred_id_bytes: registered.cred_id.clone(),
            public_key: registered.public_key.clone(),
            aaguid: registered.aaguid,
            counter: registered.counter,
            passkey: passkey_json,
            label: input.label,
            // Persist the *policy* the tenant configured at registration
            // time so future audits can compare per-credential intent
            // against the tenant's current policy.
            attestation: rp_attestation_at_registration(&rp.attestation),
            created_at: self.clock.now(),
            last_used_at: None,
            revoked_at: None,
        };

        self.cred_repo.insert(&stored).await?;

        tracing::info!(
            tenant_id = %input.tenant_id.as_uuid(),
            user_id = %input.user_id.as_uuid(),
            cred_id = %cred_id_b64,
            "webauthn.register_finish",
        );

        Ok(RegisterFinishOutput {
            cred_id: cred_id_b64,
        })
    }
}

/// Identity helper kept as a fn for symmetry — keeps the call-site short
/// and gives us a clean place to add policy upgrade logic later (e.g.
/// downgrade `Enterprise` to `Direct` at storage time when the
/// authenticator did not actually return an enterprise attestation).
const fn rp_attestation_at_registration(p: &AttestationPolicy) -> AttestationPolicy {
    *p
}

/// Helper used by [`RegisterFinishUseCase`] to keep the `OffsetDateTime`
/// import alive when the clock type happens to monomorphise away.
#[allow(dead_code)]
fn _ensure_time_imported(_t: OffsetDateTime) {}

/// HIGH-002 — enforce the per-tenant AAGUID allow/block policy and the
/// MDS3 freshness gate. Emits a structured audit-grade tracing event
/// for every decision (accept *and* reject). Returns
/// [`IamError::Forbidden`] on reject so the HTTP layer surfaces a 403.
#[allow(clippy::cognitive_complexity)] // policy gate: 2-source fan-in (AAGUID policy + MDS3 freshness) + audit emit on every branch
async fn enforce_aaguid_policy(
    policy_repo: Option<&dyn WebauthnAaguidPolicyRepository>,
    mds_repo: Option<&dyn WebauthnMdsRepository>,
    mds_fetcher: Option<&MdsFetcher>,
    tenant_id: TenantId,
    user_id: UserId,
    aaguid: Uuid,
) -> Result<(), IamError> {
    let Some(policy_repo) = policy_repo else {
        // Backward-compat: HIGH-002 enforcement not wired ⇒ allow.
        return Ok(());
    };
    let rows = policy_repo.list(tenant_id).await?;
    let decision = evaluate_aaguid_policy(&rows, aaguid);

    // MDS3 staleness + strict-unknown gating — only applied when the
    // policy decision was Accept. A Reject overrides MDS-based logic.
    if let (AaguidDecision::Accept { .. }, Some(mds), Some(fetcher)) =
        (&decision, mds_repo, mds_fetcher)
    {
        let last_refresh = mds.last_refresh().await?;
        if fetcher.stale_for_longer_than(last_refresh) {
            tracing::warn!(
                tenant_id = %tenant_id.as_uuid(),
                user_id = %user_id.as_uuid(),
                aaguid = %aaguid,
                "webauthn.register_finish: MDS cache stale beyond tolerance — refusing unverified attestation",
            );
            return Err(IamError::forbidden("webauthn:aaguid"));
        }
        if fetcher.strict_unknown_aaguid() {
            let known = mds.get(aaguid).await?.is_some();
            if !known {
                tracing::warn!(
                    tenant_id = %tenant_id.as_uuid(),
                    user_id = %user_id.as_uuid(),
                    aaguid = %aaguid,
                    "webauthn.register_finish: aaguid not present in MDS cache (strict mode)",
                );
                return Err(IamError::forbidden("webauthn:aaguid"));
            }
        } else {
            // Soft warning when unknown but not strict.
            if mds.get(aaguid).await?.is_none() {
                tracing::warn!(
                    tenant_id = %tenant_id.as_uuid(),
                    user_id = %user_id.as_uuid(),
                    aaguid = %aaguid,
                    "webauthn.register_finish: aaguid not present in MDS cache (warning — non-strict mode accepts)",
                );
            }
        }
    }

    match decision {
        AaguidDecision::Accept { reason } => {
            tracing::info!(
                target: "audit.webauthn.aaguid",
                tenant_id = %tenant_id.as_uuid(),
                user_id = %user_id.as_uuid(),
                aaguid = %aaguid,
                decision = "accept",
                reason = %reason,
                "webauthn.register_finish aaguid policy decision",
            );
            Ok(())
        }
        AaguidDecision::Reject { reason } => {
            tracing::warn!(
                target: "audit.webauthn.aaguid",
                tenant_id = %tenant_id.as_uuid(),
                user_id = %user_id.as_uuid(),
                aaguid = %aaguid,
                decision = "reject",
                reason = %reason,
                "webauthn.register_finish aaguid policy decision",
            );
            Err(IamError::forbidden("webauthn:aaguid"))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::domain::{TenantId, UserId};
    use crate::model::webauthn::{AaguidAction, AaguidPolicy, MdsEntry, MdsStatus};
    use async_trait::async_trait;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakePolicyRepo {
        rows: Mutex<Vec<AaguidPolicy>>,
    }

    #[async_trait]
    impl WebauthnAaguidPolicyRepository for FakePolicyRepo {
        async fn list(&self, tenant_id: TenantId) -> Result<Vec<AaguidPolicy>, IamError> {
            let g = self.rows.lock().unwrap();
            Ok(g.iter()
                .filter(|r| r.tenant_id == tenant_id)
                .cloned()
                .collect())
        }
        async fn upsert(&self, policy: &AaguidPolicy) -> Result<(), IamError> {
            let mut g = self.rows.lock().unwrap();
            g.retain(|r| !(r.tenant_id == policy.tenant_id && r.aaguid == policy.aaguid));
            g.push(policy.clone());
            Ok(())
        }
        async fn delete(&self, tenant_id: TenantId, aaguid: Uuid) -> Result<(), IamError> {
            let mut g = self.rows.lock().unwrap();
            g.retain(|r| !(r.tenant_id == tenant_id && r.aaguid == aaguid));
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeMdsRepo {
        rows: Mutex<Vec<MdsEntry>>,
        last_refresh: Mutex<Option<OffsetDateTime>>,
    }
    #[async_trait]
    impl WebauthnMdsRepository for FakeMdsRepo {
        async fn get(&self, aaguid: Uuid) -> Result<Option<MdsEntry>, IamError> {
            let g = self.rows.lock().unwrap();
            Ok(g.iter().find(|e| e.aaguid == aaguid).cloned())
        }
        async fn replace_all(&self, entries: Vec<MdsEntry>) -> Result<(), IamError> {
            *self.rows.lock().unwrap() = entries;
            *self.last_refresh.lock().unwrap() = Some(OffsetDateTime::now_utc());
            Ok(())
        }
        async fn status(&self) -> Result<MdsStatus, IamError> {
            let entries = self.rows.lock().unwrap().len() as u64;
            let last = *self.last_refresh.lock().unwrap();
            Ok(MdsStatus {
                last_refresh: last,
                total_entries: entries,
                root_cert_fingerprint: crate::service::webauthn::PINNED_ROOT_SHA256_HEX.to_owned(),
            })
        }
        async fn last_refresh(&self) -> Result<Option<OffsetDateTime>, IamError> {
            Ok(*self.last_refresh.lock().unwrap())
        }
    }

    fn aaguid(idx: u128) -> Uuid {
        Uuid::from_u128(idx)
    }

    fn fresh_fetcher() -> Arc<MdsFetcher> {
        Arc::new(MdsFetcher::new(
            crate::service::webauthn::MdsConfig::default(),
        ))
    }

    fn strict_fetcher() -> Arc<MdsFetcher> {
        let cfg = crate::service::webauthn::MdsConfig {
            strict_unknown_aaguid: true,
            ..crate::service::webauthn::MdsConfig::default()
        };
        Arc::new(MdsFetcher::new(cfg))
    }

    #[tokio::test]
    async fn enforce_with_no_policy_repo_allows_anything() {
        let res =
            enforce_aaguid_policy(None, None, None, TenantId::new(), UserId::new(), aaguid(1))
                .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn enforce_rejects_blocked_aaguid() {
        let tid = TenantId::new();
        let policy = FakePolicyRepo::default();
        policy
            .upsert(&AaguidPolicy {
                tenant_id: tid,
                aaguid: aaguid(7),
                action: AaguidAction::Block,
                reason: "RP-001".into(),
                set_by: UserId::new(),
                set_at: OffsetDateTime::UNIX_EPOCH,
            })
            .await
            .unwrap();
        let err = enforce_aaguid_policy(Some(&policy), None, None, tid, UserId::new(), aaguid(7))
            .await
            .unwrap_err();
        match err {
            IamError::Forbidden { required } => assert_eq!(required, "webauthn:aaguid"),
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn enforce_allowlist_mode_rejects_non_allowed_aaguid() {
        let tid = TenantId::new();
        let policy = FakePolicyRepo::default();
        // Tenant has an allow row ⇒ allowlist-only mode.
        policy
            .upsert(&AaguidPolicy {
                tenant_id: tid,
                aaguid: aaguid(1),
                action: AaguidAction::Allow,
                reason: "L3 approved".into(),
                set_by: UserId::new(),
                set_at: OffsetDateTime::UNIX_EPOCH,
            })
            .await
            .unwrap();
        // A different AAGUID is not on the allowlist — implicit reject.
        let err = enforce_aaguid_policy(Some(&policy), None, None, tid, UserId::new(), aaguid(2))
            .await
            .unwrap_err();
        assert!(matches!(err, IamError::Forbidden { .. }));
        // The allowed AAGUID still works.
        enforce_aaguid_policy(Some(&policy), None, None, tid, UserId::new(), aaguid(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn enforce_cross_tenant_blocklist_does_not_affect_other_tenants() {
        let tid_a = TenantId::new();
        let tid_b = TenantId::new();
        let policy = FakePolicyRepo::default();
        // Tenant A blocks AAGUID 5.
        policy
            .upsert(&AaguidPolicy {
                tenant_id: tid_a,
                aaguid: aaguid(5),
                action: AaguidAction::Block,
                reason: "tenant-A block".into(),
                set_by: UserId::new(),
                set_at: OffsetDateTime::UNIX_EPOCH,
            })
            .await
            .unwrap();
        // Tenant B has no rows ⇒ default allow.
        enforce_aaguid_policy(Some(&policy), None, None, tid_b, UserId::new(), aaguid(5))
            .await
            .expect("tenant B must not see tenant A's blocklist");
        // Tenant A: blocked.
        let err = enforce_aaguid_policy(Some(&policy), None, None, tid_a, UserId::new(), aaguid(5))
            .await
            .unwrap_err();
        assert!(matches!(err, IamError::Forbidden { .. }));
    }

    #[tokio::test]
    async fn enforce_strict_unknown_aaguid_rejects_when_not_in_mds() {
        let tid = TenantId::new();
        let policy = FakePolicyRepo::default(); // default allow
        let mds = FakeMdsRepo::default();
        // Populate so last_refresh becomes recent (fresh cache).
        mds.replace_all(vec![]).await.unwrap();
        let fetcher = strict_fetcher();
        // Strict mode + AAGUID absent from MDS ⇒ reject.
        let err = enforce_aaguid_policy(
            Some(&policy),
            Some(&mds),
            Some(&fetcher),
            tid,
            UserId::new(),
            aaguid(99),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, IamError::Forbidden { .. }));
    }

    #[tokio::test]
    async fn enforce_non_strict_unknown_aaguid_is_a_warning_not_reject() {
        let tid = TenantId::new();
        let policy = FakePolicyRepo::default();
        let mds = FakeMdsRepo::default();
        mds.replace_all(vec![]).await.unwrap();
        let fetcher = fresh_fetcher();
        // Non-strict: unknown AAGUID still accepted.
        enforce_aaguid_policy(
            Some(&policy),
            Some(&mds),
            Some(&fetcher),
            tid,
            UserId::new(),
            aaguid(99),
        )
        .await
        .expect("non-strict mode must accept unknown AAGUID");
    }

    #[tokio::test]
    async fn enforce_stale_mds_beyond_tolerance_rejects() {
        let tid = TenantId::new();
        let policy = FakePolicyRepo::default();
        let mds = FakeMdsRepo::default();
        // Manually set an OLD last_refresh.
        {
            let mut g = mds.last_refresh.lock().unwrap();
            *g = Some(OffsetDateTime::now_utc() - time::Duration::days(30));
        }
        let fetcher = fresh_fetcher();
        let err = enforce_aaguid_policy(
            Some(&policy),
            Some(&mds),
            Some(&fetcher),
            tid,
            UserId::new(),
            aaguid(1),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, IamError::Forbidden { .. }));
    }
}
