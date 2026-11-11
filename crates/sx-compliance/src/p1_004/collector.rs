//! P1-004 collector trait and the five built-in implementations.
//!
//! The trait signature mirrors the spec:
//! `EvidenceCollector { id: ControlId; collect() -> Evidence }`.
//! The returned `Evidence` envelope is the same shape used by the
//! rest of the crate (`crate::collector::types::Evidence`) so the
//! WORM persistence path is uniform.
//!
//! Every collector takes its production dependencies through a
//! Boxed trait object (`Box<dyn Fetcher>`) so tests can swap in
//! deterministic stubs without an `aws-sdk-iam`, `sqlx`, or Vault
//! client present. The production wiring (services/sx-monolith) is
//! responsible for binding the trait objects to real adapters.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

use crate::collector::types::{Evidence, EvidenceContentType};
use crate::model::framework::Framework;
use crate::p1_004::control::{ids, ControlId};
use crate::p1_004::schedule::ControlSchedule;
use crate::p1_004::store::TenantId;

/// Error returned by a built-in P1-004 collector.
#[derive(Debug, Error)]
pub enum P1004CollectError {
    /// The underlying transport / fetcher failed.
    #[error("fetch failed: {0}")]
    Fetch(String),
    /// Encoding the evidence payload failed.
    #[error("payload encoding failed: {0}")]
    Encoding(String),
    /// A required field was missing in the upstream response.
    #[error("invalid upstream response: {0}")]
    Invalid(String),
}

/// P1-004 evidence collector trait.
///
/// Every concrete collector exposes its `ControlId` and a tenant-scoped
/// `collect`. The `Evidence` envelope is the canonical shape used by
/// the bundle writer + WORM store.
#[async_trait]
pub trait EvidenceCollector: Send + Sync + std::fmt::Debug {
    /// Framework-local control identifier (`SX-…`).
    fn id(&self) -> ControlId;

    /// Default schedule for this collector.
    fn schedule(&self) -> ControlSchedule {
        ControlSchedule::weekly_default()
    }

    /// Collect evidence for `tenant_id` at `now`.
    async fn collect(
        &self,
        tenant_id: &TenantId,
        now: OffsetDateTime,
    ) -> Result<Evidence, P1004CollectError>;
}

// ---------------------------------------------------------------------------
// 1. MFA enrollment rate (Postgres count)
// ---------------------------------------------------------------------------

/// Tenant-scoped result of an MFA-enrollment query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MfaEnrollmentStats {
    /// Number of active users in the tenant.
    pub active_users: u64,
    /// Subset of active users with at least one MFA factor enrolled.
    pub mfa_enrolled: u64,
}

impl MfaEnrollmentStats {
    /// Enrolment ratio rounded to four decimal places. Returns `0.0`
    /// when there are no active users so the evidence is well-defined
    /// for empty tenants.
    #[must_use]
    pub fn enrollment_rate(&self) -> f64 {
        if self.active_users == 0 {
            0.0
        } else {
            #[allow(clippy::cast_precision_loss)]
            let raw = (self.mfa_enrolled as f64) / (self.active_users as f64);
            (raw * 10_000.0).round() / 10_000.0
        }
    }
}

/// Abstraction over "count MFA-enrolled users for tenant X".
#[async_trait]
pub trait MfaEnrollmentQuery: Send + Sync + std::fmt::Debug {
    /// Return the active/enrolled counts for `tenant_id`.
    async fn stats(&self, tenant_id: &TenantId) -> Result<MfaEnrollmentStats, P1004CollectError>;
}

/// Concrete collector for [`ids::MFA_ENROLLMENT_RATE`].
#[derive(Debug)]
pub struct MfaEnrollmentCollector {
    query: Arc<dyn MfaEnrollmentQuery>,
}

impl MfaEnrollmentCollector {
    /// Construct from an injected query implementation.
    #[must_use]
    pub fn new(query: Arc<dyn MfaEnrollmentQuery>) -> Self {
        Self { query }
    }
}

#[async_trait]
impl EvidenceCollector for MfaEnrollmentCollector {
    fn id(&self) -> ControlId {
        ControlId::new(ids::MFA_ENROLLMENT_RATE)
    }

    async fn collect(
        &self,
        tenant_id: &TenantId,
        now: OffsetDateTime,
    ) -> Result<Evidence, P1004CollectError> {
        let stats = self.query.stats(tenant_id).await?;
        let payload = serde_json::json!({
            "control_id": ids::MFA_ENROLLMENT_RATE,
            "tenant_id": tenant_id.as_str(),
            "active_users": stats.active_users,
            "mfa_enrolled": stats.mfa_enrolled,
            "enrollment_rate": stats.enrollment_rate(),
        });
        let bytes =
            serde_json::to_vec(&payload).map_err(|e| P1004CollectError::Encoding(e.to_string()))?;
        Ok(Evidence::new(
            ids::MFA_ENROLLMENT_RATE,
            Framework::Soc2,
            now,
            EvidenceContentType::Json,
            bytes,
            "1.0.0",
        ))
    }
}

// ---------------------------------------------------------------------------
// 2. AWS IAM password policy fetch
// ---------------------------------------------------------------------------

/// Snapshot of an AWS IAM account password policy (the subset the
/// auditor cares about). The shape mirrors `aws-sdk-iam`'s
/// `PasswordPolicy` but we keep it as a plain struct so the collector
/// does not take a hard dependency on `aws-sdk-iam` at this crate
/// boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IamPasswordPolicy {
    /// Minimum password length (PCI DSS v4 requires >= 12).
    pub minimum_password_length: u32,
    /// Whether the policy requires symbols.
    pub require_symbols: bool,
    /// Whether the policy requires numbers.
    pub require_numbers: bool,
    /// Whether the policy requires uppercase.
    pub require_uppercase: bool,
    /// Whether the policy requires lowercase.
    pub require_lowercase: bool,
    /// Whether users are allowed to change their own password.
    pub allow_users_to_change_password: bool,
    /// Days before a password expires; `None` if unlimited.
    pub max_password_age_days: Option<u32>,
    /// Remember last N passwords to prevent reuse; `None` if unlimited.
    pub password_reuse_prevention: Option<u32>,
}

/// Abstraction over `aws-sdk-iam`'s `GetAccountPasswordPolicy` call.
#[async_trait]
pub trait IamPasswordPolicyFetcher: Send + Sync + std::fmt::Debug {
    /// Fetch the current password policy for the AWS account bound to
    /// `tenant_id`'s cloud connector configuration.
    async fn fetch(&self, tenant_id: &TenantId) -> Result<IamPasswordPolicy, P1004CollectError>;
}

/// Concrete collector for [`ids::AWS_IAM_PASSWORD_POLICY`].
#[derive(Debug)]
pub struct IamPasswordPolicyCollector {
    fetcher: Arc<dyn IamPasswordPolicyFetcher>,
}

impl IamPasswordPolicyCollector {
    /// Construct from a `Fetcher` implementation.
    #[must_use]
    pub fn new(fetcher: Arc<dyn IamPasswordPolicyFetcher>) -> Self {
        Self { fetcher }
    }
}

#[async_trait]
impl EvidenceCollector for IamPasswordPolicyCollector {
    fn id(&self) -> ControlId {
        ControlId::new(ids::AWS_IAM_PASSWORD_POLICY)
    }

    async fn collect(
        &self,
        tenant_id: &TenantId,
        now: OffsetDateTime,
    ) -> Result<Evidence, P1004CollectError> {
        let pol = self.fetcher.fetch(tenant_id).await?;
        let payload = serde_json::json!({
            "control_id": ids::AWS_IAM_PASSWORD_POLICY,
            "tenant_id": tenant_id.as_str(),
            "policy": pol,
        });
        let bytes =
            serde_json::to_vec(&payload).map_err(|e| P1004CollectError::Encoding(e.to_string()))?;
        Ok(Evidence::new(
            ids::AWS_IAM_PASSWORD_POLICY,
            Framework::PciDss,
            now,
            EvidenceContentType::Json,
            bytes,
            "1.0.0",
        ))
    }
}

// ---------------------------------------------------------------------------
// 3. Vault sealed-state probe
// ---------------------------------------------------------------------------

/// Vault `sys/seal-status` response shape (subset).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultSealStatus {
    /// True if Vault is sealed (bad — keys unavailable).
    pub sealed: bool,
    /// Vault server version reported by the API.
    pub version: String,
    /// Number of key shares required to unseal.
    pub threshold: u32,
    /// Total number of key shares.
    pub n: u32,
}

/// Abstraction over the Vault `sys/seal-status` probe.
#[async_trait]
pub trait VaultStatusProbe: Send + Sync + std::fmt::Debug {
    /// Probe Vault and return its current seal status.
    async fn probe(&self, tenant_id: &TenantId) -> Result<VaultSealStatus, P1004CollectError>;
}

/// Concrete collector for [`ids::VAULT_SEALED_STATE`].
#[derive(Debug)]
pub struct VaultSealedStateCollector {
    probe: Arc<dyn VaultStatusProbe>,
}

impl VaultSealedStateCollector {
    /// Construct from a probe implementation.
    #[must_use]
    pub fn new(probe: Arc<dyn VaultStatusProbe>) -> Self {
        Self { probe }
    }
}

#[async_trait]
impl EvidenceCollector for VaultSealedStateCollector {
    fn id(&self) -> ControlId {
        ControlId::new(ids::VAULT_SEALED_STATE)
    }

    async fn collect(
        &self,
        tenant_id: &TenantId,
        now: OffsetDateTime,
    ) -> Result<Evidence, P1004CollectError> {
        let s = self.probe.probe(tenant_id).await?;
        let payload = serde_json::json!({
            "control_id": ids::VAULT_SEALED_STATE,
            "tenant_id": tenant_id.as_str(),
            "status": s,
        });
        let bytes =
            serde_json::to_vec(&payload).map_err(|e| P1004CollectError::Encoding(e.to_string()))?;
        Ok(Evidence::new(
            ids::VAULT_SEALED_STATE,
            Framework::Soc2,
            now,
            EvidenceContentType::Json,
            bytes,
            "1.0.0",
        ))
    }
}

// ---------------------------------------------------------------------------
// 4. Kill-switch tested-recently (reads `kill_switch_events`)
// ---------------------------------------------------------------------------

/// Window inside which a kill-switch test event is considered "recent".
pub const KILL_SWITCH_WINDOW_DAYS: i64 = 90;

/// Abstraction over the `kill_switch_events` table read.
#[async_trait]
pub trait KillSwitchEventReader: Send + Sync + std::fmt::Debug {
    /// Timestamp of the most recent kill-switch *test* event for the
    /// supplied tenant; `None` when no test has ever been recorded.
    async fn last_test_at(
        &self,
        tenant_id: &TenantId,
    ) -> Result<Option<OffsetDateTime>, P1004CollectError>;
}

/// Concrete collector for [`ids::KILL_SWITCH_TESTED_RECENTLY`].
#[derive(Debug)]
pub struct KillSwitchRecentCollector {
    reader: Arc<dyn KillSwitchEventReader>,
}

impl KillSwitchRecentCollector {
    /// Construct from a reader.
    #[must_use]
    pub fn new(reader: Arc<dyn KillSwitchEventReader>) -> Self {
        Self { reader }
    }
}

#[async_trait]
impl EvidenceCollector for KillSwitchRecentCollector {
    fn id(&self) -> ControlId {
        ControlId::new(ids::KILL_SWITCH_TESTED_RECENTLY)
    }

    async fn collect(
        &self,
        tenant_id: &TenantId,
        now: OffsetDateTime,
    ) -> Result<Evidence, P1004CollectError> {
        let last = self.reader.last_test_at(tenant_id).await?;
        let (healthy, age_days, last_iso) = match last {
            Some(ts) => {
                let age = now - ts;
                let days = age.whole_days();
                let healthy = age <= Duration::days(KILL_SWITCH_WINDOW_DAYS);
                let iso = ts
                    .format(&time::format_description::well_known::Rfc3339)
                    .map_err(|e| P1004CollectError::Encoding(e.to_string()))?;
                (healthy, Some(days), Some(iso))
            }
            None => (false, None, None),
        };
        let payload = serde_json::json!({
            "control_id": ids::KILL_SWITCH_TESTED_RECENTLY,
            "tenant_id": tenant_id.as_str(),
            "healthy": healthy,
            "last_test_at": last_iso,
            "age_days": age_days,
            "threshold_days": KILL_SWITCH_WINDOW_DAYS,
        });
        let bytes =
            serde_json::to_vec(&payload).map_err(|e| P1004CollectError::Encoding(e.to_string()))?;
        Ok(Evidence::new(
            ids::KILL_SWITCH_TESTED_RECENTLY,
            Framework::Soc2,
            now,
            EvidenceContentType::Json,
            bytes,
            "1.0.0",
        ))
    }
}

// ---------------------------------------------------------------------------
// 5. Audit-chain integrity verify
// ---------------------------------------------------------------------------

/// Result of a chain verification probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainVerifyOutcome {
    /// Number of records inspected.
    pub records_examined: u64,
    /// `true` iff every link verified.
    pub verified: bool,
    /// Id of the first failing record (if any).
    pub first_failing_id: Option<String>,
    /// RFC 3339 window start.
    pub window_start: String,
    /// RFC 3339 window end.
    pub window_end: String,
}

/// Abstraction over the `sx-audit` chain-verify call.
#[async_trait]
pub trait ChainVerifyProbe: Send + Sync + std::fmt::Debug {
    /// Verify the last `window_days` of chain entries for `tenant_id`.
    async fn verify(
        &self,
        tenant_id: &TenantId,
        now: OffsetDateTime,
        window_days: i64,
    ) -> Result<ChainVerifyOutcome, P1004CollectError>;
}

/// Concrete collector for [`ids::AUDIT_CHAIN_INTEGRITY_VERIFY`].
#[derive(Debug)]
pub struct AuditChainVerifyCollector {
    probe: Arc<dyn ChainVerifyProbe>,
}

impl AuditChainVerifyCollector {
    /// Window the collector covers.
    pub const WINDOW_DAYS: i64 = 7;

    /// Construct from a verifier.
    #[must_use]
    pub fn new(probe: Arc<dyn ChainVerifyProbe>) -> Self {
        Self { probe }
    }
}

#[async_trait]
impl EvidenceCollector for AuditChainVerifyCollector {
    fn id(&self) -> ControlId {
        ControlId::new(ids::AUDIT_CHAIN_INTEGRITY_VERIFY)
    }

    async fn collect(
        &self,
        tenant_id: &TenantId,
        now: OffsetDateTime,
    ) -> Result<Evidence, P1004CollectError> {
        let outcome = self.probe.verify(tenant_id, now, Self::WINDOW_DAYS).await?;
        let payload = serde_json::json!({
            "control_id": ids::AUDIT_CHAIN_INTEGRITY_VERIFY,
            "tenant_id": tenant_id.as_str(),
            "outcome": outcome,
        });
        let bytes =
            serde_json::to_vec(&payload).map_err(|e| P1004CollectError::Encoding(e.to_string()))?;
        Ok(Evidence::new(
            ids::AUDIT_CHAIN_INTEGRITY_VERIFY,
            Framework::Iso27001,
            now,
            EvidenceContentType::Json,
            bytes,
            "1.0.0",
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::Mutex;

    use time::macros::datetime;

    use super::*;

    fn t() -> TenantId {
        TenantId::new("tenant-A")
    }

    #[derive(Debug, Default)]
    struct StubMfa {
        active: u64,
        enrolled: u64,
    }

    #[async_trait]
    impl MfaEnrollmentQuery for StubMfa {
        async fn stats(&self, _t: &TenantId) -> Result<MfaEnrollmentStats, P1004CollectError> {
            Ok(MfaEnrollmentStats {
                active_users: self.active,
                mfa_enrolled: self.enrolled,
            })
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mfa_collector_emits_expected_payload() {
        let c = MfaEnrollmentCollector::new(Arc::new(StubMfa {
            active: 200,
            enrolled: 175,
        }));
        let ev = c
            .collect(&t(), datetime!(2026-06-12 00:00:00 UTC))
            .await
            .unwrap();
        assert_eq!(ev.control_id, "SX-MFA-ENROLLMENT-RATE");
        let parsed: serde_json::Value = serde_json::from_slice(&ev.payload).unwrap();
        assert_eq!(parsed["active_users"], 200);
        assert_eq!(parsed["mfa_enrolled"], 175);
        assert!((parsed["enrollment_rate"].as_f64().unwrap() - 0.875).abs() < 1e-9);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mfa_collector_handles_zero_active_users() {
        let c = MfaEnrollmentCollector::new(Arc::new(StubMfa {
            active: 0,
            enrolled: 0,
        }));
        let ev = c
            .collect(&t(), datetime!(2026-06-12 00:00:00 UTC))
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&ev.payload).unwrap();
        assert!((parsed["enrollment_rate"].as_f64().unwrap()).abs() < 1e-9);
    }

    #[derive(Debug)]
    struct StubIam(Mutex<IamPasswordPolicy>);

    #[async_trait]
    impl IamPasswordPolicyFetcher for StubIam {
        async fn fetch(&self, _t: &TenantId) -> Result<IamPasswordPolicy, P1004CollectError> {
            Ok(self.0.lock().unwrap().clone())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn iam_collector_records_policy_snapshot() {
        let pol = IamPasswordPolicy {
            minimum_password_length: 14,
            require_symbols: true,
            require_numbers: true,
            require_uppercase: true,
            require_lowercase: true,
            allow_users_to_change_password: true,
            max_password_age_days: Some(90),
            password_reuse_prevention: Some(12),
        };
        let c = IamPasswordPolicyCollector::new(Arc::new(StubIam(Mutex::new(pol.clone()))));
        let ev = c
            .collect(&t(), datetime!(2026-06-12 00:00:00 UTC))
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&ev.payload).unwrap();
        assert_eq!(parsed["policy"]["minimum_password_length"], 14);
        assert_eq!(parsed["policy"]["require_symbols"], true);
        assert_eq!(parsed["policy"]["max_password_age_days"], 90);
    }

    #[derive(Debug)]
    struct StubVault(VaultSealStatus);

    #[async_trait]
    impl VaultStatusProbe for StubVault {
        async fn probe(&self, _t: &TenantId) -> Result<VaultSealStatus, P1004CollectError> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn vault_collector_serialises_seal_status() {
        let s = VaultSealStatus {
            sealed: false,
            version: "1.17.0".into(),
            threshold: 3,
            n: 5,
        };
        let c = VaultSealedStateCollector::new(Arc::new(StubVault(s)));
        let ev = c
            .collect(&t(), datetime!(2026-06-12 00:00:00 UTC))
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&ev.payload).unwrap();
        assert_eq!(parsed["status"]["sealed"], false);
        assert_eq!(parsed["status"]["version"], "1.17.0");
    }

    #[derive(Debug, Default)]
    struct StubKill(Option<OffsetDateTime>);

    #[async_trait]
    impl KillSwitchEventReader for StubKill {
        async fn last_test_at(
            &self,
            _t: &TenantId,
        ) -> Result<Option<OffsetDateTime>, P1004CollectError> {
            Ok(self.0)
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn kill_switch_collector_marks_healthy_within_window() {
        let c = KillSwitchRecentCollector::new(Arc::new(StubKill(Some(
            datetime!(2026-04-15 00:00:00 UTC),
        ))));
        let ev = c
            .collect(&t(), datetime!(2026-06-12 00:00:00 UTC))
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&ev.payload).unwrap();
        assert_eq!(parsed["healthy"], true);
        assert_eq!(parsed["threshold_days"], 90);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn kill_switch_collector_unhealthy_when_stale() {
        let c = KillSwitchRecentCollector::new(Arc::new(StubKill(Some(
            datetime!(2025-01-01 00:00:00 UTC),
        ))));
        let ev = c
            .collect(&t(), datetime!(2026-06-12 00:00:00 UTC))
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&ev.payload).unwrap();
        assert_eq!(parsed["healthy"], false);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn kill_switch_collector_unhealthy_when_never_tested() {
        let c = KillSwitchRecentCollector::new(Arc::new(StubKill::default()));
        let ev = c
            .collect(&t(), datetime!(2026-06-12 00:00:00 UTC))
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&ev.payload).unwrap();
        assert_eq!(parsed["healthy"], false);
        assert!(parsed["last_test_at"].is_null());
    }

    #[derive(Debug)]
    struct StubChain(ChainVerifyOutcome);

    #[async_trait]
    impl ChainVerifyProbe for StubChain {
        async fn verify(
            &self,
            _t: &TenantId,
            _now: OffsetDateTime,
            _window: i64,
        ) -> Result<ChainVerifyOutcome, P1004CollectError> {
            Ok(self.0.clone())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn audit_chain_collector_includes_outcome() {
        let outcome = ChainVerifyOutcome {
            records_examined: 5_000,
            verified: true,
            first_failing_id: None,
            window_start: "2026-06-05T00:00:00Z".into(),
            window_end: "2026-06-12T00:00:00Z".into(),
        };
        let c = AuditChainVerifyCollector::new(Arc::new(StubChain(outcome)));
        let ev = c
            .collect(&t(), datetime!(2026-06-12 00:00:00 UTC))
            .await
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&ev.payload).unwrap();
        assert_eq!(parsed["outcome"]["verified"], true);
        assert_eq!(parsed["outcome"]["records_examined"], 5_000);
    }
}
