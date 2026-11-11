//! Device-trust service trait + in-memory implementation.
//!
//! The trait lives here so consumers (the API crate, downstream policy
//! engines, dashboards) can depend on a small surface without pulling in the
//! storage adapter. The in-memory implementation backs the dev / standalone
//! monolith path and is exercised by the integration tests.

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::policy::{compare_versions, PosturePolicy, PostureRule};
use crate::posture::PostureClaims;

/// Posture verdict emitted by the evaluator.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeviceTrustStatus {
    /// All policy rules satisfied.
    Trusted,
    /// At least one policy rule violated.
    Untrusted,
    /// Posture signal absent or older than the configured freshness window.
    Stale,
}

impl DeviceTrustStatus {
    /// Lowercase serialisation used in HTTP responses + DB columns.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Untrusted => "untrusted",
            Self::Stale => "stale",
        }
    }
}

/// Outcome of evaluating a posture against a policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceTrustDecision {
    /// Verdict.
    pub status: DeviceTrustStatus,
    /// Per-rule violation messages — empty when `status == Trusted`.
    pub reasons: Vec<String>,
}

impl DeviceTrustDecision {
    /// Trusted with no reasons.
    #[must_use]
    pub const fn trusted() -> Self {
        Self {
            status: DeviceTrustStatus::Trusted,
            reasons: Vec::new(),
        }
    }

    /// Untrusted with the supplied reasons.
    #[must_use]
    pub const fn untrusted(reasons: Vec<String>) -> Self {
        Self {
            status: DeviceTrustStatus::Untrusted,
            reasons,
        }
    }

    /// Stale with the supplied reason.
    #[must_use]
    pub fn stale(reason: impl Into<String>) -> Self {
        Self {
            status: DeviceTrustStatus::Stale,
            reasons: vec![reason.into()],
        }
    }
}

/// Generic error returned by the device-trust port.
#[derive(Debug, Clone, Error)]
pub enum DeviceTrustError {
    /// Resource not found.
    #[error("not found")]
    NotFound,
    /// Caller not permitted.
    #[error("forbidden")]
    Forbidden,
    /// Validation error.
    #[error("invalid: {0}")]
    Invalid(String),
    /// Underlying dependency failure (db, etc.).
    #[error("dependency: {0}")]
    Dependency(String),
    /// Programmer error.
    #[error("internal: {0}")]
    Internal(String),
}

/// Device-trust service trait.
///
/// Implementations own the per-tenant policy store and the recent snapshot
/// log. The HTTP layer ports against this trait via
/// [`sx_api::port::DeviceTrustPort`] in the API crate.
#[async_trait]
pub trait DeviceTrustService: Send + Sync + std::fmt::Debug {
    /// Fetch the current policy for `tenant_id`.
    async fn get_policy(&self, tenant_id: &str) -> Result<PosturePolicy, DeviceTrustError>;
    /// Replace the policy for `tenant_id`. Tenant existence is enforced by
    /// the storage layer (the in-memory adapter is permissive).
    async fn put_policy(
        &self,
        tenant_id: &str,
        policy: PosturePolicy,
    ) -> Result<PosturePolicy, DeviceTrustError>;
    /// Evaluate `posture` against the tenant's policy. Returns the
    /// per-rule decision without mutating state.
    async fn evaluate(
        &self,
        tenant_id: &str,
        posture: &PostureClaims,
    ) -> Result<DeviceTrustDecision, DeviceTrustError>;
    /// Persist a posture observation (status + claims) keyed by session.
    /// Implementations are expected to bound the retained snapshot count.
    async fn record_snapshot(
        &self,
        tenant_id: &str,
        snapshot: PostureSnapshot,
    ) -> Result<(), DeviceTrustError>;
    /// List recent snapshots, newest-first, capped at `limit`.
    async fn list_snapshots(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<PostureSnapshot>, DeviceTrustError>;
}

/// One posture observation recorded against an active session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PostureSnapshot {
    /// Snapshot id (uuid).
    pub id: String,
    /// User id from the bearer claim `sub`.
    pub user_id: String,
    /// Session id from the bearer claim `sid`.
    pub session_id: String,
    /// Verdict.
    pub status: DeviceTrustStatus,
    /// Decoded posture claims at the moment of evaluation.
    pub claims: PostureClaims,
    /// Per-rule reasons.
    pub reasons: Vec<String>,
    /// RFC 3339 timestamp.
    pub observed_at: String,
}

/// Pure evaluator: turns a `(policy, posture)` pair into a decision.
///
/// Exposed standalone (not just behind the trait) so callers can run the
/// evaluation without a service registration — useful in tests + the
/// dashboard preview.
#[must_use]
pub fn evaluate_policy(policy: &PosturePolicy, posture: &PostureClaims) -> DeviceTrustDecision {
    let mut reasons = Vec::new();

    // OS block-list is the hardest gate.
    if let Some(os) = posture.os_name.as_deref() {
        if policy
            .os_block_list
            .iter()
            .any(|b| b.eq_ignore_ascii_case(os))
        {
            reasons.push(format!("os '{os}' is on the block list"));
        }
        if !policy.os_allow_list.is_empty()
            && !policy
                .os_allow_list
                .iter()
                .any(|a| a.eq_ignore_ascii_case(os))
        {
            reasons.push(format!("os '{os}' not in the allow list"));
        }
        if let Some(min_ver) = policy.minimum_os_versions.get(os) {
            if let Some(actual) = posture.os_version.as_deref() {
                if compare_versions(actual, min_ver) == std::cmp::Ordering::Less {
                    reasons.push(format!("os '{os}' version {actual} < required {min_ver}"));
                }
            } else {
                reasons.push(format!(
                    "os '{os}' requires version >= {min_ver}, none reported"
                ));
            }
        }
    } else if !policy.os_allow_list.is_empty() || !policy.minimum_os_versions.is_empty() {
        // Policy cares about OS but we got none.
        reasons.push("os_name missing from posture".to_owned());
    }

    if !policy.edr_vendor_allow_list.is_empty() {
        match posture.edr_vendor.as_deref() {
            Some(vendor) => {
                if !policy
                    .edr_vendor_allow_list
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(vendor))
                {
                    reasons.push(format!("edr vendor '{vendor}' not in allow list"));
                }
            }
            None => reasons.push("edr_vendor missing from posture".to_owned()),
        }
    }

    for rule in &policy.rules {
        match rule {
            PostureRule::RequireDiskEncryption => {
                if !posture.disk_encrypted {
                    reasons.push("disk encryption required".to_owned());
                }
            }
            PostureRule::RequireEdr => {
                if !posture.edr_present {
                    reasons.push("edr agent required".to_owned());
                }
            }
            PostureRule::RequireScreenLock => match posture.screen_lock_minutes {
                Some(mins) => {
                    if let Some(max) = policy.max_screen_lock_minutes {
                        if mins > max {
                            reasons.push(format!("screen lock {mins}m > permitted {max}m"));
                        }
                    }
                }
                None => reasons.push("screen lock not configured".to_owned()),
            },
        }
    }

    if reasons.is_empty() {
        DeviceTrustDecision::trusted()
    } else {
        DeviceTrustDecision::untrusted(reasons)
    }
}

/// In-memory adapter — backs dev / standalone monolith.
#[derive(Debug, Default)]
pub struct InMemoryDeviceTrustService {
    policies: Mutex<HashMap<String, PosturePolicy>>,
    snapshots: Mutex<HashMap<String, Vec<PostureSnapshot>>>,
    snapshot_cap: usize,
}

impl InMemoryDeviceTrustService {
    /// Construct a new in-memory store with the default snapshot cap (500
    /// entries per tenant).
    #[must_use]
    pub fn new() -> Self {
        Self {
            policies: Mutex::new(HashMap::new()),
            snapshots: Mutex::new(HashMap::new()),
            snapshot_cap: 500,
        }
    }

    /// Build with a custom snapshot retention cap. Used by tests to verify
    /// the eviction behaviour.
    #[must_use]
    pub fn with_cap(cap: usize) -> Self {
        Self {
            policies: Mutex::new(HashMap::new()),
            snapshots: Mutex::new(HashMap::new()),
            snapshot_cap: cap,
        }
    }
}

#[async_trait]
impl DeviceTrustService for InMemoryDeviceTrustService {
    async fn get_policy(&self, tenant_id: &str) -> Result<PosturePolicy, DeviceTrustError> {
        let guard = self
            .policies
            .lock()
            .map_err(|_| DeviceTrustError::Internal("policy mutex poisoned".into()))?;
        Ok(guard
            .get(tenant_id)
            .cloned()
            .unwrap_or_else(PosturePolicy::permissive))
    }

    async fn put_policy(
        &self,
        tenant_id: &str,
        policy: PosturePolicy,
    ) -> Result<PosturePolicy, DeviceTrustError> {
        let mut guard = self
            .policies
            .lock()
            .map_err(|_| DeviceTrustError::Internal("policy mutex poisoned".into()))?;
        guard.insert(tenant_id.to_owned(), policy.clone());
        // Release the lock before returning so callers awaiting the same
        // mutex don't queue behind the trivial `Ok(...)` tail.
        drop(guard);
        Ok(policy)
    }

    async fn evaluate(
        &self,
        tenant_id: &str,
        posture: &PostureClaims,
    ) -> Result<DeviceTrustDecision, DeviceTrustError> {
        let policy = self.get_policy(tenant_id).await?;
        Ok(evaluate_policy(&policy, posture))
    }

    async fn record_snapshot(
        &self,
        tenant_id: &str,
        snapshot: PostureSnapshot,
    ) -> Result<(), DeviceTrustError> {
        let mut guard = self
            .snapshots
            .lock()
            .map_err(|_| DeviceTrustError::Internal("snapshot mutex poisoned".into()))?;
        let bucket = guard.entry(tenant_id.to_owned()).or_default();
        bucket.insert(0, snapshot);
        if bucket.len() > self.snapshot_cap {
            bucket.truncate(self.snapshot_cap);
        }
        // Release the lock before returning so concurrent recorders don't
        // queue behind the trivial `Ok(())` tail.
        drop(guard);
        Ok(())
    }

    async fn list_snapshots(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<PostureSnapshot>, DeviceTrustError> {
        let guard = self
            .snapshots
            .lock()
            .map_err(|_| DeviceTrustError::Internal("snapshot mutex poisoned".into()))?;
        Ok(guard
            .get(tenant_id)
            .map(|v| v.iter().take(limit).cloned().collect())
            .unwrap_or_default())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn tenant() -> &'static str {
        "01010101-0101-0101-0101-010101010101"
    }

    #[test]
    fn trusted_when_all_rules_pass() {
        let policy = PosturePolicy::strict_baseline();
        let posture = PostureClaims {
            os_name: Some("macOS".into()),
            os_version: Some("14.5.0".into()),
            disk_encrypted: true,
            edr_present: true,
            screen_lock_minutes: Some(5),
            ..PostureClaims::default()
        };
        let dec = evaluate_policy(&policy, &posture);
        assert_eq!(dec.status, DeviceTrustStatus::Trusted);
        assert!(dec.reasons.is_empty());
    }

    #[test]
    fn untrusted_when_disk_encryption_missing() {
        let policy = PosturePolicy::strict_baseline();
        let posture = PostureClaims {
            disk_encrypted: false,
            edr_present: true,
            screen_lock_minutes: Some(5),
            ..PostureClaims::default()
        };
        let dec = evaluate_policy(&policy, &posture);
        assert_eq!(dec.status, DeviceTrustStatus::Untrusted);
        assert!(dec.reasons.iter().any(|r| r.contains("disk encryption")));
    }

    #[test]
    fn untrusted_when_edr_missing_and_lock_unconfigured() {
        let policy = PosturePolicy::strict_baseline();
        let posture = PostureClaims {
            disk_encrypted: true,
            edr_present: false,
            screen_lock_minutes: None,
            ..PostureClaims::default()
        };
        let dec = evaluate_policy(&policy, &posture);
        assert_eq!(dec.status, DeviceTrustStatus::Untrusted);
        assert!(dec.reasons.iter().any(|r| r.contains("edr")));
        assert!(dec.reasons.iter().any(|r| r.contains("screen lock")));
    }

    #[test]
    fn os_block_list_rejects() {
        let mut policy = PosturePolicy::permissive();
        policy.os_block_list.push("Windows".into());
        let posture = PostureClaims::with_os("Windows");
        let dec = evaluate_policy(&policy, &posture);
        assert_eq!(dec.status, DeviceTrustStatus::Untrusted);
        assert!(dec.reasons.iter().any(|r| r.contains("block list")));
    }

    #[test]
    fn os_allow_list_excludes_unknown() {
        let mut policy = PosturePolicy::permissive();
        policy.os_allow_list.push("macOS".into());
        let posture = PostureClaims::with_os("Windows");
        let dec = evaluate_policy(&policy, &posture);
        assert_eq!(dec.status, DeviceTrustStatus::Untrusted);
    }

    #[test]
    fn min_os_version_enforced() {
        let mut policy = PosturePolicy::permissive();
        policy
            .minimum_os_versions
            .insert("macOS".into(), "14.5.0".into());
        let posture = PostureClaims {
            os_name: Some("macOS".into()),
            os_version: Some("14.4.0".into()),
            ..PostureClaims::default()
        };
        let dec = evaluate_policy(&policy, &posture);
        assert_eq!(dec.status, DeviceTrustStatus::Untrusted);
        assert!(dec.reasons.iter().any(|r| r.contains("14.4.0")));
    }

    #[test]
    fn edr_vendor_allow_list_enforced() {
        let mut policy = PosturePolicy::permissive();
        policy.edr_vendor_allow_list.push("CrowdStrike".into());
        let posture = PostureClaims {
            edr_present: true,
            edr_vendor: Some("UnknownEDR".into()),
            ..PostureClaims::default()
        };
        let dec = evaluate_policy(&policy, &posture);
        assert_eq!(dec.status, DeviceTrustStatus::Untrusted);
    }

    #[test]
    fn permissive_policy_trusts_anything() {
        let policy = PosturePolicy::permissive();
        let posture = PostureClaims::default();
        let dec = evaluate_policy(&policy, &posture);
        assert_eq!(dec.status, DeviceTrustStatus::Trusted);
    }

    #[tokio::test]
    async fn in_memory_round_trips_policy() {
        let svc = InMemoryDeviceTrustService::new();
        let p = PosturePolicy::strict_baseline();
        svc.put_policy(tenant(), p.clone()).await.unwrap();
        let got = svc.get_policy(tenant()).await.unwrap();
        assert_eq!(got, p);
    }

    #[tokio::test]
    async fn in_memory_evaluates_against_stored_policy() {
        let svc = InMemoryDeviceTrustService::new();
        svc.put_policy(tenant(), PosturePolicy::strict_baseline())
            .await
            .unwrap();
        let dec = svc
            .evaluate(
                tenant(),
                &PostureClaims {
                    disk_encrypted: false,
                    edr_present: false,
                    ..PostureClaims::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(dec.status, DeviceTrustStatus::Untrusted);
    }

    #[tokio::test]
    async fn snapshot_cap_is_enforced() {
        let svc = InMemoryDeviceTrustService::with_cap(2);
        for i in 0..5 {
            svc.record_snapshot(
                tenant(),
                PostureSnapshot {
                    id: format!("snap-{i}"),
                    user_id: "u".into(),
                    session_id: "s".into(),
                    status: DeviceTrustStatus::Trusted,
                    claims: PostureClaims::default(),
                    reasons: Vec::new(),
                    observed_at: "1970-01-01T00:00:00Z".into(),
                },
            )
            .await
            .unwrap();
        }
        let list = svc.list_snapshots(tenant(), 10).await.unwrap();
        assert_eq!(list.len(), 2);
        // Newest first; the last id pushed is "snap-4".
        assert_eq!(list.first().map(|s| s.id.as_str()), Some("snap-4"));
    }
}
