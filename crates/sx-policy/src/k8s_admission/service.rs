//! Multi-tenant admission analyzer service.
//!
//! The service is a thin orchestration layer over [`rules::analyze`]: it
//! resolves the per-tenant [`AnalyzerConfig`] + [`ClusterRegistry`], runs the
//! rule set, records an [`AdmissionAuditRecord`] on the in-memory ring, and
//! returns a populated [`AdmissionResponse`]. The HTTP layer in `sx-api`
//! depends only on the [`K8sAdmissionService`] trait so a SQL-backed impl can
//! be wired up later without touching controllers.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use thiserror::Error;

use super::rules::{analyze, AnalyzerConfig};
use super::schema::{
    AdmissionAuditRecord, AdmissionRequest, AdmissionResponse, AdmissionReview, AdmissionStatus,
    ClusterRegistry, FindingSeverity, K8sAdmissionFinding, TypeMeta,
};

/// Maximum audit records retained per tenant (in-memory MVP).
pub const AUDIT_RING_CAPACITY: usize = 1024;

/// Errors returned by [`K8sAdmissionService`] implementations.
#[derive(Debug, Error)]
pub enum K8sAdmissionServiceError {
    /// The supplied review carried no `request` block.
    #[error("admission review carries no `request`")]
    MissingRequest,
    /// The supplied review carried no `request.object`.
    #[error("admission review request carries no `object`")]
    MissingObject,
    /// The caller named a cluster id the tenant has not registered.
    #[error("unknown cluster id `{0}` for tenant")]
    UnknownCluster(String),
    /// JSON payload failed to parse as an `AdmissionReview`.
    #[error("invalid JSON payload: {0}")]
    InvalidJson(String),
    /// Internal invariant broken — typically a poisoned mutex.
    #[error("internal: {0}")]
    Internal(String),
}

impl<T> From<PoisonError<T>> for K8sAdmissionServiceError {
    fn from(err: PoisonError<T>) -> Self {
        Self::Internal(format!("mutex poisoned: {err}"))
    }
}

/// Multi-tenant analyzer surface consumed by `sx-api`.
///
/// # HTTP integration sketch
///
/// The MVP exposes `POST /v1/k8s/admission/review` as a non-blocking analyzer.
/// A bare-bones axum handler over this trait looks like:
///
/// ```ignore
/// async fn review_handler(
///     State(svc): State<Arc<dyn K8sAdmissionService>>,
///     TenantScope(tenant_id): TenantScope,
///     Query(q): Query<ReviewQuery>,
///     Json(review): Json<AdmissionReview>,
/// ) -> Result<Json<AdmissionReview>, ApiError> {
///     let out = svc.review(&tenant_id, q.cluster_id.as_deref(), review).await?;
///     Ok(Json(out))
/// }
/// ```
///
/// The trait + DTOs are intentionally axum-free so this crate stays a pure
/// library — wiring lives in `sx-api` / `services/sx-monolith`.
#[async_trait]
pub trait K8sAdmissionService: Send + Sync {
    /// Run the rule set against `review` on behalf of `tenant_id`. When
    /// `cluster_id` is `Some(_)` the analyzer also enriches the audit record
    /// and verifies the cluster is registered for the tenant.
    async fn review(
        &self,
        tenant_id: &str,
        cluster_id: Option<&str>,
        review: AdmissionReview,
    ) -> Result<AdmissionReview, K8sAdmissionServiceError>;

    /// Replace the per-tenant analyzer config (trusted registries +
    /// disabled rule list).
    async fn set_config(
        &self,
        tenant_id: &str,
        config: AnalyzerConfig,
    ) -> Result<(), K8sAdmissionServiceError>;

    /// Read the per-tenant analyzer config (default if unset).
    async fn get_config(&self, tenant_id: &str)
        -> Result<AnalyzerConfig, K8sAdmissionServiceError>;

    /// Register (or rename) a cluster for this tenant.
    async fn upsert_cluster(
        &self,
        tenant_id: &str,
        cluster_id: &str,
        display_name: &str,
    ) -> Result<(), K8sAdmissionServiceError>;

    /// List the audit ring for `tenant_id`, most-recent first.
    async fn audit_log(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<AdmissionAuditRecord>, K8sAdmissionServiceError>;

    /// JSON-in / JSON-out wrapper around [`Self::review`]. Convenience for
    /// HTTP layers that don't want to depend on the typed DTOs directly.
    async fn review_json(
        &self,
        tenant_id: &str,
        cluster_id: Option<&str>,
        body: &[u8],
    ) -> Result<serde_json::Value, K8sAdmissionServiceError> {
        let review: AdmissionReview = serde_json::from_slice(body)
            .map_err(|e| K8sAdmissionServiceError::InvalidJson(e.to_string()))?;
        let out = self.review(tenant_id, cluster_id, review).await?;
        serde_json::to_value(out)
            .map_err(|e| K8sAdmissionServiceError::Internal(format!("serialize: {e}")))
    }
}

/// Source of "now" — injected so tests can pin timestamps.
pub trait Clock: Send + Sync {
    /// Current unix epoch seconds.
    fn now_unix(&self) -> i64;
}

/// `SystemTime`-backed clock used in production.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }
}

#[derive(Default)]
struct TenantState {
    config: AnalyzerConfig,
    clusters: ClusterRegistry,
    audit: std::collections::VecDeque<AdmissionAuditRecord>,
}

/// Default in-memory implementation. Suitable for tests and the MVP API.
pub struct InMemoryK8sAdmissionService {
    state: Mutex<BTreeMap<String, TenantState>>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for InMemoryK8sAdmissionService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryK8sAdmissionService").finish()
    }
}

impl Default for InMemoryK8sAdmissionService {
    fn default() -> Self {
        Self::new(Arc::new(SystemClock))
    }
}

impl InMemoryK8sAdmissionService {
    /// Construct a fresh service.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            state: Mutex::new(BTreeMap::new()),
            clock,
        }
    }

    // The closure body borrows from `guard` (via `entry`); we cannot drop the
    // lock earlier without invalidating that borrow.
    #[allow(clippy::significant_drop_tightening)]
    fn with_tenant<R>(
        &self,
        tenant_id: &str,
        f: impl FnOnce(&mut TenantState) -> R,
    ) -> Result<R, K8sAdmissionServiceError> {
        let mut guard = self.state.lock()?;
        let entry = guard.entry(tenant_id.to_owned()).or_default();
        Ok(f(entry))
    }
}

#[async_trait]
impl K8sAdmissionService for InMemoryK8sAdmissionService {
    async fn review(
        &self,
        tenant_id: &str,
        cluster_id: Option<&str>,
        review: AdmissionReview,
    ) -> Result<AdmissionReview, K8sAdmissionServiceError> {
        let request: AdmissionRequest = review
            .request
            .ok_or(K8sAdmissionServiceError::MissingRequest)?;
        let object = request
            .object
            .clone()
            .ok_or(K8sAdmissionServiceError::MissingObject)?;

        let (config, cluster_known) = self.with_tenant(tenant_id, |state| {
            let cluster_known = cluster_id.is_none_or(|cid| state.clusters.contains(cid));
            (state.config.clone(), cluster_known)
        })?;

        if !cluster_known {
            let cid = cluster_id.unwrap_or("");
            return Err(K8sAdmissionServiceError::UnknownCluster(cid.to_owned()));
        }

        let findings = analyze(&object, &config);
        let response = build_response(&request, findings.clone());
        let audit = build_audit(
            tenant_id,
            cluster_id,
            &request,
            &findings,
            self.clock.now_unix(),
        );

        self.with_tenant(tenant_id, |state| {
            if state.audit.len() >= AUDIT_RING_CAPACITY {
                state.audit.pop_front();
            }
            state.audit.push_back(audit.clone());
        })?;

        tracing::info!(
            target: "audit.k8s_admission",
            tenant_id = %tenant_id,
            cluster_id = ?cluster_id,
            review_uid = %audit.review_uid,
            kind = %audit.kind,
            namespace = %audit.namespace,
            name = %audit.name,
            findings = audit.finding_count,
            max_severity = %audit.max_severity,
            recommended_deny = audit.recommended_deny,
            "k8s admission review analyzed"
        );

        Ok(AdmissionReview {
            type_meta: TypeMeta {
                api_version: if review.type_meta.api_version.is_empty() {
                    "admission.k8s.io/v1".to_owned()
                } else {
                    review.type_meta.api_version
                },
                kind: if review.type_meta.kind.is_empty() {
                    "AdmissionReview".to_owned()
                } else {
                    review.type_meta.kind
                },
            },
            request: None,
            response: Some(response),
        })
    }

    async fn set_config(
        &self,
        tenant_id: &str,
        config: AnalyzerConfig,
    ) -> Result<(), K8sAdmissionServiceError> {
        self.with_tenant(tenant_id, |state| {
            state.config = config;
        })
    }

    async fn get_config(
        &self,
        tenant_id: &str,
    ) -> Result<AnalyzerConfig, K8sAdmissionServiceError> {
        self.with_tenant(tenant_id, |state| state.config.clone())
    }

    async fn upsert_cluster(
        &self,
        tenant_id: &str,
        cluster_id: &str,
        display_name: &str,
    ) -> Result<(), K8sAdmissionServiceError> {
        self.with_tenant(tenant_id, |state| {
            state.clusters.upsert(cluster_id, display_name);
        })
    }

    async fn audit_log(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<AdmissionAuditRecord>, K8sAdmissionServiceError> {
        self.with_tenant(tenant_id, |state| {
            state.audit.iter().rev().cloned().collect()
        })
    }
}

fn build_response(
    request: &AdmissionRequest,
    findings: Vec<K8sAdmissionFinding>,
) -> AdmissionResponse {
    let recommended_deny = findings.iter().any(|f| f.severity.is_blocking());
    let warnings = findings
        .iter()
        .map(|f| format!("[{}] {}: {}", f.severity.as_str(), f.rule_id, f.title))
        .collect::<Vec<_>>();
    let message = if findings.is_empty() {
        "no findings".to_owned()
    } else {
        format!(
            "{} finding(s); max severity = {}",
            findings.len(),
            findings
                .iter()
                .map(|f| f.severity)
                .max()
                .map_or("none", FindingSeverity::as_str),
        )
    };
    let code = if recommended_deny { 422 } else { 200 };
    AdmissionResponse {
        uid: request.uid.clone(),
        allowed: !recommended_deny,
        status: Some(AdmissionStatus { code, message }),
        warnings,
        findings,
    }
}

fn build_audit(
    tenant_id: &str,
    cluster_id: Option<&str>,
    request: &AdmissionRequest,
    findings: &[K8sAdmissionFinding],
    at_unix: i64,
) -> AdmissionAuditRecord {
    let max_severity = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .map_or("none", FindingSeverity::as_str)
        .to_owned();
    AdmissionAuditRecord {
        tenant_id: tenant_id.to_owned(),
        cluster_id: cluster_id.map(str::to_owned),
        review_uid: request.uid.clone(),
        kind: request.kind.kind.clone(),
        namespace: request.namespace.clone(),
        name: request.name.clone(),
        finding_count: findings.len(),
        max_severity,
        recommended_deny: findings.iter().any(|f| f.severity.is_blocking()),
        at_unix,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc
)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    #[derive(Debug, Default, Clone, Copy)]
    struct FixedClock(i64);
    impl Clock for FixedClock {
        fn now_unix(&self) -> i64 {
            self.0
        }
    }

    fn review_with_pod(uid: &str, namespace: &str, name: &str, object: Value) -> AdmissionReview {
        AdmissionReview {
            type_meta: TypeMeta {
                api_version: "admission.k8s.io/v1".to_owned(),
                kind: "AdmissionReview".to_owned(),
            },
            request: Some(AdmissionRequest {
                uid: uid.to_owned(),
                kind: super::super::schema::GroupVersionKind {
                    group: String::new(),
                    version: "v1".to_owned(),
                    kind: "Pod".to_owned(),
                },
                resource: super::super::schema::GroupVersionResource {
                    group: String::new(),
                    version: "v1".to_owned(),
                    resource: "pods".to_owned(),
                },
                user_info: super::super::schema::K8sUserInfo::default(),
                operation: "CREATE".to_owned(),
                namespace: namespace.to_owned(),
                name: name.to_owned(),
                object: Some(object),
                old_object: None,
            }),
            response: None,
        }
    }

    #[tokio::test]
    async fn review_emits_response_and_audit() {
        let svc = InMemoryK8sAdmissionService::new(Arc::new(FixedClock(1_700_000_000)));
        let object = json!({
            "kind": "Pod",
            "spec": {
                "hostNetwork": true,
                "containers": [{
                    "name": "evil", "image": "evil.example/x:latest",
                    "securityContext": { "privileged": true },
                }],
            },
        });
        let out = svc
            .review(
                "tenant-a",
                None,
                review_with_pod("u1", "ns", "evil", object),
            )
            .await
            .expect("review ok");
        let resp = out.response.expect("response set");
        assert_eq!(resp.uid, "u1");
        assert!(!resp.allowed, "deny expected");
        assert!(resp
            .findings
            .iter()
            .any(|f| f.rule_id == "k8s.pod.privileged"));

        let log = svc.audit_log("tenant-a").await.expect("audit");
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].review_uid, "u1");
        assert_eq!(log[0].max_severity, "critical");
        assert!(log[0].recommended_deny);
    }

    #[tokio::test]
    async fn review_rejects_unknown_cluster() {
        let svc = InMemoryK8sAdmissionService::new(Arc::new(FixedClock(0)));
        let object = json!({ "kind": "Pod", "spec": { "containers": [] } });
        let err = svc
            .review(
                "tenant-a",
                Some("cluster-x"),
                review_with_pod("u1", "ns", "p", object),
            )
            .await
            .expect_err("should error");
        matches!(err, K8sAdmissionServiceError::UnknownCluster(_));
    }

    #[tokio::test]
    async fn upsert_cluster_then_review_succeeds() {
        let svc = InMemoryK8sAdmissionService::new(Arc::new(FixedClock(0)));
        svc.upsert_cluster("tenant-a", "cluster-x", "prod-eu")
            .await
            .expect("upsert");
        let object = json!({
            "kind": "Pod",
            "spec": {
                "automountServiceAccountToken": false,
                "securityContext": {
                    "seccompProfile": { "type": "RuntimeDefault" },
                    "appArmorProfile": { "type": "RuntimeDefault" },
                    "runAsNonRoot": true,
                    "runAsUser": 1000,
                },
                "containers": [{
                    "name": "ok", "image": "gcr.io/foo/ok:1.2.3",
                    "resources": { "limits": { "cpu": "100m", "memory": "128Mi" } },
                    "securityContext": {
                        "allowPrivilegeEscalation": false,
                        "readOnlyRootFilesystem": true,
                        "capabilities": { "drop": ["ALL"] },
                    },
                }],
            },
        });
        let out = svc
            .review(
                "tenant-a",
                Some("cluster-x"),
                review_with_pod("u2", "ns", "ok", object),
            )
            .await
            .expect("ok");
        let resp = out.response.expect("resp");
        assert!(resp.allowed, "clean pod should be allowed: {resp:?}");
    }

    #[tokio::test]
    async fn tenant_isolation_holds() {
        let svc = InMemoryK8sAdmissionService::new(Arc::new(FixedClock(0)));
        let object = json!({ "kind": "Pod", "spec": { "containers": [{
            "name": "x", "image": "gcr.io/foo/x:1",
            "securityContext": { "privileged": true },
        }]}});
        svc.review(
            "tenant-a",
            None,
            review_with_pod("u1", "ns", "p", object.clone()),
        )
        .await
        .expect("ok");
        let a = svc.audit_log("tenant-a").await.expect("a");
        let b = svc.audit_log("tenant-b").await.expect("b");
        assert_eq!(a.len(), 1);
        assert!(b.is_empty(), "tenant-b must not see tenant-a audit");
    }

    #[tokio::test]
    async fn config_can_disable_rule() {
        let svc = InMemoryK8sAdmissionService::new(Arc::new(FixedClock(0)));
        let mut cfg = svc.get_config("tenant-a").await.expect("cfg");
        cfg.disabled_rules
            .push("k8s.container.latest_tag".to_owned());
        svc.set_config("tenant-a", cfg).await.expect("set");
        let object = json!({ "kind": "Pod", "spec": { "containers": [{
            "name": "x", "image": "gcr.io/foo/x:latest",
        }]}});
        let out = svc
            .review("tenant-a", None, review_with_pod("u1", "ns", "p", object))
            .await
            .expect("ok");
        let resp = out.response.expect("resp");
        assert!(!resp
            .findings
            .iter()
            .any(|f| f.rule_id == "k8s.container.latest_tag"));
    }

    #[tokio::test]
    async fn review_json_round_trips_via_serde() {
        let svc = InMemoryK8sAdmissionService::new(Arc::new(FixedClock(0)));
        let body = serde_json::to_vec(&review_with_pod(
            "u1",
            "ns",
            "evil",
            json!({
                "kind": "Pod",
                "spec": {
                    "containers": [{
                        "name": "x", "image": "evil.example/x:latest",
                        "securityContext": { "privileged": true },
                    }]
                }
            }),
        ))
        .expect("encode");
        let out = svc
            .review_json("tenant-a", None, &body)
            .await
            .expect("review_json");
        let findings = out
            .get("response")
            .and_then(|r| r.get("findings"))
            .and_then(Value::as_array)
            .expect("findings array");
        assert!(findings
            .iter()
            .any(|f| f.get("rule_id").and_then(Value::as_str) == Some("k8s.pod.privileged")));
    }

    #[tokio::test]
    async fn review_json_rejects_malformed_payload() {
        let svc = InMemoryK8sAdmissionService::new(Arc::new(FixedClock(0)));
        let err = svc
            .review_json("tenant-a", None, b"not json at all")
            .await
            .expect_err("should error");
        assert!(matches!(err, K8sAdmissionServiceError::InvalidJson(_)));
    }

    #[tokio::test]
    async fn audit_ring_caps_at_capacity() {
        let svc = InMemoryK8sAdmissionService::new(Arc::new(FixedClock(0)));
        let object = json!({ "kind": "Pod", "spec": { "containers": [] } });
        for i in 0..(AUDIT_RING_CAPACITY + 5) {
            let uid = format!("u{i}");
            svc.review(
                "tenant-a",
                None,
                review_with_pod(&uid, "ns", "p", object.clone()),
            )
            .await
            .expect("ok");
        }
        let log = svc.audit_log("tenant-a").await.expect("log");
        assert_eq!(log.len(), AUDIT_RING_CAPACITY);
    }
}
