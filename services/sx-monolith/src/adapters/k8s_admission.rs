//! Composition-root wiring for the HIGH-009 K8s admission webhook.
//!
//! The adapter constructs:
//!
//! - An [`InMemoryTenantRulePolicy`] seeded with the recommended rule
//!   pack as the default — operators override per-tenant by calling
//!   into [`InMemoryTenantRulePolicy::set_pack`] from the eventual
//!   `/v1/admin/runtime/k8s/policies` admin endpoint (out of scope for
//!   this task; the rule pack model already supports it).
//! - The [`AdmissionEngine`] wrapping that policy + a null audit sink.
//! - A small adapter type that bridges the engine to the
//!   [`sx_api::port::K8sAdmissionPort`] surface the controller binds to.
//!
//! Future work: the null audit sink is swappable for an
//! `sx-audit`-backed sink so admission decisions join the
//! tenant-wide hash-chain. The current null sink emits a `tracing::info!`
//! line per decision so operators still see the audit trail in stdout
//! during the gradual roll-out.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use sqlx::types::Json;
use sqlx::{PgPool, Row as _};
use sx_api::port::{K8sAdmissionPort, K8sAdmissionPortError};
use sx_api::view::k8s_admission_view::K8sAdmissionPolicyView;
use sx_discovery::k8s_admission::{
    audit::AuditSinkError, AdmissionEngine, AdmissionReview, AdmissionRule, K8sAdmissionAuditEvent,
    K8sAdmissionAuditSink, MandatoryLabels, NoHostNetwork, NoLatestTag, NoPrivileged,
    PodSecurityStandard, PssProfile, RulePack, TenantRulePolicy,
};

/// Tracing-based audit sink. The MVP wiring writes a structured event
/// per admission decision; the production deployment is expected to
/// swap this for a sink that forwards into `sx_audit::AuditSink` so
/// admission rows join the hash-chained tenant audit trail.
#[derive(Debug, Clone, Default)]
struct TracingAuditSink;

#[async_trait]
impl K8sAdmissionAuditSink for TracingAuditSink {
    async fn record(&self, event: K8sAdmissionAuditEvent) -> Result<(), AuditSinkError> {
        // INFO level — admission decisions are operationally interesting
        // (and the per-tenant 90-day retention requirement means the
        // sink WILL be wired to durable storage soon).
        tracing::info!(
            target: "sx_monolith::k8s_admission",
            tenant_id = %event.tenant_id,
            uid = %event.request_uid,
            kind = ?event.kind,
            namespace = ?event.namespace,
            operation = ?event.operation,
            decision = event.decision.as_str(),
            rule = ?event.rule_id,
            reason = ?event.reason,
            retention_days = event.retention_days,
            "k8s admission decision",
        );
        Ok(())
    }
}

/// Bundle returned by [`build`] / [`build_pg`].
#[derive(Clone)]
pub(crate) struct K8sAdmissionBundle {
    /// Trait-object port ready to be inserted into [`sx_api::AppState`].
    pub port: Arc<dyn K8sAdmissionPort>,
    /// Backing policy store — kept around for tests + the composition
    /// root. The admin endpoint mutates it through the port.
    #[allow(dead_code)]
    pub policy: Arc<MonolithK8sPolicy>,
}

impl std::fmt::Debug for K8sAdmissionBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("K8sAdmissionBundle").finish_non_exhaustive()
    }
}

/// Build the in-memory bundle (dev / no database). The default policy is
/// the recommended baseline (kube-system opt-out, PSS baseline, no
/// privileged, no host-network, no `:latest` tag); operator overrides live
/// only in memory and reset on restart.
pub(crate) fn build() -> K8sAdmissionBundle {
    let policy = Arc::new(MonolithK8sPolicy::new_default(None, 0));
    assemble(policy)
}

/// Build the durable bundle. Operator-authored admission policies are
/// persisted to `k8s_admission_policies` and reloaded into the engine at
/// boot, so a customised rule pack survives a restart instead of silently
/// reverting to the recommended baseline. Selected when the DB is enabled.
pub(crate) async fn build_pg(pool: PgPool, stmt_timeout_ms: u64) -> K8sAdmissionBundle {
    let policy = Arc::new(MonolithK8sPolicy::new_default(Some(pool), stmt_timeout_ms));
    if let Err(e) = policy.hydrate().await {
        tracing::warn!(
            target: "adapters.k8s_admission",
            error = %e,
            "failed to hydrate k8s admission policies from Postgres; starting from the recommended baseline",
        );
    }
    assemble(policy)
}

/// Wire the engine + port around a constructed policy store.
fn assemble(policy: Arc<MonolithK8sPolicy>) -> K8sAdmissionBundle {
    let engine = AdmissionEngine::new(
        Arc::clone(&policy) as Arc<dyn TenantRulePolicy>,
        Arc::new(TracingAuditSink),
    );
    let port: Arc<dyn K8sAdmissionPort> = Arc::new(EngineAdapter {
        engine,
        policy: Arc::clone(&policy),
    });
    K8sAdmissionBundle { port, policy }
}

/// The recommended baseline expressed as the declarative admin spec.
/// `spec_to_rulepack(&recommended_spec())` is identical to
/// [`RulePack::recommended`], so the default is unchanged — it is just
/// authored through the same shape the admin endpoint persists.
fn recommended_spec() -> K8sAdmissionPolicyView {
    K8sAdmissionPolicyView {
        pss_profile: Some("baseline".to_owned()),
        no_privileged: true,
        no_host_network: true,
        no_latest_tag: true,
        mandatory_labels: Vec::new(),
        namespace_optouts: vec![
            "kube-system".to_owned(),
            "kube-public".to_owned(),
            "kube-node-lease".to_owned(),
        ],
        dry_run: false,
    }
}

/// Reconstruct a [`RulePack`] (trait-object rules) from the serialisable
/// admin spec. Unknown PSS profiles fall back to `Baseline`.
fn spec_to_rulepack(spec: &K8sAdmissionPolicyView) -> RulePack {
    let mut rules: Vec<Arc<dyn AdmissionRule>> = Vec::new();
    if let Some(profile) = spec.pss_profile.as_deref() {
        let p = if profile.eq_ignore_ascii_case("restricted") {
            PssProfile::Restricted
        } else {
            PssProfile::Baseline
        };
        rules.push(Arc::new(PodSecurityStandard::new(p)));
    }
    if spec.no_privileged {
        rules.push(Arc::new(NoPrivileged));
    }
    if spec.no_host_network {
        rules.push(Arc::new(NoHostNetwork));
    }
    if spec.no_latest_tag {
        rules.push(Arc::new(NoLatestTag));
    }
    if !spec.mandatory_labels.is_empty() {
        rules.push(Arc::new(MandatoryLabels::new(
            spec.mandatory_labels.clone(),
        )));
    }
    RulePack {
        rules,
        namespace_optouts: spec
            .namespace_optouts
            .iter()
            .cloned()
            .collect::<HashSet<_>>(),
        dry_run: spec.dry_run,
    }
}

/// Monolith [`TenantRulePolicy`] with a durable (Postgres) spec store + an
/// in-memory cache the sync `for_tenant` hot path reads. Writes go
/// write-through (Pg + cache); the cache is hydrated from Pg at boot.
pub(crate) struct MonolithK8sPolicy {
    /// tenant_id -> authored spec (authoritative in-memory view).
    specs: RwLock<HashMap<String, K8sAdmissionPolicyView>>,
    /// Spec returned when a tenant has authored none (recommended).
    default_spec: K8sAdmissionPolicyView,
    /// `Some` when the DB is enabled.
    pool: Option<PgPool>,
    stmt_timeout_ms: u64,
}

impl std::fmt::Debug for MonolithK8sPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonolithK8sPolicy").finish_non_exhaustive()
    }
}

impl MonolithK8sPolicy {
    fn new_default(pool: Option<PgPool>, stmt_timeout_ms: u64) -> Self {
        Self {
            specs: RwLock::new(HashMap::new()),
            default_spec: recommended_spec(),
            pool,
            stmt_timeout_ms,
        }
    }

    fn dep(e: impl std::fmt::Display) -> K8sAdmissionPortError {
        K8sAdmissionPortError::Internal(format!("k8s admission policy store: {e}"))
    }

    /// Load every persisted policy into the in-memory cache.
    async fn hydrate(&self) -> Result<(), K8sAdmissionPortError> {
        let Some(pool) = self.pool.as_ref() else {
            return Ok(());
        };
        let rows = sqlx::query("SELECT tenant_id, spec FROM k8s_admission_policies")
            .fetch_all(pool)
            .await
            .map_err(Self::dep)?;
        let mut cache = self
            .specs
            .write()
            .map_err(|_| K8sAdmissionPortError::Internal("k8s policy cache poisoned".into()))?;
        for r in rows {
            let tenant: String = r.try_get("tenant_id").map_err(Self::dep)?;
            let spec = r
                .try_get::<Json<K8sAdmissionPolicyView>, _>("spec")
                .map(|j| j.0)
                .map_err(Self::dep)?;
            cache.insert(tenant, spec);
        }
        Ok(())
    }

    async fn set_policy(
        &self,
        tenant_id: &str,
        spec: K8sAdmissionPolicyView,
    ) -> Result<K8sAdmissionPolicyView, K8sAdmissionPortError> {
        if tenant_id.is_empty() {
            return Err(K8sAdmissionPortError::Invalid(
                "tenant_id is required".into(),
            ));
        }
        if let Some(pool) = self.pool.as_ref() {
            let bounded = self.stmt_timeout_ms.clamp(1, 60_000);
            let mut tx = pool.begin().await.map_err(Self::dep)?;
            sqlx::query(&format!("SET LOCAL statement_timeout = {bounded}"))
                .execute(&mut *tx)
                .await
                .map_err(Self::dep)?;
            sqlx::query(
                "INSERT INTO k8s_admission_policies (tenant_id, spec, updated_at) \
                 VALUES ($1, $2, now()) \
                 ON CONFLICT (tenant_id) DO UPDATE SET spec = EXCLUDED.spec, updated_at = now()",
            )
            .bind(tenant_id)
            .bind(Json(&spec))
            .execute(&mut *tx)
            .await
            .map_err(Self::dep)?;
            tx.commit().await.map_err(Self::dep)?;
        }
        self.specs
            .write()
            .map_err(|_| K8sAdmissionPortError::Internal("k8s policy cache poisoned".into()))?
            .insert(tenant_id.to_owned(), spec.clone());
        Ok(spec)
    }

    fn get_policy(&self, tenant_id: &str) -> Result<K8sAdmissionPolicyView, K8sAdmissionPortError> {
        let cache = self
            .specs
            .read()
            .map_err(|_| K8sAdmissionPortError::Internal("k8s policy cache poisoned".into()))?;
        Ok(cache
            .get(tenant_id)
            .cloned()
            .unwrap_or_else(|| self.default_spec.clone()))
    }
}

impl TenantRulePolicy for MonolithK8sPolicy {
    fn for_tenant(&self, tenant_id: &str) -> RulePack {
        let spec = self
            .specs
            .read()
            .ok()
            .and_then(|c| c.get(tenant_id).cloned())
            .unwrap_or_else(|| self.default_spec.clone());
        spec_to_rulepack(&spec)
    }
}

/// Trait-object bridge from [`AdmissionEngine`] + the policy store to the
/// [`K8sAdmissionPort`] the API layer binds against.
#[derive(Debug, Clone)]
struct EngineAdapter {
    engine: AdmissionEngine,
    policy: Arc<MonolithK8sPolicy>,
}

#[async_trait]
impl K8sAdmissionPort for EngineAdapter {
    async fn admit(
        &self,
        tenant_id: &str,
        review: AdmissionReview,
    ) -> Result<AdmissionReview, K8sAdmissionPortError> {
        self.engine
            .evaluate(tenant_id, review)
            .await
            .map_err(|e| K8sAdmissionPortError::Invalid(e.to_string()))
    }

    async fn get_policy(
        &self,
        tenant_id: &str,
    ) -> Result<K8sAdmissionPolicyView, K8sAdmissionPortError> {
        self.policy.get_policy(tenant_id)
    }

    async fn set_policy(
        &self,
        tenant_id: &str,
        policy: K8sAdmissionPolicyView,
    ) -> Result<K8sAdmissionPolicyView, K8sAdmissionPortError> {
        self.policy.set_policy(tenant_id, policy).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;
    use sx_discovery::k8s_admission::{AdmissionRequest, AdmissionReview, GroupVersionKind};

    fn pod_review(uid: &str, namespace: &str, object: serde_json::Value) -> AdmissionReview {
        AdmissionReview {
            api_version: "admission.k8s.io/v1".into(),
            kind: "AdmissionReview".into(),
            request: Some(AdmissionRequest {
                uid: uid.into(),
                kind: Some(GroupVersionKind {
                    group: String::new(),
                    version: "v1".into(),
                    kind: "Pod".into(),
                }),
                name: Some("nginx".into()),
                namespace: Some(namespace.into()),
                operation: Some("CREATE".into()),
                object: Some(object),
                old_object: None,
                user_info: None,
                dry_run: Some(false),
            }),
            response: None,
        }
    }

    #[tokio::test]
    async fn bundle_default_pack_denies_privileged_pod() {
        let bundle = build();
        let review = pod_review(
            "u-1",
            "default",
            json!({
                "spec": {"containers": [{
                    "name": "c",
                    "image": "nginx:1.25",
                    "securityContext": {"privileged": true}
                }]}
            }),
        );
        let resp = bundle.port.admit("t-a", review).await.unwrap();
        let r = resp.response.unwrap();
        assert!(!r.allowed, "recommended pack must deny privileged pods");
    }

    #[tokio::test]
    async fn bundle_default_pack_opts_out_kube_system() {
        let bundle = build();
        let review = pod_review(
            "u-2",
            "kube-system",
            json!({
                "spec": {"containers": [{
                    "name": "c",
                    "image": "nginx:1.25",
                    "securityContext": {"privileged": true}
                }]}
            }),
        );
        let resp = bundle.port.admit("t-a", review).await.unwrap();
        let r = resp.response.unwrap();
        assert!(r.allowed, "kube-system must be opted out");
    }

    #[test]
    fn recommended_spec_reconstructs_the_recommended_pack() {
        // The declarative default must reproduce RulePack::recommended()'s
        // namespace opt-outs + rule set so the baseline is unchanged.
        let pack = spec_to_rulepack(&recommended_spec());
        assert!(pack.is_namespace_optout("kube-system"));
        assert!(pack.is_namespace_optout("kube-public"));
        assert!(pack.is_namespace_optout("kube-node-lease"));
        assert!(!pack.is_namespace_optout("default"));
        assert_eq!(pack.rules.len(), RulePack::recommended().rules.len());
        assert!(!pack.dry_run);
    }

    /// Durability proof against a real Postgres: an operator-authored
    /// admission policy survives a *fresh bundle (restart-equivalent)* via
    /// boot hydration — `get_policy` returns it and the engine enforces it;
    /// an unconfigured tenant still reads the recommended baseline. Gated
    /// on `TEST_DATABASE_URL` (silent no-op in CI).
    #[tokio::test]
    async fn pg_k8s_policy_survives_restart() {
        #[allow(clippy::disallowed_methods)]
        let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
            return;
        };
        let tenant = uuid::Uuid::new_v4().to_string();
        let strict = K8sAdmissionPolicyView {
            pss_profile: Some("restricted".to_owned()),
            no_privileged: true,
            no_host_network: true,
            no_latest_tag: true,
            mandatory_labels: vec!["app".to_owned()],
            namespace_optouts: Vec::new(),
            dry_run: false,
        };

        // Process 1: author the policy.
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("connect");
            let bundle = build_pg(pool, 15_000).await;
            let stored = bundle
                .port
                .set_policy(&tenant, strict.clone())
                .await
                .expect("set policy");
            assert_eq!(stored, strict);
        }

        // Process 2 (fresh bundle): hydrated from Pg.
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("reconnect");
            let bundle = build_pg(pool, 15_000).await;
            let got = bundle.port.get_policy(&tenant).await.expect("get policy");
            assert_eq!(got, strict, "policy survived restart");

            // Unconfigured tenant → recommended baseline.
            let other = uuid::Uuid::new_v4().to_string();
            let def = bundle.port.get_policy(&other).await.expect("default");
            assert_eq!(def.pss_profile.as_deref(), Some("baseline"));
            assert!(def.no_privileged);

            // The restored policy is enforced: a privileged pod in a
            // non-opted-out namespace is denied.
            let review = pod_review(
                "u-r",
                "default",
                json!({
                    "spec": {"containers": [{
                        "name": "c",
                        "image": "nginx:1.25",
                        "securityContext": {"privileged": true}
                    }]}
                }),
            );
            let resp = bundle.port.admit(&tenant, review).await.expect("admit");
            assert!(
                !resp.response.unwrap().allowed,
                "privileged pod denied under the restored policy"
            );
        }

        // Cleanup (no RLS on this table).
        {
            let pool = sqlx::PgPool::connect(&url).await.expect("reconnect");
            sqlx::query("DELETE FROM k8s_admission_policies WHERE tenant_id = $1")
                .bind(&tenant)
                .execute(&pool)
                .await
                .expect("cleanup");
        }
    }
}
