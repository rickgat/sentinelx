//! Admission engine — entry point for the webhook controller.
//!
//! The engine pulls four moving parts together:
//!
//! 1. The [`super::policy::TenantRulePolicy`] — resolved per-tenant.
//! 2. The [`super::rules::AdmissionRule`] pack carried by the resolved
//!    [`super::policy::RulePack`].
//! 3. The [`super::audit::K8sAdmissionAuditSink`] — one row per decision.
//! 4. The [`super::types::AdmissionReview`] envelope on the wire.
//!
//! Flow per request:
//!
//! - Reject early when the envelope has no `request` block (malformed
//!   `AdmissionReview`; the apiserver should never send this, but we do
//!   not panic).
//! - Resolve the rule pack for `tenant_id`.
//! - If the request's namespace is in `pack.namespace_optouts`,
//!   short-circuit `allow=true` with a `namespace_optout` rule id in
//!   the audit row — never consult any rule.
//! - Evaluate every rule in pack order. The **first** [`super::rules::RuleOutcome::Deny`]
//!   short-circuits — the response carries that single reason.
//! - Honour `pack.dry_run`: when set, the engine still records the
//!   would-be-deny in the audit row (decision =
//!   [`super::audit::K8sAdmissionDecision::DryRunWouldDeny`]) and
//!   surfaces it as a `warnings[]` entry on the response, but still
//!   returns `allowed=true`.

use std::sync::Arc;

use super::audit::{K8sAdmissionAuditEvent, K8sAdmissionAuditSink, K8sAdmissionDecision};
use super::policy::TenantRulePolicy;
use super::rules::RuleOutcome;
use super::types::{AdmissionRequest, AdmissionResponse, AdmissionReview};

/// Errors returned by [`AdmissionEngine::evaluate`].
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// The inbound `AdmissionReview` envelope had no `request` block.
    #[error("AdmissionReview is missing the 'request' field")]
    MissingRequest,
    /// The inbound envelope is wired but the version is not the v1
    /// admission API the engine understands.
    #[error("unsupported AdmissionReview apiVersion: {0}")]
    UnsupportedVersion(String),
}

/// Engine — fans an [`AdmissionReview`] through the tenant's active
/// rule pack and returns the response envelope.
#[derive(Clone)]
pub struct AdmissionEngine {
    policy: Arc<dyn TenantRulePolicy>,
    audit: Arc<dyn K8sAdmissionAuditSink>,
}

impl std::fmt::Debug for AdmissionEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmissionEngine")
            .field("policy", &self.policy)
            .field("audit", &self.audit)
            .finish()
    }
}

impl AdmissionEngine {
    /// Construct a new engine.
    #[must_use]
    pub fn new(policy: Arc<dyn TenantRulePolicy>, audit: Arc<dyn K8sAdmissionAuditSink>) -> Self {
        Self { policy, audit }
    }

    /// Evaluate `review` for `tenant_id` and return the response
    /// envelope. The engine also writes one audit row per decision via
    /// the configured sink; audit-sink errors are logged but never
    /// surfaced — failing closed on audit failure would brick the
    /// cluster.
    ///
    /// # Errors
    /// - [`EngineError::MissingRequest`] when the envelope lacks the
    ///   `request` field.
    /// - [`EngineError::UnsupportedVersion`] when the envelope carries
    ///   an `apiVersion` other than `admission.k8s.io/v1`.
    pub async fn evaluate(
        &self,
        tenant_id: &str,
        review: AdmissionReview,
    ) -> Result<AdmissionReview, EngineError> {
        if review.api_version != "admission.k8s.io/v1" {
            return Err(EngineError::UnsupportedVersion(review.api_version));
        }
        let request = review.request.ok_or(EngineError::MissingRequest)?;
        let response = self.evaluate_request(tenant_id, &request).await;
        Ok(AdmissionReview::response(response))
    }

    /// Evaluate the parsed [`AdmissionRequest`] directly. Useful in
    /// tests that want to skip envelope parsing.
    pub async fn evaluate_request(
        &self,
        tenant_id: &str,
        request: &AdmissionRequest,
    ) -> AdmissionResponse {
        let pack = self.policy.for_tenant(tenant_id);

        // Namespace opt-out: short-circuit with allow, write a one-line
        // audit row attributing the allow to the opt-out, and skip rule
        // evaluation entirely.
        if let Some(ns) = request.namespace.as_deref() {
            if pack.is_namespace_optout(ns) {
                self.record(K8sAdmissionAuditEvent::new(
                    tenant_id,
                    request,
                    K8sAdmissionDecision::Allow,
                    Some("namespace_optout".to_owned()),
                    Some(format!(
                        "namespace '{ns}' is in the per-tenant opt-out list"
                    )),
                ))
                .await;
                return AdmissionResponse::allow(&request.uid);
            }
        }

        // Walk the pack. First deny wins.
        for rule in &pack.rules {
            match rule.evaluate(request) {
                RuleOutcome::Pass => {}
                RuleOutcome::Deny { reason } => {
                    let formatted = format!("[{}] {}", rule.id(), reason);
                    if pack.dry_run {
                        // Dry-run: emit warning, record would-deny,
                        // return allow.
                        self.record(K8sAdmissionAuditEvent::new(
                            tenant_id,
                            request,
                            K8sAdmissionDecision::DryRunWouldDeny,
                            Some(rule.id().to_owned()),
                            Some(formatted.clone()),
                        ))
                        .await;
                        return AdmissionResponse::allow(&request.uid)
                            .with_warnings(vec![format!("[dry-run] would-deny: {formatted}")]);
                    }
                    // Enforcing: record deny, return deny.
                    self.record(K8sAdmissionAuditEvent::new(
                        tenant_id,
                        request,
                        K8sAdmissionDecision::Deny,
                        Some(rule.id().to_owned()),
                        Some(formatted.clone()),
                    ))
                    .await;
                    return AdmissionResponse::deny(&request.uid, formatted);
                }
            }
        }

        // No rule denied → allow.
        self.record(K8sAdmissionAuditEvent::new(
            tenant_id,
            request,
            K8sAdmissionDecision::Allow,
            None,
            None,
        ))
        .await;
        AdmissionResponse::allow(&request.uid)
    }

    /// Best-effort write. Errors are logged and dropped — the apiserver
    /// must never observe an admission failure caused by an audit-sink
    /// hiccup.
    async fn record(&self, event: K8sAdmissionAuditEvent) {
        if let Err(err) = self.audit.record(event).await {
            tracing::warn!(
                target: "sx_discovery::k8s_admission",
                error = %err,
                "admission audit sink failed; failing open to preserve cluster availability",
            );
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::k8s_admission::audit::RecordingK8sAdmissionAuditSink;
    use crate::k8s_admission::policy::{InMemoryTenantRulePolicy, RulePack};
    use crate::k8s_admission::rules::{
        MandatoryLabels, NoHostNetwork, NoLatestTag, NoPrivileged, PodSecurityStandard, PssProfile,
    };
    use crate::k8s_admission::types::GroupVersionKind;
    use serde_json::json;
    use std::sync::Arc;

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

    fn engine_with(pack: RulePack) -> (AdmissionEngine, Arc<RecordingK8sAdmissionAuditSink>) {
        let policy = InMemoryTenantRulePolicy::new();
        policy.set_default(pack);
        let sink = Arc::new(RecordingK8sAdmissionAuditSink::new());
        let engine = AdmissionEngine::new(Arc::new(policy), sink.clone());
        (engine, sink)
    }

    #[tokio::test]
    async fn missing_request_returns_engine_error() {
        let (engine, _sink) = engine_with(RulePack::empty());
        let review = AdmissionReview {
            api_version: "admission.k8s.io/v1".into(),
            kind: "AdmissionReview".into(),
            request: None,
            response: None,
        };
        let err = engine.evaluate("t-a", review).await.unwrap_err();
        assert!(matches!(err, EngineError::MissingRequest));
    }

    #[tokio::test]
    async fn unsupported_version_rejected() {
        let (engine, _sink) = engine_with(RulePack::empty());
        let mut review = pod_review("u", "default", json!({"spec": {"containers": []}}));
        review.api_version = "admission.k8s.io/v1beta1".into();
        let err = engine.evaluate("t-a", review).await.unwrap_err();
        assert!(matches!(err, EngineError::UnsupportedVersion(_)));
    }

    #[tokio::test]
    async fn empty_pack_allows_everything_and_audits_allow() {
        let (engine, sink) = engine_with(RulePack::empty());
        let review = pod_review(
            "u-1",
            "default",
            json!({"spec": {"containers": [{"name": "c", "image": "nginx:1.25", "securityContext": {"privileged": true}}]}}),
        );
        let resp = engine.evaluate("t-a", review).await.unwrap();
        let r = resp.response.expect("response present");
        assert!(r.allowed);
        assert_eq!(sink.len(), 1);
        assert_eq!(sink.events()[0].decision, K8sAdmissionDecision::Allow);
    }

    #[tokio::test]
    async fn namespace_optout_short_circuits_with_audit_marker() {
        let mut pack = RulePack::empty();
        pack.rules = vec![Arc::new(NoPrivileged)];
        pack.namespace_optouts.insert("kube-system".to_owned());
        let (engine, sink) = engine_with(pack);
        let review = pod_review(
            "u-2",
            "kube-system",
            json!({"spec": {"containers": [{"name": "c", "image": "nginx:1.25", "securityContext": {"privileged": true}}]}}),
        );
        let resp = engine.evaluate("t-a", review).await.unwrap();
        let r = resp.response.unwrap();
        assert!(
            r.allowed,
            "kube-system opt-out should override even a privileged pod"
        );
        let ev = &sink.events()[0];
        assert_eq!(ev.decision, K8sAdmissionDecision::Allow);
        assert_eq!(ev.rule_id.as_deref(), Some("namespace_optout"));
    }

    #[tokio::test]
    async fn first_deny_short_circuits_remaining_rules() {
        let mut pack = RulePack::empty();
        // NoPrivileged first; we'd never reach the latest-tag rule.
        pack.rules = vec![Arc::new(NoPrivileged), Arc::new(NoLatestTag)];
        let (engine, sink) = engine_with(pack);
        let review = pod_review(
            "u-3",
            "default",
            json!({"spec": {"containers": [
                {"name": "c", "image": "nginx:latest", "securityContext": {"privileged": true}}
            ]}}),
        );
        let resp = engine.evaluate("t-a", review).await.unwrap();
        let r = resp.response.unwrap();
        assert!(!r.allowed);
        let s = r.status.expect("status present on deny");
        assert_eq!(s.code, 403);
        assert!(
            s.message.contains("no-privileged"),
            "first deny wins: {}",
            s.message
        );
        let ev = &sink.events()[0];
        assert_eq!(ev.decision, K8sAdmissionDecision::Deny);
        assert_eq!(ev.rule_id.as_deref(), Some("no-privileged"));
    }

    #[tokio::test]
    async fn dry_run_returns_allow_with_warning_and_records_would_deny() {
        let mut pack = RulePack::empty();
        pack.rules = vec![Arc::new(NoHostNetwork)];
        pack.dry_run = true;
        let (engine, sink) = engine_with(pack);
        let review = pod_review(
            "u-4",
            "default",
            json!({"spec": {"hostNetwork": true, "containers": []}}),
        );
        let resp = engine.evaluate("t-a", review).await.unwrap();
        let r = resp.response.unwrap();
        assert!(r.allowed, "dry-run must always allow");
        let warnings = r.warnings.expect("warnings present on dry-run would-deny");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("would-deny"));
        let ev = &sink.events()[0];
        assert_eq!(ev.decision, K8sAdmissionDecision::DryRunWouldDeny);
        assert_eq!(ev.rule_id.as_deref(), Some("no-host-network"));
    }

    #[tokio::test]
    async fn per_tenant_packs_resolve_independently() {
        let policy = InMemoryTenantRulePolicy::new();
        policy.set_default(RulePack::empty()); // default: permissive
        let mut strict = RulePack::empty();
        strict.rules = vec![Arc::new(NoPrivileged)];
        policy.set_pack("t-strict", strict);
        let sink = Arc::new(RecordingK8sAdmissionAuditSink::new());
        let engine = AdmissionEngine::new(Arc::new(policy), sink.clone());

        let pod = json!({"spec": {"containers": [
            {"name": "c", "image": "nginx:1.25", "securityContext": {"privileged": true}}
        ]}});

        // Permissive tenant: allow.
        let resp_permissive = engine
            .evaluate("t-other", pod_review("u-a", "default", pod.clone()))
            .await
            .unwrap();
        assert!(resp_permissive.response.unwrap().allowed);

        // Strict tenant: deny.
        let resp_strict = engine
            .evaluate("t-strict", pod_review("u-b", "default", pod.clone()))
            .await
            .unwrap();
        assert!(!resp_strict.response.unwrap().allowed);
    }

    #[tokio::test]
    async fn pss_baseline_pack_denies_privileged_pod() {
        let mut pack = RulePack::empty();
        pack.rules = vec![Arc::new(PodSecurityStandard::new(PssProfile::Baseline))];
        let (engine, _sink) = engine_with(pack);
        let review = pod_review(
            "u",
            "default",
            json!({"spec": {"containers": [
                {"name": "c", "image": "nginx:1.25", "securityContext": {"privileged": true}}
            ]}}),
        );
        let resp = engine.evaluate("t-a", review).await.unwrap();
        let r = resp.response.unwrap();
        assert!(!r.allowed);
        assert!(r.status.unwrap().message.contains("pss-baseline"));
    }

    #[tokio::test]
    async fn pss_restricted_requires_full_compliance() {
        let mut pack = RulePack::empty();
        pack.rules = vec![Arc::new(PodSecurityStandard::new(PssProfile::Restricted))];
        let (engine, _sink) = engine_with(pack);
        let compliant = json!({"spec": {"containers": [{
            "name": "c",
            "image": "nginx:1.25",
            "securityContext": {
                "runAsNonRoot": true,
                "capabilities": {"drop": ["ALL"]},
                "seccompProfile": {"type": "RuntimeDefault"}
            }
        }]}});
        let resp = engine
            .evaluate("t-a", pod_review("u", "default", compliant))
            .await
            .unwrap();
        assert!(resp.response.unwrap().allowed);
    }

    #[tokio::test]
    async fn mandatory_labels_deny_carries_rule_id_in_response() {
        let mut pack = RulePack::empty();
        pack.rules = vec![Arc::new(MandatoryLabels::new(vec![
            "app".into(),
            "owner".into(),
        ]))];
        let (engine, _sink) = engine_with(pack);
        let review = pod_review(
            "u",
            "default",
            json!({
                "metadata": {"labels": {"app": "nginx"}},
                "spec": {"containers": []}
            }),
        );
        let resp = engine.evaluate("t-a", review).await.unwrap();
        let r = resp.response.unwrap();
        assert!(!r.allowed);
        let s = r.status.unwrap();
        assert!(s.message.contains("mandatory-labels"));
        assert!(s.message.contains("owner"));
    }

    #[tokio::test]
    async fn audit_record_attaches_request_payload_for_investigation() {
        let mut pack = RulePack::empty();
        pack.rules = vec![Arc::new(NoLatestTag)];
        let (engine, sink) = engine_with(pack);
        let review = pod_review(
            "u-9",
            "default",
            json!({"spec": {"containers": [{"name": "c", "image": "nginx:latest"}]}}),
        );
        let _ = engine.evaluate("t-a", review).await.unwrap();
        let ev = &sink.events()[0];
        // The full sanitised request is retained for investigation.
        assert!(ev.request.object.is_some());
        assert_eq!(ev.retention_days, 90);
    }
}
