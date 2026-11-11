//! Pluggable admission rules.
//!
//! Each rule implements [`AdmissionRule::evaluate`] against a parsed
//! [`AdmissionRequest`] and either returns [`RuleOutcome::Pass`] or
//! [`RuleOutcome::Deny { reason }`]. The engine fans the request through
//! every active rule and short-circuits on the first deny so the
//! response carries a single, actionable message — operators reading
//! the `kubectl` error want one reason at a time, not a wall of text.
//!
//! ## Built-in rule pack
//!
//! HIGH-009 ships five rules covering the most common pod-security
//! posture violations:
//!
//! - [`NoPrivileged`] — refuses pods whose any container sets
//!   `securityContext.privileged: true`.
//! - [`NoHostNetwork`] — refuses pods that opt into the host network
//!   namespace (`spec.hostNetwork: true`), which is the classic
//!   container-breakout staging ground.
//! - [`NoLatestTag`] — refuses pods whose container image references
//!   the `:latest` tag (or omits a tag, which the runtime resolves to
//!   `:latest`).
//! - [`MandatoryLabels`] — refuses pods missing any of a
//!   per-tenant-configurable set of labels (compliance / cost
//!   attribution / ownership use case).
//! - [`PodSecurityStandard`] — enforces the upstream PSS profile
//!   ([`PssProfile::Restricted`] or [`PssProfile::Baseline`]).
//!
//! Every rule operates on the raw JSON object so it stays decoupled
//! from any `k8s-openapi` version drift — the apiserver guarantees the
//! shape it ships, and the rules look up the specific fields they
//! care about.

use serde_json::Value;

use super::types::AdmissionRequest;

/// Result of a single rule evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleOutcome {
    /// The rule did not object — the next rule may still deny.
    Pass,
    /// The rule denied the request. The `reason` is included verbatim
    /// in the deny response surfaced to `kubectl`.
    Deny {
        /// Human-readable message — prefixed by the rule's `id()`
        /// before being sent to the apiserver.
        reason: String,
    },
}

impl RuleOutcome {
    /// Convenience constructor for [`RuleOutcome::Deny`].
    #[must_use]
    pub fn deny(reason: impl Into<String>) -> Self {
        Self::Deny {
            reason: reason.into(),
        }
    }
}

/// One pluggable rule. Implementations MUST be cheap to evaluate —
/// the apiserver enforces a 10s admission webhook timeout and a single
/// request fans out through the entire rule pack.
pub trait AdmissionRule: Send + Sync + std::fmt::Debug {
    /// Stable identifier — used as the audit `rule_id` field and as the
    /// configuration key for per-tenant enable/disable.
    fn id(&self) -> &'static str;

    /// Evaluate the rule against `req`. Implementations MUST NOT mutate
    /// any global state; they read `req` and return a verdict.
    fn evaluate(&self, req: &AdmissionRequest) -> RuleOutcome;
}

/// Built-in: deny any pod whose any container declares
/// `securityContext.privileged: true`.
#[derive(Debug, Clone, Copy)]
pub struct NoPrivileged;

impl AdmissionRule for NoPrivileged {
    fn id(&self) -> &'static str {
        "no-privileged"
    }

    fn evaluate(&self, req: &AdmissionRequest) -> RuleOutcome {
        if !is_pod_kind(req) {
            return RuleOutcome::Pass;
        }
        let Some(obj) = req.object.as_ref() else {
            return RuleOutcome::Pass;
        };
        for container in iter_pod_containers(obj) {
            if container
                .get("securityContext")
                .and_then(|s| s.get("privileged"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                let name = container
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("<unnamed>");
                return RuleOutcome::deny(format!(
                    "container '{name}' requests privileged mode; \
                     privileged containers are not permitted by tenant policy",
                ));
            }
        }
        RuleOutcome::Pass
    }
}

/// Built-in: deny pods that opt into the host network namespace.
#[derive(Debug, Clone, Copy)]
pub struct NoHostNetwork;

impl AdmissionRule for NoHostNetwork {
    fn id(&self) -> &'static str {
        "no-host-network"
    }

    fn evaluate(&self, req: &AdmissionRequest) -> RuleOutcome {
        if !is_pod_kind(req) {
            return RuleOutcome::Pass;
        }
        let Some(obj) = req.object.as_ref() else {
            return RuleOutcome::Pass;
        };
        let host_network = pod_spec(obj)
            .and_then(|s| s.get("hostNetwork"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if host_network {
            RuleOutcome::deny(
                "spec.hostNetwork=true is forbidden — pods must use the cluster CNI namespace",
            )
        } else {
            RuleOutcome::Pass
        }
    }
}

/// Built-in: deny pods whose container image uses the `:latest` tag or
/// omits a tag entirely. Mutable image references are the #1 cause of
/// "the same manifest behaves differently on a redeploy" outages.
#[derive(Debug, Clone, Copy)]
pub struct NoLatestTag;

impl AdmissionRule for NoLatestTag {
    fn id(&self) -> &'static str {
        "no-latest-tag"
    }

    fn evaluate(&self, req: &AdmissionRequest) -> RuleOutcome {
        if !is_pod_kind(req) {
            return RuleOutcome::Pass;
        }
        let Some(obj) = req.object.as_ref() else {
            return RuleOutcome::Pass;
        };
        for container in iter_pod_containers(obj) {
            let Some(image) = container.get("image").and_then(Value::as_str) else {
                continue;
            };
            if image_uses_latest_or_no_tag(image) {
                let name = container
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("<unnamed>");
                return RuleOutcome::deny(format!(
                    "container '{name}' image '{image}' uses :latest (or no tag); \
                     pin to an immutable tag or digest",
                ));
            }
        }
        RuleOutcome::Pass
    }
}

/// Built-in: enforce a per-tenant set of mandatory labels on every Pod
/// (compliance / cost-attribution / ownership). Missing any one of the
/// configured keys is a deny.
#[derive(Debug, Clone)]
pub struct MandatoryLabels {
    required: Vec<String>,
}

impl MandatoryLabels {
    /// Build a `MandatoryLabels` rule from a deduplicated, non-empty
    /// `required` set. An empty set turns the rule into a no-op (every
    /// pod passes) — the engine still keeps it in the pack so an
    /// operator can swap the configuration in at runtime via the
    /// per-tenant policy without changing the rule wiring.
    #[must_use]
    pub fn new(required: Vec<String>) -> Self {
        let mut seen = Vec::with_capacity(required.len());
        for k in required {
            if !seen.iter().any(|existing: &String| existing == &k) {
                seen.push(k);
            }
        }
        Self { required: seen }
    }

    /// Read-only access to the configured required keys (for tests).
    #[must_use]
    pub fn required(&self) -> &[String] {
        &self.required
    }
}

impl AdmissionRule for MandatoryLabels {
    fn id(&self) -> &'static str {
        "mandatory-labels"
    }

    fn evaluate(&self, req: &AdmissionRequest) -> RuleOutcome {
        if self.required.is_empty() || !is_pod_kind(req) {
            return RuleOutcome::Pass;
        }
        let Some(obj) = req.object.as_ref() else {
            return RuleOutcome::Pass;
        };
        let labels = obj.get("metadata").and_then(|m| m.get("labels"));
        for required in &self.required {
            let present = labels
                .and_then(|l| l.get(required.as_str()))
                .and_then(Value::as_str)
                .is_some_and(|v| !v.is_empty());
            if !present {
                return RuleOutcome::deny(format!(
                    "missing mandatory label '{required}' (tenant compliance policy)",
                ));
            }
        }
        RuleOutcome::Pass
    }
}

/// Upstream Pod Security Standard profile.
///
/// - [`Restricted`](PssProfile::Restricted) — strictest; enforces every
///   restriction the upstream profile lists (no privileged, drop ALL,
///   `runAsNonRoot=true`, seccomp `RuntimeDefault`, no host
///   namespaces).
/// - [`Baseline`](PssProfile::Baseline) — broadly permissive; bans only
///   the most dangerous escapes (privileged, host namespaces).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PssProfile {
    /// `restricted` — the strictest PSS profile.
    Restricted,
    /// `baseline` — only refuses the most dangerous escapes.
    Baseline,
}

impl PssProfile {
    /// Parse a profile name (case-insensitive).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "restricted" => Some(Self::Restricted),
            "baseline" => Some(Self::Baseline),
            _ => None,
        }
    }

    /// Stable identifier for the rule and audit row.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Restricted => "restricted",
            Self::Baseline => "baseline",
        }
    }
}

/// Built-in: enforce a Pod Security Standard profile.
#[derive(Debug, Clone, Copy)]
pub struct PodSecurityStandard {
    /// Profile to enforce.
    pub profile: PssProfile,
}

impl PodSecurityStandard {
    /// Construct a `PodSecurityStandard` rule for `profile`.
    #[must_use]
    pub const fn new(profile: PssProfile) -> Self {
        Self { profile }
    }
}

impl AdmissionRule for PodSecurityStandard {
    fn id(&self) -> &'static str {
        match self.profile {
            PssProfile::Restricted => "pss-restricted",
            PssProfile::Baseline => "pss-baseline",
        }
    }

    #[allow(clippy::too_many_lines)] // PSS baseline+restricted: 12 banned controls + capability/seccomp/runAsUser checks fan out by design.
    fn evaluate(&self, req: &AdmissionRequest) -> RuleOutcome {
        if !is_pod_kind(req) {
            return RuleOutcome::Pass;
        }
        let Some(obj) = req.object.as_ref() else {
            return RuleOutcome::Pass;
        };
        let Some(spec) = pod_spec(obj) else {
            return RuleOutcome::Pass;
        };
        // Baseline: ban privileged, host namespaces, hostPath volumes,
        // hostPort.
        if spec
            .get("hostNetwork")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return RuleOutcome::deny(format!(
                "PSS {}: spec.hostNetwork=true is forbidden",
                self.profile.as_str(),
            ));
        }
        if spec
            .get("hostPID")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return RuleOutcome::deny(format!(
                "PSS {}: spec.hostPID=true is forbidden",
                self.profile.as_str(),
            ));
        }
        if spec
            .get("hostIPC")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return RuleOutcome::deny(format!(
                "PSS {}: spec.hostIPC=true is forbidden",
                self.profile.as_str(),
            ));
        }
        if let Some(volumes) = spec.get("volumes").and_then(Value::as_array) {
            for v in volumes {
                if v.get("hostPath").is_some() {
                    let name = v.get("name").and_then(Value::as_str).unwrap_or("<unnamed>");
                    return RuleOutcome::deny(format!(
                        "PSS {}: hostPath volume '{name}' is forbidden",
                        self.profile.as_str(),
                    ));
                }
            }
        }
        for container in iter_pod_containers(obj) {
            // Baseline + Restricted: no privileged containers.
            if container
                .get("securityContext")
                .and_then(|s| s.get("privileged"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                let name = container_name(container);
                return RuleOutcome::deny(format!(
                    "PSS {}: container '{name}' is privileged",
                    self.profile.as_str(),
                ));
            }
            // Baseline + Restricted: no `allowPrivilegeEscalation=true`.
            if container
                .get("securityContext")
                .and_then(|s| s.get("allowPrivilegeEscalation"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                let name = container_name(container);
                return RuleOutcome::deny(format!(
                    "PSS {}: container '{name}' sets allowPrivilegeEscalation=true",
                    self.profile.as_str(),
                ));
            }
            // Baseline + Restricted: no hostPort.
            if let Some(ports) = container.get("ports").and_then(Value::as_array) {
                for p in ports {
                    if let Some(hp) = p.get("hostPort").and_then(Value::as_i64) {
                        if hp != 0 {
                            let name = container_name(container);
                            return RuleOutcome::deny(format!(
                                "PSS {}: container '{name}' binds hostPort {hp}",
                                self.profile.as_str(),
                            ));
                        }
                    }
                }
            }
            // Restricted-only extras: runAsNonRoot, capabilities drop ALL,
            // seccompProfile RuntimeDefault, no procMount=Unmasked.
            if matches!(self.profile, PssProfile::Restricted) {
                let sec_ctx = container.get("securityContext");
                let run_as_non_root = sec_ctx
                    .and_then(|s| s.get("runAsNonRoot"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !run_as_non_root {
                    let name = container_name(container);
                    return RuleOutcome::deny(format!(
                        "PSS restricted: container '{name}' must set \
                         securityContext.runAsNonRoot=true",
                    ));
                }
                let caps_drop_all = sec_ctx
                    .and_then(|s| s.get("capabilities"))
                    .and_then(|c| c.get("drop"))
                    .and_then(Value::as_array)
                    .is_some_and(|arr| {
                        arr.iter()
                            .any(|v| v.as_str().is_some_and(|s| s.eq_ignore_ascii_case("ALL")))
                    });
                if !caps_drop_all {
                    let name = container_name(container);
                    return RuleOutcome::deny(format!(
                        "PSS restricted: container '{name}' must drop ALL capabilities",
                    ));
                }
                let seccomp_ok = sec_ctx
                    .and_then(|s| s.get("seccompProfile"))
                    .and_then(|p| p.get("type"))
                    .and_then(Value::as_str)
                    .is_some_and(|t| t == "RuntimeDefault" || t == "Localhost");
                if !seccomp_ok {
                    let name = container_name(container);
                    return RuleOutcome::deny(format!(
                        "PSS restricted: container '{name}' must set \
                         seccompProfile.type=RuntimeDefault (or Localhost)",
                    ));
                }
            }
        }
        RuleOutcome::Pass
    }
}

// ---------------------------------------------------------------------------
// JSON-path helpers — small, focused, all pure functions.
// ---------------------------------------------------------------------------

/// True when the inbound request targets a `Pod` (or a workload that
/// embeds a `PodSpec` via `spec.template`).
fn is_pod_kind(req: &AdmissionRequest) -> bool {
    req.kind.as_ref().is_none_or(|k| {
        let kind = k.kind.as_str();
        matches!(
            kind,
            "Pod" | "Deployment" | "ReplicaSet" | "StatefulSet" | "DaemonSet" | "Job" | "CronJob",
        )
    })
}

/// Extract the pod spec from a `Pod`, or the embedded pod-template
/// spec from a `Deployment`/`StatefulSet`/etc.
fn pod_spec(obj: &Value) -> Option<&Value> {
    if let Some(template) = obj
        .get("spec")
        .and_then(|s| s.get("template"))
        .and_then(|t| t.get("spec"))
    {
        return Some(template);
    }
    // Cron jobs embed the template one level deeper.
    if let Some(template) = obj
        .get("spec")
        .and_then(|s| s.get("jobTemplate"))
        .and_then(|t| t.get("spec"))
        .and_then(|s| s.get("template"))
        .and_then(|t| t.get("spec"))
    {
        return Some(template);
    }
    obj.get("spec")
}

/// Iterate every container declared on a pod-like object — both the
/// `containers` and the `initContainers` arrays.
fn iter_pod_containers(obj: &Value) -> Vec<&Value> {
    let mut out: Vec<&Value> = Vec::new();
    let Some(spec) = pod_spec(obj) else {
        return out;
    };
    if let Some(arr) = spec.get("containers").and_then(Value::as_array) {
        out.extend(arr.iter());
    }
    if let Some(arr) = spec.get("initContainers").and_then(Value::as_array) {
        out.extend(arr.iter());
    }
    if let Some(arr) = spec.get("ephemeralContainers").and_then(Value::as_array) {
        out.extend(arr.iter());
    }
    out
}

fn container_name(container: &Value) -> &str {
    container
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("<unnamed>")
}

/// True when the image reference uses `:latest` or omits a tag (which
/// the runtime treats as `:latest`). Digest-pinned references
/// (`name@sha256:...`) pass.
fn image_uses_latest_or_no_tag(image: &str) -> bool {
    // Digest-pinned references always pass.
    if image.contains('@') {
        return false;
    }
    // Split at the last `/` to separate registry/repo from name[:tag].
    let last = image.rsplit_once('/').map_or(image, |(_, t)| t);
    match last.rsplit_once(':') {
        None => true, // no tag at all
        Some((_, tag)) => tag.eq_ignore_ascii_case("latest") || tag.is_empty(),
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::match_wildcard_for_single_variants
)]
mod tests {
    use super::*;
    use crate::k8s_admission::types::GroupVersionKind;
    use serde_json::json;

    fn pod_request(pod_obj: Value) -> AdmissionRequest {
        AdmissionRequest {
            uid: "u-1".into(),
            kind: Some(GroupVersionKind {
                group: String::new(),
                version: "v1".into(),
                kind: "Pod".into(),
            }),
            name: Some("test".into()),
            namespace: Some("default".into()),
            operation: Some("CREATE".into()),
            object: Some(pod_obj),
            old_object: None,
            user_info: None,
            dry_run: Some(false),
        }
    }

    #[test]
    fn no_privileged_denies_privileged_container() {
        let req = pod_request(json!({
            "kind": "Pod",
            "metadata": {"name": "x"},
            "spec": {"containers": [
                {"name": "c1", "image": "nginx:1.25", "securityContext": {"privileged": true}}
            ]}
        }));
        let out = NoPrivileged.evaluate(&req);
        assert!(matches!(out, RuleOutcome::Deny { .. }));
    }

    #[test]
    fn no_privileged_passes_non_privileged() {
        let req = pod_request(json!({
            "kind": "Pod",
            "spec": {"containers": [
                {"name": "c1", "image": "nginx:1.25"}
            ]}
        }));
        assert_eq!(NoPrivileged.evaluate(&req), RuleOutcome::Pass);
    }

    #[test]
    fn no_host_network_denies_when_true() {
        let req = pod_request(json!({
            "spec": {"hostNetwork": true, "containers": []}
        }));
        let out = NoHostNetwork.evaluate(&req);
        assert!(matches!(out, RuleOutcome::Deny { .. }));
    }

    #[test]
    fn no_host_network_passes_when_false_or_missing() {
        let r1 = pod_request(json!({"spec": {"containers": []}}));
        let r2 = pod_request(json!({"spec": {"hostNetwork": false, "containers": []}}));
        assert_eq!(NoHostNetwork.evaluate(&r1), RuleOutcome::Pass);
        assert_eq!(NoHostNetwork.evaluate(&r2), RuleOutcome::Pass);
    }

    #[test]
    fn no_latest_tag_denies_latest_or_no_tag() {
        let cases = [
            ("nginx", true),
            ("nginx:latest", true),
            ("nginx:LATEST", true),
            ("docker.io/library/nginx:latest", true),
            ("registry.example/repo/img:latest", true),
            ("registry.example/repo/img:1.25.0", false),
            ("nginx@sha256:abc", false),
            ("nginx:1.25", false),
        ];
        for (img, expect_deny) in cases {
            let req = pod_request(json!({
                "spec": {"containers": [{"name": "c1", "image": img}]}
            }));
            let out = NoLatestTag.evaluate(&req);
            let denied = matches!(out, RuleOutcome::Deny { .. });
            assert_eq!(denied, expect_deny, "image='{img}'");
        }
    }

    #[test]
    fn mandatory_labels_denies_when_missing() {
        let req = pod_request(json!({
            "metadata": {"labels": {"app": "nginx"}},
            "spec": {"containers": []}
        }));
        let rule = MandatoryLabels::new(vec!["app".into(), "owner".into(), "cost-center".into()]);
        let out = rule.evaluate(&req);
        match out {
            RuleOutcome::Deny { reason } => assert!(reason.contains("owner")),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn mandatory_labels_deduplicates_required_keys() {
        let rule = MandatoryLabels::new(vec!["app".into(), "app".into(), "owner".into()]);
        assert_eq!(rule.required().len(), 2);
    }

    #[test]
    fn mandatory_labels_passes_when_all_present() {
        let req = pod_request(json!({
            "metadata": {"labels": {"app": "nginx", "owner": "platform"}},
            "spec": {"containers": []}
        }));
        let rule = MandatoryLabels::new(vec!["app".into(), "owner".into()]);
        assert_eq!(rule.evaluate(&req), RuleOutcome::Pass);
    }

    #[test]
    fn mandatory_labels_empty_set_is_noop() {
        let req = pod_request(json!({"spec": {"containers": []}}));
        let rule = MandatoryLabels::new(vec![]);
        assert_eq!(rule.evaluate(&req), RuleOutcome::Pass);
    }

    #[test]
    fn pss_baseline_blocks_host_network() {
        let req = pod_request(json!({"spec": {"hostNetwork": true, "containers": []}}));
        assert!(matches!(
            PodSecurityStandard::new(PssProfile::Baseline).evaluate(&req),
            RuleOutcome::Deny { .. }
        ));
    }

    #[test]
    fn pss_baseline_passes_compliant_pod() {
        let req = pod_request(json!({
            "spec": {"containers": [{"name": "c1", "image": "nginx:1.25"}]}
        }));
        assert_eq!(
            PodSecurityStandard::new(PssProfile::Baseline).evaluate(&req),
            RuleOutcome::Pass
        );
    }

    #[test]
    fn pss_restricted_requires_run_as_non_root() {
        let req = pod_request(json!({
            "spec": {"containers": [{"name": "c1", "image": "nginx:1.25"}]}
        }));
        let out = PodSecurityStandard::new(PssProfile::Restricted).evaluate(&req);
        match out {
            RuleOutcome::Deny { reason } => assert!(reason.contains("runAsNonRoot")),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn pss_restricted_requires_drop_all_capabilities() {
        let req = pod_request(json!({
            "spec": {"containers": [{
                "name": "c1",
                "image": "nginx:1.25",
                "securityContext": {"runAsNonRoot": true}
            }]}
        }));
        let out = PodSecurityStandard::new(PssProfile::Restricted).evaluate(&req);
        match out {
            RuleOutcome::Deny { reason } => assert!(reason.contains("drop ALL")),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn pss_restricted_requires_seccomp() {
        let req = pod_request(json!({
            "spec": {"containers": [{
                "name": "c1",
                "image": "nginx:1.25",
                "securityContext": {
                    "runAsNonRoot": true,
                    "capabilities": {"drop": ["ALL"]}
                }
            }]}
        }));
        let out = PodSecurityStandard::new(PssProfile::Restricted).evaluate(&req);
        match out {
            RuleOutcome::Deny { reason } => assert!(reason.contains("seccomp")),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn pss_restricted_passes_fully_compliant_pod() {
        let req = pod_request(json!({
            "spec": {"containers": [{
                "name": "c1",
                "image": "nginx:1.25",
                "securityContext": {
                    "runAsNonRoot": true,
                    "capabilities": {"drop": ["ALL"]},
                    "seccompProfile": {"type": "RuntimeDefault"}
                }
            }]}
        }));
        assert_eq!(
            PodSecurityStandard::new(PssProfile::Restricted).evaluate(&req),
            RuleOutcome::Pass
        );
    }

    #[test]
    fn pss_baseline_blocks_host_path_volume() {
        let req = pod_request(json!({
            "spec": {
                "volumes": [{"name": "data", "hostPath": {"path": "/etc"}}],
                "containers": []
            }
        }));
        let out = PodSecurityStandard::new(PssProfile::Baseline).evaluate(&req);
        match out {
            RuleOutcome::Deny { reason } => assert!(reason.contains("hostPath")),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn pss_baseline_blocks_host_port() {
        let req = pod_request(json!({
            "spec": {"containers": [{
                "name": "c1",
                "image": "nginx:1.25",
                "ports": [{"containerPort": 80, "hostPort": 8080}]
            }]}
        }));
        let out = PodSecurityStandard::new(PssProfile::Baseline).evaluate(&req);
        match out {
            RuleOutcome::Deny { reason } => assert!(reason.contains("hostPort")),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn deployment_template_pod_spec_is_evaluated() {
        // Workloads embed PodSpec under spec.template.spec — the engine
        // descends so the same rule pack catches a Deployment as it does
        // a bare Pod.
        let mut req = pod_request(json!({
            "kind": "Deployment",
            "spec": {"template": {"spec": {
                "hostNetwork": true,
                "containers": [{"name": "c1", "image": "nginx:1.25"}]
            }}}
        }));
        req.kind = Some(GroupVersionKind {
            group: "apps".into(),
            version: "v1".into(),
            kind: "Deployment".into(),
        });
        assert!(matches!(
            NoHostNetwork.evaluate(&req),
            RuleOutcome::Deny { .. }
        ));
    }

    #[test]
    fn pss_profile_parse_is_case_insensitive() {
        assert_eq!(
            PssProfile::parse("restricted"),
            Some(PssProfile::Restricted)
        );
        assert_eq!(PssProfile::parse(" Baseline "), Some(PssProfile::Baseline));
        assert_eq!(PssProfile::parse("nonsense"), None);
    }

    #[test]
    fn missing_object_passes_every_rule() {
        // DELETE has no `object`; rules MUST pass instead of panicking.
        let req = AdmissionRequest {
            uid: "u".into(),
            kind: Some(GroupVersionKind {
                group: String::new(),
                version: "v1".into(),
                kind: "Pod".into(),
            }),
            name: None,
            namespace: None,
            operation: Some("DELETE".into()),
            object: None,
            old_object: None,
            user_info: None,
            dry_run: None,
        };
        assert_eq!(NoPrivileged.evaluate(&req), RuleOutcome::Pass);
        assert_eq!(NoHostNetwork.evaluate(&req), RuleOutcome::Pass);
        assert_eq!(NoLatestTag.evaluate(&req), RuleOutcome::Pass);
        assert_eq!(
            MandatoryLabels::new(vec!["app".into()]).evaluate(&req),
            RuleOutcome::Pass
        );
        assert_eq!(
            PodSecurityStandard::new(PssProfile::Restricted).evaluate(&req),
            RuleOutcome::Pass
        );
    }
}
