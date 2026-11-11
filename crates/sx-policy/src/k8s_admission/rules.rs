//! Deterministic rule set for the K8s admission analyzer.
//!
//! Each rule walks `request.object` (the candidate Pod / Deployment /
//! `DaemonSet` / `StatefulSet` / Job / `CronJob`) and emits zero or more
//! [`K8sAdmissionFinding`]s. Rules are pure: same input → same output.
//!
//! Pod templates are resolved transparently — a Deployment, `DaemonSet`,
//! `StatefulSet`, Job or `CronJob` is reduced to its embedded
//! `spec.template.spec` (`CronJobs` go through `spec.jobTemplate.spec.template.spec`)
//! so a single rule body covers every workload kind.

use serde_json::Value;

use super::schema::{FindingSeverity, K8sAdmissionFinding};

/// Static rule descriptor — id + severity + title + references.
#[derive(Debug, Clone, Copy)]
pub struct RuleSpec {
    /// Stable id, e.g. `"k8s.pod.privileged"`.
    pub id: &'static str,
    /// Severity bucket.
    pub severity: FindingSeverity,
    /// Short title surfaced in the dashboard.
    pub title: &'static str,
    /// External references (CIS K8s, NSA, MITRE ATT&CK).
    pub references: &'static [&'static str],
}

/// All built-in rule descriptors. Order is the order findings are reported in.
pub const BUILTIN_RULES: &[RuleSpec] = &[
    RuleSpec {
        id: "k8s.pod.privileged",
        severity: FindingSeverity::Critical,
        title: "Privileged container",
        references: &[
            "CIS-K8s-5.2.1",
            "NSA-Kubernetes-Hardening-Pod-Security",
            "MITRE-T1611",
        ],
    },
    RuleSpec {
        id: "k8s.pod.host_network",
        severity: FindingSeverity::High,
        title: "Pod uses host network",
        references: &["CIS-K8s-5.2.4", "NSA-Kubernetes-Hardening-Network-Policy"],
    },
    RuleSpec {
        id: "k8s.pod.host_pid",
        severity: FindingSeverity::High,
        title: "Pod uses host PID namespace",
        references: &["CIS-K8s-5.2.2"],
    },
    RuleSpec {
        id: "k8s.pod.host_ipc",
        severity: FindingSeverity::High,
        title: "Pod uses host IPC namespace",
        references: &["CIS-K8s-5.2.3"],
    },
    RuleSpec {
        id: "k8s.pod.host_path",
        severity: FindingSeverity::High,
        title: "Pod mounts a hostPath volume",
        references: &["CIS-K8s-5.2.9", "MITRE-T1610"],
    },
    RuleSpec {
        id: "k8s.container.dangerous_capability",
        severity: FindingSeverity::Critical,
        title: "Container adds NET_ADMIN / SYS_ADMIN capability",
        references: &["CIS-K8s-5.2.8", "NSA-Kubernetes-Hardening-Pod-Security"],
    },
    RuleSpec {
        id: "k8s.container.missing_seccomp",
        severity: FindingSeverity::Medium,
        title: "Container has no seccomp profile",
        references: &["CIS-K8s-5.7.2", "NSA-Kubernetes-Hardening-Pod-Security"],
    },
    RuleSpec {
        id: "k8s.container.missing_apparmor",
        severity: FindingSeverity::Medium,
        title: "Container has no AppArmor profile",
        references: &["CIS-K8s-5.7.2"],
    },
    RuleSpec {
        id: "k8s.pod.unsafe_sysctl",
        severity: FindingSeverity::High,
        title: "Pod sets an unsafe sysctl",
        references: &["CIS-K8s-5.2.10"],
    },
    RuleSpec {
        id: "k8s.container.untrusted_registry",
        severity: FindingSeverity::High,
        title: "Container pulls image from an untrusted registry",
        references: &["NSA-Kubernetes-Hardening-Supply-Chain"],
    },
    RuleSpec {
        id: "k8s.container.latest_tag",
        severity: FindingSeverity::Medium,
        title: "Container image uses `:latest` tag",
        references: &["CIS-K8s-5.1.3"],
    },
    RuleSpec {
        id: "k8s.container.missing_resource_limits",
        severity: FindingSeverity::Low,
        title: "Container missing CPU/memory resource limits",
        references: &["CIS-K8s-5.7.4"],
    },
    RuleSpec {
        id: "k8s.container.run_as_root",
        severity: FindingSeverity::High,
        title: "Container runs as root (uid 0)",
        references: &["CIS-K8s-5.2.6", "NSA-Kubernetes-Hardening-Pod-Security"],
    },
    RuleSpec {
        id: "k8s.container.allow_privilege_escalation",
        severity: FindingSeverity::High,
        title: "Container allows privilege escalation",
        references: &["CIS-K8s-5.2.5"],
    },
    RuleSpec {
        id: "k8s.container.read_only_root_fs_disabled",
        severity: FindingSeverity::Medium,
        title: "Container root filesystem is writable",
        references: &["CIS-K8s-5.2.7"],
    },
    RuleSpec {
        id: "k8s.pod.automount_sa_token_default",
        severity: FindingSeverity::Medium,
        title: "Pod auto-mounts the default ServiceAccount token",
        references: &["CIS-K8s-5.1.5", "NSA-Kubernetes-Hardening-RBAC"],
    },
];

/// Configuration knobs that the per-tenant policy can flip.
#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    /// Allow-list of trusted registry prefixes. An image whose registry host
    /// does **not** start with one of these triggers
    /// `k8s.container.untrusted_registry`. When empty the rule is skipped.
    pub trusted_registries: Vec<String>,
    /// Rule ids the tenant has explicitly disabled.
    pub disabled_rules: Vec<String>,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            trusted_registries: vec![
                "gcr.io".to_owned(),
                "ghcr.io".to_owned(),
                "registry.k8s.io".to_owned(),
                "quay.io".to_owned(),
                "public.ecr.aws".to_owned(),
            ],
            disabled_rules: Vec::new(),
        }
    }
}

impl AnalyzerConfig {
    /// `true` when the rule is enabled for this tenant.
    fn enabled(&self, rule_id: &str) -> bool {
        !self.disabled_rules.iter().any(|r| r == rule_id)
    }
}

/// Stable lookup: severity for a rule id, or `None` if unknown.
#[must_use]
pub fn severity_of(rule_id: &str) -> Option<FindingSeverity> {
    BUILTIN_RULES
        .iter()
        .find(|r| r.id == rule_id)
        .map(|r| r.severity)
}

/// Run every enabled rule against `object` and return the findings in stable
/// declaration order. `object` is the `request.object` field — typically a
/// Pod/Deployment/etc.
#[must_use]
pub fn analyze(object: &Value, config: &AnalyzerConfig) -> Vec<K8sAdmissionFinding> {
    let pod_spec = resolve_pod_spec(object);
    let mut findings = Vec::new();
    let Some(spec) = pod_spec else {
        return findings;
    };

    if config.enabled("k8s.pod.privileged") {
        scan_privileged(spec, &mut findings);
    }
    if config.enabled("k8s.pod.host_network") {
        scan_host_namespace(spec, "hostNetwork", "k8s.pod.host_network", &mut findings);
    }
    if config.enabled("k8s.pod.host_pid") {
        scan_host_namespace(spec, "hostPID", "k8s.pod.host_pid", &mut findings);
    }
    if config.enabled("k8s.pod.host_ipc") {
        scan_host_namespace(spec, "hostIPC", "k8s.pod.host_ipc", &mut findings);
    }
    if config.enabled("k8s.pod.host_path") {
        scan_host_path(spec, &mut findings);
    }
    if config.enabled("k8s.container.dangerous_capability") {
        scan_dangerous_capabilities(spec, &mut findings);
    }
    if config.enabled("k8s.container.missing_seccomp") {
        scan_missing_seccomp(spec, &mut findings);
    }
    if config.enabled("k8s.container.missing_apparmor") {
        scan_missing_apparmor(object, spec, &mut findings);
    }
    if config.enabled("k8s.pod.unsafe_sysctl") {
        scan_unsafe_sysctls(spec, &mut findings);
    }
    if config.enabled("k8s.container.untrusted_registry") && !config.trusted_registries.is_empty() {
        scan_untrusted_registry(spec, &config.trusted_registries, &mut findings);
    }
    if config.enabled("k8s.container.latest_tag") {
        scan_latest_tag(spec, &mut findings);
    }
    if config.enabled("k8s.container.missing_resource_limits") {
        scan_missing_resource_limits(spec, &mut findings);
    }
    if config.enabled("k8s.container.run_as_root") {
        scan_run_as_root(spec, &mut findings);
    }
    if config.enabled("k8s.container.allow_privilege_escalation") {
        scan_allow_privilege_escalation(spec, &mut findings);
    }
    if config.enabled("k8s.container.read_only_root_fs_disabled") {
        scan_read_only_root_fs(spec, &mut findings);
    }
    if config.enabled("k8s.pod.automount_sa_token_default") {
        scan_automount_sa_token(spec, &mut findings);
    }

    findings
}

fn resolve_pod_spec(object: &Value) -> Option<&Value> {
    let kind = object.get("kind").and_then(Value::as_str).unwrap_or("");
    match kind {
        "Pod" => object.get("spec"),
        "CronJob" => object
            .pointer("/spec/jobTemplate/spec/template/spec")
            .or_else(|| object.pointer("/spec/template/spec")),
        // Deployment / DaemonSet / StatefulSet / Job / ReplicaSet / ReplicationController
        _ => object
            .pointer("/spec/template/spec")
            .or_else(|| object.get("spec")),
    }
}

fn finding_for(rule_id: &str, detail: String, path: Option<String>) -> K8sAdmissionFinding {
    if let Some(spec) = BUILTIN_RULES.iter().find(|r| r.id == rule_id).copied() {
        K8sAdmissionFinding {
            rule_id: spec.id.to_owned(),
            severity: spec.severity,
            title: spec.title.to_owned(),
            detail,
            path,
            references: spec.references.iter().map(|s| (*s).to_owned()).collect(),
        }
    } else {
        K8sAdmissionFinding {
            rule_id: rule_id.to_owned(),
            severity: FindingSeverity::Medium,
            title: "Unknown rule".to_owned(),
            detail,
            path,
            references: Vec::new(),
        }
    }
}

fn containers_of(pod_spec: &Value) -> Vec<(String, &Value, &'static str)> {
    let mut out = Vec::new();
    for kind in ["initContainers", "containers", "ephemeralContainers"] {
        if let Some(arr) = pod_spec.get(kind).and_then(Value::as_array) {
            for c in arr {
                let name = c
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("<unnamed>")
                    .to_owned();
                out.push((name, c, kind));
            }
        }
    }
    out
}

fn scan_privileged(pod_spec: &Value, out: &mut Vec<K8sAdmissionFinding>) {
    for (name, c, kind) in containers_of(pod_spec) {
        let privileged = c
            .pointer("/securityContext/privileged")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if privileged {
            out.push(finding_for(
                "k8s.pod.privileged",
                format!("container `{name}` runs privileged"),
                Some(format!("/spec/{kind}/{name}/securityContext/privileged")),
            ));
        }
    }
}

fn scan_host_namespace(
    pod_spec: &Value,
    field: &str,
    rule_id: &str,
    out: &mut Vec<K8sAdmissionFinding>,
) {
    if pod_spec
        .get(field)
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        out.push(finding_for(
            rule_id,
            format!("pod sets `{field}: true`"),
            Some(format!("/spec/{field}")),
        ));
    }
}

fn scan_host_path(pod_spec: &Value, out: &mut Vec<K8sAdmissionFinding>) {
    let Some(volumes) = pod_spec.get("volumes").and_then(Value::as_array) else {
        return;
    };
    for vol in volumes {
        if let Some(hp) = vol.get("hostPath") {
            let vol_name = vol
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("<unnamed>");
            let path = hp
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>");
            out.push(finding_for(
                "k8s.pod.host_path",
                format!("volume `{vol_name}` mounts hostPath `{path}`"),
                Some(format!("/spec/volumes/{vol_name}/hostPath")),
            ));
        }
    }
}

fn scan_dangerous_capabilities(pod_spec: &Value, out: &mut Vec<K8sAdmissionFinding>) {
    const DANGEROUS: &[&str] = &[
        "SYS_ADMIN",
        "NET_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "DAC_READ_SEARCH",
        "ALL",
    ];
    for (name, c, kind) in containers_of(pod_spec) {
        let Some(adds) = c
            .pointer("/securityContext/capabilities/add")
            .and_then(Value::as_array)
        else {
            continue;
        };
        for cap in adds {
            let Some(cap_str) = cap.as_str() else {
                continue;
            };
            let upper = cap_str.to_ascii_uppercase();
            if DANGEROUS.iter().any(|d| *d == upper) {
                out.push(finding_for(
                    "k8s.container.dangerous_capability",
                    format!("container `{name}` adds dangerous capability `{upper}`"),
                    Some(format!(
                        "/spec/{kind}/{name}/securityContext/capabilities/add"
                    )),
                ));
            }
        }
    }
}

fn pod_seccomp_set(pod_spec: &Value) -> bool {
    pod_spec
        .pointer("/securityContext/seccompProfile/type")
        .and_then(Value::as_str)
        .is_some_and(|t| !t.is_empty() && t != "Unconfined")
}

fn scan_missing_seccomp(pod_spec: &Value, out: &mut Vec<K8sAdmissionFinding>) {
    let pod_default = pod_seccomp_set(pod_spec);
    for (name, c, kind) in containers_of(pod_spec) {
        let container_type = c
            .pointer("/securityContext/seccompProfile/type")
            .and_then(Value::as_str);
        let configured = container_type.is_some_and(|t| !t.is_empty() && t != "Unconfined")
            || (pod_default && container_type != Some("Unconfined"));
        if !configured {
            out.push(finding_for(
                "k8s.container.missing_seccomp",
                format!("container `{name}` has no seccomp profile (or set to Unconfined)"),
                Some(format!(
                    "/spec/{kind}/{name}/securityContext/seccompProfile"
                )),
            ));
        }
    }
}

fn scan_missing_apparmor(object: &Value, pod_spec: &Value, out: &mut Vec<K8sAdmissionFinding>) {
    // AppArmor is annotated `container.apparmor.security.beta.kubernetes.io/<name>`
    // pre-1.30, and via `securityContext.appArmorProfile.type` 1.30+.
    let annotations = object
        .pointer("/metadata/annotations")
        .and_then(Value::as_object);
    let pod_default = pod_spec
        .pointer("/securityContext/appArmorProfile/type")
        .and_then(Value::as_str)
        .is_some_and(|v| !v.is_empty() && v != "Unconfined");
    for (name, c, kind) in containers_of(pod_spec) {
        let from_annotation = annotations.is_some_and(|a| {
            let key = format!("container.apparmor.security.beta.kubernetes.io/{name}");
            a.get(&key)
                .and_then(Value::as_str)
                .is_some_and(|v| !v.is_empty() && v != "unconfined")
        });
        let container_type = c
            .pointer("/securityContext/appArmorProfile/type")
            .and_then(Value::as_str);
        let from_security_context = container_type
            .is_some_and(|v| !v.is_empty() && v != "Unconfined")
            || (pod_default && container_type != Some("Unconfined"));
        if !from_annotation && !from_security_context {
            out.push(finding_for(
                "k8s.container.missing_apparmor",
                format!("container `{name}` has no AppArmor profile"),
                Some(format!(
                    "/spec/{kind}/{name}/securityContext/appArmorProfile"
                )),
            ));
        }
    }
}

fn scan_unsafe_sysctls(pod_spec: &Value, out: &mut Vec<K8sAdmissionFinding>) {
    // The kubelet's safe-sysctl allowlist (1.28+) is small and well-known;
    // anything outside it is "unsafe" per upstream definition.
    const SAFE: &[&str] = &[
        "kernel.shm_rmid_forced",
        "net.ipv4.ip_local_port_range",
        "net.ipv4.tcp_syncookies",
        "net.ipv4.ping_group_range",
        "net.ipv4.ip_unprivileged_port_start",
    ];
    let Some(sysctls) = pod_spec
        .pointer("/securityContext/sysctls")
        .and_then(Value::as_array)
    else {
        return;
    };
    for sysctl in sysctls {
        let Some(name) = sysctl.get("name").and_then(Value::as_str) else {
            continue;
        };
        if !SAFE.contains(&name) {
            out.push(finding_for(
                "k8s.pod.unsafe_sysctl",
                format!("pod sets unsafe sysctl `{name}`"),
                Some("/spec/securityContext/sysctls".to_owned()),
            ));
        }
    }
}

fn scan_untrusted_registry(
    pod_spec: &Value,
    trusted: &[String],
    out: &mut Vec<K8sAdmissionFinding>,
) {
    for (name, c, kind) in containers_of(pod_spec) {
        let Some(image) = c.get("image").and_then(Value::as_str) else {
            continue;
        };
        let registry = extract_registry(image);
        let trusted_hit = trusted
            .iter()
            .any(|prefix| registry.starts_with(prefix.as_str()));
        if !trusted_hit {
            out.push(finding_for(
                "k8s.container.untrusted_registry",
                format!("container `{name}` image `{image}` registry `{registry}` not in tenant allow-list"),
                Some(format!("/spec/{kind}/{name}/image")),
            ));
        }
    }
}

fn extract_registry(image: &str) -> &str {
    // Heuristic: registry is everything up to the first `/` if it contains `.` or `:`,
    // otherwise the image came from the implicit docker.io.
    if let Some((head, _rest)) = image.split_once('/') {
        if head.contains('.') || head.contains(':') || head == "localhost" {
            return head;
        }
    }
    "docker.io"
}

fn scan_latest_tag(pod_spec: &Value, out: &mut Vec<K8sAdmissionFinding>) {
    for (name, c, kind) in containers_of(pod_spec) {
        let Some(image) = c.get("image").and_then(Value::as_str) else {
            continue;
        };
        if image_uses_latest(image) {
            out.push(finding_for(
                "k8s.container.latest_tag",
                format!("container `{name}` image `{image}` uses `:latest` or unpinned tag"),
                Some(format!("/spec/{kind}/{name}/image")),
            ));
        }
    }
}

fn image_uses_latest(image: &str) -> bool {
    // Split off the registry host (which may contain `:` for a port).
    let after_host = image.split_once('/').map_or(image, |(_, rest)| rest);
    if after_host.contains('@') {
        // Digest-pinned — fine.
        return false;
    }
    match after_host.rsplit_once(':') {
        Some((_, tag)) => tag.eq_ignore_ascii_case("latest") || tag.is_empty(),
        None => true, // no tag → defaults to :latest
    }
}

fn scan_missing_resource_limits(pod_spec: &Value, out: &mut Vec<K8sAdmissionFinding>) {
    for (name, c, kind) in containers_of(pod_spec) {
        let limits = c.pointer("/resources/limits").and_then(Value::as_object);
        let has_cpu = limits.is_some_and(|m| m.contains_key("cpu"));
        let has_mem = limits.is_some_and(|m| m.contains_key("memory"));
        if !has_cpu || !has_mem {
            let missing = match (has_cpu, has_mem) {
                (false, false) => "cpu+memory",
                (false, true) => "cpu",
                (true, false) => "memory",
                (true, true) => "",
            };
            out.push(finding_for(
                "k8s.container.missing_resource_limits",
                format!("container `{name}` missing resource limit: {missing}"),
                Some(format!("/spec/{kind}/{name}/resources/limits")),
            ));
        }
    }
}

fn scan_run_as_root(pod_spec: &Value, out: &mut Vec<K8sAdmissionFinding>) {
    let pod_run_as_user = pod_spec
        .pointer("/securityContext/runAsUser")
        .and_then(Value::as_i64);
    let pod_run_as_non_root = pod_spec
        .pointer("/securityContext/runAsNonRoot")
        .and_then(Value::as_bool);

    for (name, c, kind) in containers_of(pod_spec) {
        let cont_run_as_user = c
            .pointer("/securityContext/runAsUser")
            .and_then(Value::as_i64)
            .or(pod_run_as_user);
        let cont_run_as_non_root = c
            .pointer("/securityContext/runAsNonRoot")
            .and_then(Value::as_bool)
            .or(pod_run_as_non_root);

        let is_root = cont_run_as_user == Some(0)
            || (cont_run_as_user.is_none() && cont_run_as_non_root != Some(true));
        if is_root {
            out.push(finding_for(
                "k8s.container.run_as_root",
                format!("container `{name}` runs as root (uid 0 or runAsNonRoot not set)"),
                Some(format!("/spec/{kind}/{name}/securityContext/runAsUser")),
            ));
        }
    }
}

fn scan_allow_privilege_escalation(pod_spec: &Value, out: &mut Vec<K8sAdmissionFinding>) {
    for (name, c, kind) in containers_of(pod_spec) {
        let ape = c
            .pointer("/securityContext/allowPrivilegeEscalation")
            .and_then(Value::as_bool);
        // Default in K8s is `true` unless explicitly false — surface either case.
        if ape != Some(false) {
            out.push(finding_for(
                "k8s.container.allow_privilege_escalation",
                format!("container `{name}` allowPrivilegeEscalation not set to false"),
                Some(format!(
                    "/spec/{kind}/{name}/securityContext/allowPrivilegeEscalation"
                )),
            ));
        }
    }
}

fn scan_automount_sa_token(pod_spec: &Value, out: &mut Vec<K8sAdmissionFinding>) {
    // K8s default for `automountServiceAccountToken` is `true`. The rule fires
    // when the field is either explicitly `true` or omitted (defaulting to true).
    // A pod that explicitly opts out (`false`) is compliant.
    let explicit = pod_spec
        .get("automountServiceAccountToken")
        .and_then(Value::as_bool);
    if explicit == Some(false) {
        return;
    }
    let detail = if explicit == Some(true) {
        "pod explicitly sets `automountServiceAccountToken: true`".to_owned()
    } else {
        "pod does not opt out of ServiceAccount token automount (default true)".to_owned()
    };
    out.push(finding_for(
        "k8s.pod.automount_sa_token_default",
        detail,
        Some("/spec/automountServiceAccountToken".to_owned()),
    ));
}

fn scan_read_only_root_fs(pod_spec: &Value, out: &mut Vec<K8sAdmissionFinding>) {
    for (name, c, kind) in containers_of(pod_spec) {
        let ro = c
            .pointer("/securityContext/readOnlyRootFilesystem")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if !ro {
            out.push(finding_for(
                "k8s.container.read_only_root_fs_disabled",
                format!("container `{name}` readOnlyRootFilesystem is not true"),
                Some(format!(
                    "/spec/{kind}/{name}/securityContext/readOnlyRootFilesystem"
                )),
            ));
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value
)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pod(spec: Value) -> Value {
        json!({ "kind": "Pod", "spec": spec })
    }

    #[test]
    fn extract_registry_handles_known_forms() {
        assert_eq!(extract_registry("nginx:1.25"), "docker.io");
        assert_eq!(extract_registry("library/nginx:1.25"), "docker.io");
        assert_eq!(extract_registry("gcr.io/foo/bar:1.0"), "gcr.io");
        assert_eq!(extract_registry("localhost:5000/x:1"), "localhost:5000");
        assert_eq!(
            extract_registry("123456.dkr.ecr.us-east-1.amazonaws.com/x:1"),
            "123456.dkr.ecr.us-east-1.amazonaws.com"
        );
    }

    #[test]
    fn image_uses_latest_detects_unpinned() {
        assert!(image_uses_latest("nginx"));
        assert!(image_uses_latest("nginx:latest"));
        assert!(image_uses_latest("nginx:LATEST"));
        assert!(image_uses_latest("gcr.io/foo/bar:latest"));
        assert!(!image_uses_latest("nginx:1.25"));
        assert!(!image_uses_latest(
            "gcr.io/foo/bar@sha256:0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn analyzes_clean_pod_with_no_findings() {
        let object = pod(json!({
            "automountServiceAccountToken": false,
            "securityContext": {
                "seccompProfile": { "type": "RuntimeDefault" },
                "appArmorProfile": { "type": "RuntimeDefault" },
                "runAsNonRoot": true,
                "runAsUser": 1000,
            },
            "containers": [{
                "name": "app",
                "image": "gcr.io/foo/app:1.0.0",
                "resources": { "limits": { "cpu": "500m", "memory": "256Mi" } },
                "securityContext": {
                    "privileged": false,
                    "allowPrivilegeEscalation": false,
                    "readOnlyRootFilesystem": true,
                    "runAsNonRoot": true,
                    "runAsUser": 1000,
                    "capabilities": { "drop": ["ALL"] },
                },
            }]
        }));
        let findings = analyze(&object, &AnalyzerConfig::default());
        assert!(findings.is_empty(), "expected clean pod, got {findings:?}");
    }

    #[test]
    fn detects_privileged() {
        let object = pod(json!({
            "containers": [{
                "name": "evil",
                "image": "gcr.io/foo/app:1",
                "securityContext": { "privileged": true },
            }]
        }));
        let findings = analyze(&object, &AnalyzerConfig::default());
        assert!(findings.iter().any(|f| f.rule_id == "k8s.pod.privileged"));
    }

    #[test]
    fn detects_host_namespaces() {
        let object = pod(json!({
            "hostNetwork": true,
            "hostPID": true,
            "hostIPC": true,
            "containers": [{ "name": "x", "image": "gcr.io/foo/x:1" }],
        }));
        let findings = analyze(&object, &AnalyzerConfig::default());
        assert!(findings.iter().any(|f| f.rule_id == "k8s.pod.host_network"));
        assert!(findings.iter().any(|f| f.rule_id == "k8s.pod.host_pid"));
        assert!(findings.iter().any(|f| f.rule_id == "k8s.pod.host_ipc"));
    }

    #[test]
    fn detects_host_path() {
        let object = pod(json!({
            "containers": [{ "name": "x", "image": "gcr.io/foo/x:1" }],
            "volumes": [{ "name": "host-root", "hostPath": { "path": "/" } }],
        }));
        let findings = analyze(&object, &AnalyzerConfig::default());
        assert!(findings.iter().any(|f| f.rule_id == "k8s.pod.host_path"));
    }

    #[test]
    fn detects_dangerous_capability() {
        let object = pod(json!({
            "containers": [{
                "name": "x", "image": "gcr.io/foo/x:1",
                "securityContext": { "capabilities": { "add": ["NET_ADMIN", "SYS_ADMIN"] } },
            }]
        }));
        let findings = analyze(&object, &AnalyzerConfig::default());
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "k8s.container.dangerous_capability"));
    }

    #[test]
    fn detects_untrusted_registry() {
        let object = pod(json!({
            "containers": [{ "name": "x", "image": "evil.example/x:1" }]
        }));
        let findings = analyze(&object, &AnalyzerConfig::default());
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "k8s.container.untrusted_registry"));
    }

    #[test]
    fn detects_latest_tag() {
        let object = pod(json!({
            "containers": [{ "name": "x", "image": "gcr.io/foo/x:latest" }]
        }));
        let findings = analyze(&object, &AnalyzerConfig::default());
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "k8s.container.latest_tag"));
    }

    #[test]
    fn detects_unsafe_sysctl() {
        let object = pod(json!({
            "securityContext": { "sysctls": [{ "name": "kernel.msgmax", "value": "65536" }] },
            "containers": [{ "name": "x", "image": "gcr.io/foo/x:1" }]
        }));
        let findings = analyze(&object, &AnalyzerConfig::default());
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "k8s.pod.unsafe_sysctl"));
    }

    #[test]
    fn deployment_pod_template_is_traversed() {
        let object = json!({
            "kind": "Deployment",
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{
                            "name": "app", "image": "evil.example/x:latest",
                        }]
                    }
                }
            }
        });
        let findings = analyze(&object, &AnalyzerConfig::default());
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "k8s.container.untrusted_registry"));
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "k8s.container.latest_tag"));
    }

    #[test]
    fn disabled_rule_is_skipped() {
        let object = pod(json!({
            "containers": [{
                "name": "x", "image": "gcr.io/foo/x:latest",
            }]
        }));
        let cfg = AnalyzerConfig {
            disabled_rules: vec!["k8s.container.latest_tag".to_owned()],
            ..AnalyzerConfig::default()
        };
        let findings = analyze(&object, &cfg);
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == "k8s.container.latest_tag"));
    }
}
