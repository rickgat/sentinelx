//! Kubernetes admission analyzer (P2-014).
//!
//! This module implements a deterministic analyzer over the
//! `AdmissionReview` v1 object exchanged with a cluster's
//! `ValidatingAdmissionWebhook`. Given an [`schema::AdmissionReview`] request
//! the analyzer runs the built-in rule set against `request.object` and
//! returns a populated [`schema::AdmissionResponse`] carrying a `SentinelX`
//! advisory (an ordered list of [`schema::K8sAdmissionFinding`]s, recommended
//! deny bit, warnings).
//!
//! In the MVP this is **not** wired in as a blocking
//! `ValidatingAdmissionWebhook` — the `SentinelX` API server hosts a
//! `POST /v1/k8s/admission/review` endpoint that callers (a cluster sidecar,
//! a CI gate, or the dashboard) invoke directly. Wiring `SentinelX` into the
//! API server as a hard webhook is intentionally deferred (TLS provisioning,
//! latency budget, fail-open vs. fail-closed semantics) to its own task.
//!
//! ## Rule set (P2-014)
//!
//! The analyzer ships 16 built-in rules covering the highest-signal
//! risks from the NSA Kubernetes Hardening checklist and CIS-K8s 1.9:
//!
//! | Severity | Rule id                                       |
//! |----------|-----------------------------------------------|
//! | Critical | `k8s.pod.privileged`                          |
//! | Critical | `k8s.container.dangerous_capability`          |
//! | High     | `k8s.pod.host_network`                        |
//! | High     | `k8s.pod.host_pid`                            |
//! | High     | `k8s.pod.host_ipc`                            |
//! | High     | `k8s.pod.host_path`                           |
//! | High     | `k8s.pod.unsafe_sysctl`                       |
//! | High     | `k8s.container.untrusted_registry`            |
//! | High     | `k8s.container.run_as_root`                   |
//! | High     | `k8s.container.allow_privilege_escalation`    |
//! | Medium   | `k8s.container.missing_seccomp`               |
//! | Medium   | `k8s.container.missing_apparmor`              |
//! | Medium   | `k8s.container.latest_tag`                    |
//! | Medium   | `k8s.container.read_only_root_fs_disabled`    |
//! | Medium   | `k8s.pod.automount_sa_token_default`          |
//! | Low      | `k8s.container.missing_resource_limits`       |
//!
//! Pod templates embedded in `Deployment` / `DaemonSet` / `StatefulSet` /
//! `Job` / `CronJob` / `ReplicaSet` are resolved transparently so each rule
//! body covers every workload kind.
//!
//! ## Multi-tenancy
//!
//! Every entry point on [`service::K8sAdmissionService`] is keyed by
//! `tenant_id`. Each tenant owns its own [`rules::AnalyzerConfig`] (trusted
//! registry allow-list + disabled rule ids) and its own
//! [`schema::ClusterRegistry`]; cross-tenant reads are impossible by
//! construction.
//!
//! ## Audit
//!
//! Every review is recorded on the in-memory ring (capacity =
//! [`service::AUDIT_RING_CAPACITY`]) and additionally emitted as a structured
//! `tracing` event on `target = "audit.k8s_admission"` for the
//! audit-chain forwarder in `sx-audit`.
//!
//! ## Tolerant parsing
//!
//! The K8s API server may include fields the schema here does not model
//! (e.g. `dryRun`, `options.kind`). All [`schema`] structs use
//! `#[serde(default)]` so the analyzer never refuses a real-world payload
//! over a missing schema definition.

pub mod rules;
pub mod schema;
pub mod service;

pub use rules::{analyze, severity_of, AnalyzerConfig, RuleSpec, BUILTIN_RULES};
pub use schema::{
    AdmissionAuditRecord, AdmissionRequest, AdmissionResponse, AdmissionReview, AdmissionStatus,
    ClusterRegistry, FindingSeverity, GroupVersionKind, GroupVersionResource, K8sAdmissionFinding,
    K8sUserInfo, TypeMeta,
};
pub use service::{
    Clock, InMemoryK8sAdmissionService, K8sAdmissionService, K8sAdmissionServiceError, SystemClock,
    AUDIT_RING_CAPACITY,
};
