//! HIGH-009 — Kubernetes admission webhook in blocking mode.
//!
//! SentinelX ships as a Kubernetes `ValidatingWebhookConfiguration`
//! target. The cluster apiserver POSTs every CREATE / UPDATE for the
//! resources the webhook is registered for to `/v1/runtime/k8s/admit`,
//! and the response decides whether the operation is admitted or
//! rejected.
//!
//! ## Layout
//!
//! - [`types`]    — minimal `admission.k8s.io/v1` envelope types.
//! - [`rules`]    — pluggable [`rules::AdmissionRule`] implementations:
//!                  `pss-{restricted,baseline}`, `no-privileged`,
//!                  `no-host-network`, `no-latest-tag`,
//!                  `mandatory-labels`.
//! - [`policy`]   — per-tenant [`policy::RulePack`] + namespace opt-outs.
//! - [`audit`]    — narrow audit-sink port; the monolith bridges this
//!                  into `sx-audit` via a thin adapter.
//! - [`engine`]   — fans an [`types::AdmissionReview`] through the
//!                  active rule pack and returns the response envelope.
//!
//! ## Dry-run mode
//!
//! Every [`policy::RulePack`] carries a `dry_run` flag. When set, the
//! engine still evaluates every rule but always returns `allowed=true`
//! and surfaces the would-be deny reason as a `warnings[]` entry the
//! apiserver forwards to the `kubectl` client. The audit row records
//! the underlying decision so an operator can review what WOULD have
//! been blocked before flipping the pack to enforcing.
//!
//! ## Per-namespace opt-out
//!
//! Operationally-critical namespaces — most commonly `kube-system` —
//! are listed in [`policy::RulePack::namespace_optouts`]; the engine
//! short-circuits with `allowed=true` for those without consulting any
//! rule. The default `recommended` pack opts out `kube-system`,
//! `kube-public`, and `kube-node-lease`.
//!
//! ## Audit + retention
//!
//! The engine emits one [`audit::K8sAdmissionAuditEvent`] per request
//! — allow OR deny. The event carries a sanitised
//! [`types::AdmissionRequest`] (the raw `object` JSON is fully retained
//! because the request payload is itself the evidence; secrets in pod
//! manifests are out of scope for this layer). The audit row's
//! `retention_days` field is set to `90` so the receiving sink can
//! enforce upstream retention policy.

pub mod audit;
pub mod engine;
pub mod policy;
pub mod rules;
pub mod types;

pub use audit::{
    K8sAdmissionAuditEvent, K8sAdmissionAuditSink, K8sAdmissionDecision, NullK8sAdmissionAuditSink,
    RecordingK8sAdmissionAuditSink, AUDIT_RETENTION_DAYS,
};
pub use engine::{AdmissionEngine, EngineError};
pub use policy::{InMemoryTenantRulePolicy, RulePack, TenantRulePolicy};
pub use rules::{
    AdmissionRule, MandatoryLabels, NoHostNetwork, NoLatestTag, NoPrivileged, PodSecurityStandard,
    PssProfile, RuleOutcome,
};
pub use types::{
    AdmissionRequest, AdmissionResponse, AdmissionReview, GroupVersionKind, Status, UserInfo,
};
