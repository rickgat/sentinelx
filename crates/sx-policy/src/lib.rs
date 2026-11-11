//! # `sx-policy`
//!
//! Pluggable policy engine for `SentinelX`.
//!
//! ## Backend choice
//!
//! The MVP ships a deterministic JSON policy DSL ([`policy::JsonPolicy`]) evaluated
//! by [`engine::JsonPolicyEngine`]. A WASM-Rego backend was evaluated and rejected
//! for Phase 1:
//!
//! * `opa-wasm` ≥ 0.x pulls `wasmtime`, which builds at multi-MB compiled size
//!   and introduces a non-trivial sandbox / supply-chain surface.
//! * The JSON DSL covers the only authorisation shapes the platform currently
//!   needs (deny-on-equal, deny-on-membership, deny-on-regex) with a few hundred
//!   lines of pure-safe Rust.
//! * Future Rego support can drop in behind the [`engine::PolicyEngine`] trait
//!   without breaking callers — the [`policy::PolicySource::Rego`] variant is
//!   already wired up and returns [`error::PolicyError::Evaluate`] until a
//!   backend is implemented.
//!
//! ## `JsonPolicy` schema
//!
//! ```json
//! {
//!   "deny_if": [
//!     { "id": "block_root",        "field": "user.name", "op": "eq",    "value": "root" },
//!     { "id": "block_test_envs",   "field": "env",       "op": "in",    "value": ["dev", "qa"] },
//!     { "id": "block_admin_paths", "field": "path",      "op": "match", "value": "^/admin/.*" }
//!   ]
//! }
//! ```
//!
//! Each rule is independent; firing any rule yields `Decision { allow: false, ... }`.
//! Rules referencing missing input fields *do not fire* (treated as not-matched,
//! not as error). All [`engine::PolicyEngine::evaluate`] calls are bounded by a
//! 100 ms `tokio::time::timeout` to protect against runaway backends.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod decision;
pub mod engine;
pub mod error;
pub mod k8s_admission;
pub mod policy;

pub use crate::decision::Decision;
pub use crate::engine::{JsonPolicyEngine, PolicyEngine, EVALUATE_TIMEOUT};
pub use crate::error::PolicyError;
pub use crate::k8s_admission::{
    analyze as analyze_k8s_admission, severity_of as k8s_admission_severity_of,
    AdmissionAuditRecord, AdmissionRequest, AdmissionResponse, AdmissionReview, AdmissionStatus,
    AnalyzerConfig, Clock as K8sAdmissionClock, ClusterRegistry, FindingSeverity, GroupVersionKind,
    GroupVersionResource, InMemoryK8sAdmissionService, K8sAdmissionFinding, K8sAdmissionService,
    K8sAdmissionServiceError, K8sUserInfo, RuleSpec, SystemClock as K8sAdmissionSystemClock,
    TypeMeta, AUDIT_RING_CAPACITY, BUILTIN_RULES,
};
pub use crate::policy::{JsonPolicy, Policy, PolicyRule, PolicySource, RuleOp, RuleValue};
