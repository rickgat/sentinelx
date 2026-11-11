//! K8s admission policy admin view (HIGH-009).
//!
//! A declarative, serialisable description of a tenant's admission rule
//! pack. The in-crate `sx_discovery::k8s_admission::RulePack` carries
//! `Arc<dyn AdmissionRule>` trait objects which cannot be serialised, so
//! the admin surface and the durable store speak this spec instead; the
//! monolith adapter reconstructs the rule pack from it. Backs
//! `GET` / `PUT /v1/admin/runtime/k8s/policies`.

use serde::{Deserialize, Serialize};
use validator::Validate;

/// A tenant's declarative admission policy.
#[derive(Debug, Clone, Serialize, Deserialize, Validate, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // declarative rule-toggle DTO
pub struct K8sAdmissionPolicyView {
    /// Pod Security Standard profile to enforce: `"baseline"` or
    /// `"restricted"`. `None` disables the PSS rule entirely.
    #[serde(default)]
    pub pss_profile: Option<String>,
    /// Deny pods requesting privileged containers.
    #[serde(default)]
    pub no_privileged: bool,
    /// Deny pods requesting host networking.
    #[serde(default)]
    pub no_host_network: bool,
    /// Deny images pinned to the mutable `:latest` tag.
    #[serde(default)]
    pub no_latest_tag: bool,
    /// Labels every workload must carry (empty disables the rule).
    #[serde(default)]
    pub mandatory_labels: Vec<String>,
    /// Namespaces exempt from all enforcement.
    #[serde(default)]
    pub namespace_optouts: Vec<String>,
    /// Stage mode — evaluate every rule but always allow, surfacing the
    /// would-be deny as a warning.
    #[serde(default)]
    pub dry_run: bool,
}
