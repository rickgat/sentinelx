//! Crate-wide convenience re-exports.
//!
//! ```rust,ignore
//! use sx_core::prelude::*;
//! ```

pub use crate::entity::asset::{Asset, AssetKind};
pub use crate::entity::cve::Cve;
pub use crate::entity::engagement::{Engagement, EngagementApproval, EngagementStatus};
pub use crate::entity::finding::{EvidenceRef, Finding, FindingFilter};
pub use crate::entity::finding_status::FindingStatus;
pub use crate::entity::permission::Permission;
pub use crate::entity::role::Role;
pub use crate::entity::tenant::{Tenant, TenantTier};
pub use crate::entity::user::User;

pub use crate::error::DomainError;

pub use crate::port::asset_repository::AssetRepository;
pub use crate::port::cve_repository::CveRepository;
pub use crate::port::engagement_repository::EngagementRepository;
pub use crate::port::finding_repository::FindingRepository;
pub use crate::port::kill_switch::{KillSwitchPort, KillSwitchScope};
pub use crate::port::tenant_repository::TenantRepository;
pub use crate::port::user_repository::UserRepository;

pub use crate::value_object::compliance::{
    ComplianceTags, HipaaSafeguard, IsoControl, NistControl, PciRequirement, Soc2Criterion,
};
pub use crate::value_object::confidence::ConfidenceScore;
pub use crate::value_object::criticality::AssetCriticality;
pub use crate::value_object::cvss::CvssScore;
pub use crate::value_object::cvss_v31::{CvssV31, CvssV31Rating};
pub use crate::value_object::cwe::CweId;
pub use crate::value_object::epss::EpssScore;
pub use crate::value_object::exposure::ExposureLevel;
pub use crate::value_object::fqdn::Fqdn;
pub use crate::value_object::ids::{
    AssetId, CveId, EngagementId, FindingId, RoleId, TenantId, UserId,
};
pub use crate::value_object::intensity::ScanIntensity;
pub use crate::value_object::mitre_attack::MitreAttackTechnique;
pub use crate::value_object::page::{Page, PagedResult};
pub use crate::value_object::scope::{ScopeCandidate, ScopeMatcher, ScopeTarget};
pub use crate::value_object::severity::{Severity, SeverityBands};
pub use crate::value_object::time_window::TimeWindow;
pub use crate::value_object::tlp::Tlp;
