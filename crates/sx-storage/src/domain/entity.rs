//! Local mirror of `sx_core::entity`.
//!
//! Slim, persistence-oriented projections of the domain entities. These
//! are the shapes the repository ports read and write. The real
//! `sx-core` entities will have richer invariants encoded in
//! constructors; here we keep them as plain data with public fields so
//! the storage layer can hydrate them directly from rows.

use serde_json::Value as JsonValue;
use time::OffsetDateTime;

use super::value_object::{AssetId, CveId, EngagementId, FindingId, TenantId, UserId};

/// Tenant aggregate root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenant {
    /// Tenant identifier.
    pub id: TenantId,
    /// Human-readable display name.
    pub name: String,
    /// URL-safe unique slug.
    pub slug: String,
    /// Subscription tier (`starter` | `growth` | `enterprise`).
    pub tier: String,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Soft-delete marker.
    pub deleted_at: Option<OffsetDateTime>,
}

/// User aggregate root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    /// User identifier.
    pub id: UserId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Login email (normalised case-insensitively).
    pub email: String,
    /// Argon2id password hash.
    pub password_hash: String,
    /// Display name.
    pub display_name: String,
    /// Whether the account is currently usable.
    pub is_active: bool,
    /// Whether MFA enrolment is complete.
    pub mfa_enrolled: bool,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Last update timestamp.
    pub updated_at: OffsetDateTime,
}

/// Engagement aggregate root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Engagement {
    /// Engagement identifier.
    pub id: EngagementId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Display name.
    pub name: String,
    /// Scope description (JSON: includes/excludes, address ranges, etc.).
    pub scope: JsonValue,
    /// Engagement window start.
    pub window_start: OffsetDateTime,
    /// Engagement window end.
    pub window_end: OffsetDateTime,
    /// Status string (e.g. `Draft`, `Approved`, `Active`, `Closed`).
    pub status: String,
    /// Whether destructive actions require two approvers.
    pub requires_dual_approval: bool,
    /// Intensity profile (e.g. `light`, `standard`, `intense`).
    pub intensity: String,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Last update timestamp.
    pub updated_at: OffsetDateTime,
}

/// Asset aggregate root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    /// Asset identifier.
    pub id: AssetId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Associated engagement.
    pub engagement_id: EngagementId,
    /// Asset kind discriminator (e.g. `Host`, `Service`, `Webapp`).
    pub kind: String,
    /// Canonical fingerprint (unique within a tenant).
    pub fingerprint: String,
    /// Exposure level (e.g. `Internet`, `Internal`).
    pub exposure: String,
    /// Business criticality (e.g. `Low`, `Medium`, `High`, `Critical`).
    pub criticality: String,
    /// Free-form tag set.
    pub tags: JsonValue,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Last update timestamp.
    pub updated_at: OffsetDateTime,
}

/// Finding aggregate root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Finding identifier.
    pub id: FindingId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Engagement the finding was raised in.
    pub engagement_id: EngagementId,
    /// Asset the finding pertains to.
    pub asset_id: AssetId,
    /// Detection rule identifier.
    pub rule_id: String,
    /// Severity (`Info`, `Low`, `Medium`, `High`, `Critical`).
    pub severity: String,
    /// Lifecycle status (`New`, `Triaged`, `InProgress`, `Resolved`,
    /// `FalsePositive`, `AcceptedRisk`).
    pub status: String,
    /// Short title.
    pub title: String,
    /// Long-form description.
    pub description: String,
    /// JSON-encoded list of evidence references (URIs, file hashes).
    pub evidence_refs: JsonValue,
    /// Detection timestamp.
    pub detected_at: OffsetDateTime,
    /// Triage timestamp (nullable).
    pub triaged_at: Option<OffsetDateTime>,
    /// Resolution timestamp (nullable).
    pub resolved_at: Option<OffsetDateTime>,
}

/// CVE aggregate root.
#[derive(Debug, Clone, PartialEq)]
pub struct Cve {
    /// CVE identifier (e.g. `CVE-2024-12345`).
    pub id: CveId,
    /// Free-text description.
    pub description: String,
    /// CVSS v3 metric vector + scores (JSON).
    pub cvss: JsonValue,
    /// EPSS probability \[0.0, 1.0\].
    pub epss: f64,
    /// Whether the CVE appears in the CISA Known Exploited list.
    pub kev: bool,
    /// Publication timestamp.
    pub published_at: OffsetDateTime,
    /// Last NVD modification timestamp.
    pub modified_at: OffsetDateTime,
}
