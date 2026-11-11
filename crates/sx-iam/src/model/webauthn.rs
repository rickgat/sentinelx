//! Domain model for FIDO2 / `WebAuthn` passkey credentials (P1-002).
//!
//! These types are storage-shape DTOs the IAM use-case layer hands to the
//! [`crate::port::WebauthnCredentialRepository`] /
//! [`crate::port::WebauthnRpRepository`] traits implemented by `sx-storage`.
//! They are deliberately decoupled from `webauthn-rs`'s opaque
//! `Passkey` wrapper so the storage layer can persist columns without
//! depending on `webauthn-rs` at the trait boundary.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::domain::{TenantId, UserId};

/// Attestation conveyance preference encoded at the per-tenant policy
/// level and on each stored credential.
///
/// Mirrors the W3C
/// [`AttestationConveyancePreference`](https://www.w3.org/TR/webauthn-3/#enum-attestation-convey)
/// enum so the storage layer never sees `webauthn-rs`'s internal type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationPolicy {
    /// No attestation required — passkey-default.
    #[default]
    None,
    /// Attestation requested, anonymisation acceptable.
    Indirect,
    /// Attestation statement required as the authenticator generated it.
    Direct,
    /// Enterprise attestation including authenticator serial.
    Enterprise,
}

impl AttestationPolicy {
    /// Stable wire / database string for the policy.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Indirect => "indirect",
            Self::Direct => "direct",
            Self::Enterprise => "enterprise",
        }
    }

    /// Parse the stable wire string. Unknown values return `None`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "none" => Some(Self::None),
            "indirect" => Some(Self::Indirect),
            "direct" => Some(Self::Direct),
            "enterprise" => Some(Self::Enterprise),
            _ => None,
        }
    }
}

/// Per-tenant relying-party configuration (one row per tenant).
///
/// `rp_id` MUST be a registrable domain suffix of `rp_origin`'s host or
/// [`crate::service::webauthn::WebauthnService::new`] will reject the
/// pair at load time. The IAM layer enforces this invariant when the
/// configuration is loaded from storage; it never mutates the values.
#[derive(Debug, Clone)]
pub struct TenantRp {
    /// Tenant owning this relying-party configuration.
    pub tenant_id: TenantId,
    /// Stable relying-party identifier (a registrable domain).
    pub rp_id: String,
    /// Human-readable relying-party name displayed by the authenticator UI.
    pub rp_name: String,
    /// HTTPS origin of the dashboard the user registers from (URL).
    pub rp_origin: String,
    /// Tenant-wide attestation policy applied at registration.
    pub attestation: AttestationPolicy,
}

/// Stored passkey credential (one row per registered authenticator).
///
/// A user may have multiple credentials (`exclude_credentials` on
/// registration prevents re-enrolment of the same authenticator). The
/// `passkey` field is the full `webauthn-rs` `Passkey` serialised as JSON
/// so subsequent `start_authentication` ceremonies can reconstruct the
/// credential without re-deriving from the individual columns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    /// Surrogate row id.
    pub id: Uuid,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Owning user.
    pub user_id: UserId,
    /// Base64url-encoded credential id (no padding) — the W3C-recommended
    /// stable identifier surfaced in the `cred_id` JWT claim.
    pub cred_id: String,
    /// Raw credential id bytes.
    pub cred_id_bytes: Vec<u8>,
    /// COSE-encoded public key (as `webauthn-rs` round-tripped JSON bytes).
    pub public_key: Vec<u8>,
    /// Authenticator AAGUID (16 bytes) or `None` for U2F-style devices.
    pub aaguid: Option<[u8; 16]>,
    /// Last observed signature counter.
    pub counter: u32,
    /// Full `webauthn-rs` `Passkey` JSON blob.
    pub passkey: serde_json::Value,
    /// Optional user-set label (`"YubiKey 5"`, `"iPhone Touch ID"`, ...).
    pub label: Option<String>,
    /// Attestation level the credential was registered under.
    pub attestation: AttestationPolicy,
    /// Creation timestamp.
    pub created_at: OffsetDateTime,
    /// Most recent successful assertion timestamp.
    pub last_used_at: Option<OffsetDateTime>,
    /// Revocation timestamp; `None` while the credential is active.
    pub revoked_at: Option<OffsetDateTime>,
}

impl StoredCredential {
    /// Whether the credential is currently usable for authentication.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

// ---------------------------------------------------------------------------
// HIGH-002 — AAGUID policy + FIDO MDS3 metadata cache
// ---------------------------------------------------------------------------

/// Per-tenant per-AAGUID admin decision (HIGH-002).
///
/// One row per `(tenant_id, aaguid)` in `webauthn_aaguid_policy`. The
/// presence of any row with [`AaguidAction::Allow`] for a tenant flips
/// the tenant into "allowlist-only" mode: every AAGUID NOT explicitly
/// allowed is then implicitly denied. The presence of [`AaguidAction::Block`]
/// rows in isolation just adds explicit blocks without changing the
/// implicit default (which stays `allow` for backward compatibility with
/// P1-002).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AaguidAction {
    /// Allow the AAGUID. Toggles the tenant into allowlist-only mode if
    /// at least one such row exists for the tenant.
    Allow,
    /// Block the AAGUID. Always reject registrations using this
    /// authenticator regardless of allowlist mode.
    Block,
}

impl AaguidAction {
    /// Stable wire / database string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
        }
    }

    /// Parse the stable wire string. Unknown values return `None`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Self::Allow),
            "block" => Some(Self::Block),
            _ => None,
        }
    }
}

/// A single AAGUID policy row (HIGH-002).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AaguidPolicy {
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// 16-byte authenticator AAGUID, encoded as a UUID for serialisation
    /// convenience (RFC 4122 byte order).
    pub aaguid: Uuid,
    /// Admin decision for this AAGUID.
    pub action: AaguidAction,
    /// Operator-supplied justification (free text up to 256 chars by
    /// HTTP-layer validation).
    pub reason: String,
    /// UUID of the operator who set the row.
    pub set_by: UserId,
    /// When the row was last mutated.
    pub set_at: OffsetDateTime,
}

/// Cached FIDO Alliance MDS3 entry (HIGH-002).
///
/// Populated by [`crate::service::webauthn::mds::MdsFetcher`] from the
/// signed JWT blob at <https://mds.fidoalliance.org/>. Strictly read-only
/// at registration time — the enforcement layer looks up authenticator
/// metadata by AAGUID to enrich audit logs and (in strict mode) to
/// reject authenticators not present in MDS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MdsEntry {
    /// 16-byte AAGUID (primary key).
    pub aaguid: Uuid,
    /// Authenticator vendor-supplied name.
    pub authenticator_name: String,
    /// Authenticator firmware version, formatted as `"<major>.<minor>"`.
    pub authenticator_version: String,
    /// FIDO certification level, e.g. `"L1"`, `"L2"`, `"L3"`,
    /// `"NOT_FIDO_CERTIFIED"`.
    pub certification_level: String,
    /// When this row was last refreshed from MDS.
    pub last_updated: OffsetDateTime,
    /// Raw MDS metadata-statement JSON object the row was derived from.
    /// Kept verbatim so audits can replay the decision.
    pub raw_blob: serde_json::Value,
}

/// MDS cache health summary (HIGH-002).
///
/// Returned by [`crate::port::WebauthnMdsRepository::status`] and surfaced
/// by `GET /v1/iam/webauthn/mds-status`. Avoids leaking secret material
/// (the pinned root cert fingerprint is a public SHA-256 hex string).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MdsStatus {
    /// Last successful refresh time. `None` if the cache has never been
    /// populated since process boot.
    pub last_refresh: Option<OffsetDateTime>,
    /// Total entry count.
    pub total_entries: u64,
    /// Lowercase hex SHA-256 fingerprint of the pinned MDS root cert.
    pub root_cert_fingerprint: String,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn attestation_policy_round_trips_through_str() {
        for p in [
            AttestationPolicy::None,
            AttestationPolicy::Indirect,
            AttestationPolicy::Direct,
            AttestationPolicy::Enterprise,
        ] {
            let s = p.as_str();
            assert_eq!(AttestationPolicy::parse(s), Some(p));
        }
    }

    #[test]
    fn attestation_policy_parse_rejects_unknown() {
        assert!(AttestationPolicy::parse("bogus").is_none());
        assert!(AttestationPolicy::parse("").is_none());
    }

    #[test]
    fn aaguid_action_round_trips_through_str() {
        for a in [AaguidAction::Allow, AaguidAction::Block] {
            assert_eq!(AaguidAction::parse(a.as_str()), Some(a));
        }
        assert!(AaguidAction::parse("garbage").is_none());
    }

    #[test]
    fn aaguid_policy_serde_round_trip() {
        let p = AaguidPolicy {
            tenant_id: TenantId::new(),
            aaguid: Uuid::nil(),
            action: AaguidAction::Block,
            reason: "RP-001 disallowed".into(),
            set_by: UserId::new(),
            set_at: OffsetDateTime::UNIX_EPOCH,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: AaguidPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn mds_entry_serde_round_trip() {
        let e = MdsEntry {
            aaguid: Uuid::from_u128(0x1234_5678_9abc_def0_1122_3344_5566_7788_u128),
            authenticator_name: "TestKey".into(),
            authenticator_version: "1.0".into(),
            certification_level: "L1".into(),
            last_updated: OffsetDateTime::UNIX_EPOCH,
            raw_blob: serde_json::json!({"hello": "world"}),
        };
        let s = serde_json::to_string(&e).unwrap();
        let back: MdsEntry = serde_json::from_str(&s).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn stored_credential_is_active_reflects_revoked_at() {
        let c = StoredCredential {
            id: Uuid::new_v4(),
            tenant_id: TenantId::new(),
            user_id: UserId::new(),
            cred_id: "abc".into(),
            cred_id_bytes: vec![1, 2, 3],
            public_key: vec![],
            aaguid: None,
            counter: 0,
            passkey: serde_json::Value::Null,
            label: None,
            attestation: AttestationPolicy::None,
            created_at: OffsetDateTime::UNIX_EPOCH,
            last_used_at: None,
            revoked_at: None,
        };
        assert!(c.is_active());
        let mut revoked = c;
        revoked.revoked_at = Some(OffsetDateTime::UNIX_EPOCH);
        assert!(!revoked.is_active());
    }
}
