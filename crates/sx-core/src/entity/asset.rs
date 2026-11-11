//! Asset entity — a discovered IT resource owned by a tenant.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::DomainError;
use crate::value_object::criticality::AssetCriticality;
use crate::value_object::exposure::ExposureLevel;
use crate::value_object::ids::{AssetId, TenantId};

/// Coarse category of an asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    /// A bare metal or virtual host with an IP.
    Host,
    /// A container or pod.
    Container,
    /// A human or workload identity (IAM principal).
    Identity,
    /// A source code repository.
    Repo,
    /// An object store bucket (S3 / GCS / etc).
    Bucket,
    /// A logical service (e.g. a Kubernetes Service, an API endpoint).
    Service,
}

impl fmt::Display for AssetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Host => "host",
            Self::Container => "container",
            Self::Identity => "identity",
            Self::Repo => "repo",
            Self::Bucket => "bucket",
            Self::Service => "service",
        };
        f.write_str(s)
    }
}

/// A discovered IT asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Asset {
    /// Identifier.
    pub id: AssetId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Coarse category.
    pub kind: AssetKind,
    /// Stable string fingerprint (used for dedup). Adapter-supplied.
    pub fingerprint: String,
    /// Network exposure.
    pub exposure: ExposureLevel,
    /// Business criticality.
    pub criticality: AssetCriticality,
    /// Key-value tags, owner-supplied.
    pub tags: BTreeMap<String, String>,
    /// First sighting.
    pub first_seen: OffsetDateTime,
    /// Last sighting — updated each scan.
    pub last_seen: OffsetDateTime,
}

impl Asset {
    /// Build a new asset.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant_id: TenantId,
        kind: AssetKind,
        fingerprint: impl Into<String>,
        exposure: ExposureLevel,
        criticality: AssetCriticality,
        tags: BTreeMap<String, String>,
        first_seen: OffsetDateTime,
        last_seen: OffsetDateTime,
    ) -> Result<Self, DomainError> {
        let fingerprint = fingerprint.into();
        if fingerprint.trim().is_empty() {
            return Err(DomainError::invalid("fingerprint cannot be empty"));
        }
        if fingerprint.len() > 512 {
            return Err(DomainError::invalid("fingerprint exceeds 512 bytes"));
        }
        if last_seen < first_seen {
            return Err(DomainError::invariant("last_seen must be >= first_seen"));
        }
        Ok(Self {
            id: AssetId::new(),
            tenant_id,
            kind,
            fingerprint,
            exposure,
            criticality,
            tags,
            first_seen,
            last_seen,
        })
    }

    /// Update `last_seen` to `at` if `at` is newer than the current value.
    pub fn observe(&mut self, at: OffsetDateTime) {
        if at > self.last_seen {
            self.last_seen = at;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    #[test]
    fn build_ok() {
        let a = Asset::new(
            TenantId::new(),
            AssetKind::Host,
            "fp:abc",
            ExposureLevel::Internet,
            AssetCriticality::Production,
            BTreeMap::new(),
            now(),
            now(),
        )
        .unwrap();
        assert_eq!(a.kind, AssetKind::Host);
    }

    #[test]
    fn rejects_empty_fingerprint() {
        assert!(Asset::new(
            TenantId::new(),
            AssetKind::Host,
            "  ",
            ExposureLevel::Unknown,
            AssetCriticality::Unknown,
            BTreeMap::new(),
            now(),
            now(),
        )
        .is_err());
    }

    #[test]
    fn rejects_inverted_timestamps() {
        let later = now() + time::Duration::seconds(60);
        assert!(Asset::new(
            TenantId::new(),
            AssetKind::Host,
            "fp",
            ExposureLevel::Unknown,
            AssetCriticality::Unknown,
            BTreeMap::new(),
            later,
            now(),
        )
        .is_err());
    }

    #[test]
    fn observe_updates_last_seen() {
        let mut a = Asset::new(
            TenantId::new(),
            AssetKind::Host,
            "fp",
            ExposureLevel::Unknown,
            AssetCriticality::Unknown,
            BTreeMap::new(),
            now(),
            now(),
        )
        .unwrap();
        let later = now() + time::Duration::seconds(30);
        a.observe(later);
        assert_eq!(a.last_seen, later);
        a.observe(now());
        assert_eq!(a.last_seen, later);
    }
}
