//! Aggregated asset emitted by the discovery layer.
//!
//! A [`DiscoveredAsset`] is the bridge between raw observations and the
//! richer asset entities held by `sx-core`. Downstream code that already
//! has access to `sx_core::entity::asset::Asset` can construct one via the
//! provided conversion helpers.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use url::Url;

use crate::contracts::{AssetId, EngagementId, Fqdn, TenantId};

/// Kind of asset, mirroring the agreed-upon `sx_core::entity::asset::AssetKind`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum DiscoveredAssetKind {
    /// A host identified by an IP address.
    Ip(IpAddr),
    /// A fully-qualified domain name.
    Domain(Fqdn),
    /// A reachable URL.
    Url(Url),
    /// An open TCP service (host + port).
    TcpService {
        /// Host address.
        host: IpAddr,
        /// Port number.
        port: u16,
    },
}

/// A single asset discovered during a scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredAsset {
    /// Local identifier.
    pub id: AssetId,
    /// Tenant scope.
    pub tenant_id: TenantId,
    /// Engagement under which the asset was discovered.
    pub engagement_id: EngagementId,
    /// What was discovered.
    pub kind: DiscoveredAssetKind,
    /// When the asset was first seen.
    #[serde(with = "time::serde::rfc3339")]
    pub discovered_at: OffsetDateTime,
}

impl DiscoveredAsset {
    /// Build a new domain asset.
    #[must_use]
    pub fn domain(
        tenant_id: TenantId,
        engagement_id: EngagementId,
        domain: Fqdn,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            id: AssetId::new(),
            tenant_id,
            engagement_id,
            kind: DiscoveredAssetKind::Domain(domain),
            discovered_at: now,
        }
    }

    /// Build a new IP-host asset.
    #[must_use]
    pub fn ip(
        tenant_id: TenantId,
        engagement_id: EngagementId,
        ip: IpAddr,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            id: AssetId::new(),
            tenant_id,
            engagement_id,
            kind: DiscoveredAssetKind::Ip(ip),
            discovered_at: now,
        }
    }

    /// Build a new TCP-service asset.
    #[must_use]
    pub fn tcp_service(
        tenant_id: TenantId,
        engagement_id: EngagementId,
        host: IpAddr,
        port: u16,
        now: OffsetDateTime,
    ) -> Self {
        Self {
            id: AssetId::new(),
            tenant_id,
            engagement_id,
            kind: DiscoveredAssetKind::TcpService { host, port },
            discovered_at: now,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn domain_constructor_sets_kind() {
        let a = DiscoveredAsset::domain(
            TenantId::new(),
            EngagementId::new(),
            Fqdn::new("example.com").unwrap(),
            OffsetDateTime::UNIX_EPOCH,
        );
        assert!(matches!(a.kind, DiscoveredAssetKind::Domain(_)));
    }

    #[test]
    fn tcp_service_constructor_sets_kind() {
        let a = DiscoveredAsset::tcp_service(
            TenantId::new(),
            EngagementId::new(),
            "127.0.0.1".parse().unwrap(),
            22,
            OffsetDateTime::UNIX_EPOCH,
        );
        match a.kind {
            DiscoveredAssetKind::TcpService { port, .. } => assert_eq!(port, 22),
            _ => panic!("wrong kind"),
        }
    }
}
