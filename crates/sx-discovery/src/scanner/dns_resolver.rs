//! Passive DNS resolver scanner.
//!
//! Queries A, AAAA, CNAME, MX, and TXT records for a domain target using an
//! explicit list of recursive resolvers (system defaults are **never**
//! used). One [`Observation::DnsRecord`] is emitted per record.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
// LOW-001-FU4 (2026-06-23): hickory-resolver 0.24 -> 0.26 migration. The
// `NameServerConfigGroup` helper was removed; nameserver configs are now
// pushed straight onto `ResolverConfig::name_servers`. `Protocol` is no
// longer exported from `config`; the per-protocol selection lives on
// `ConnectionConfig::{udp,tcp,...}`. `TokioAsyncResolver` was renamed to
// `TokioResolver` and is constructed via the new `Resolver::builder_with_config`
// fluent API + `ResolverBuilder::with_options`.
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;
use time::OffsetDateTime;
use tokio::time::timeout;

use crate::contracts::{ScanIntensity, ScopeTarget};
use crate::error::DiscoveryError;
use crate::model::observation::{DnsRecordKind, Observation};
use crate::model::scan_result::ScanResult;
use crate::service::scanner::{ScanContext, Scanner, ScannerCapabilities, ScannerId, TargetKind};

/// Stable id used to register / look up this scanner.
pub const DNS_RESOLVER_ID: ScannerId = ScannerId::new("dns_resolver_v1");

/// Configuration for the DNS resolver scanner.
#[derive(Debug, Clone)]
pub struct DnsScannerConfig {
    /// Explicit list of recursive resolvers. **Must** be non-empty;
    /// system defaults are never used.
    pub resolvers: Vec<SocketAddr>,
    /// Per-query timeout.
    pub query_timeout: Duration,
}

impl DnsScannerConfig {
    /// Validate the configuration.
    pub fn check(&self) -> Result<(), DiscoveryError> {
        if self.resolvers.is_empty() {
            return Err(DiscoveryError::config(
                "dns scanner requires explicit resolvers; system defaults are disabled",
            ));
        }
        if self.query_timeout.is_zero() {
            return Err(DiscoveryError::config(
                "dns scanner query_timeout must be > 0",
            ));
        }
        Ok(())
    }
}

/// DNS resolver scanner — A / AAAA / CNAME / MX / TXT for domain targets.
#[derive(Debug)]
pub struct DnsResolverScanner {
    cfg: DnsScannerConfig,
    resolver: Arc<TokioResolver>,
}

impl DnsResolverScanner {
    /// Build a new scanner from a validated config.
    pub fn new(cfg: DnsScannerConfig) -> Result<Self, DiscoveryError> {
        cfg.check()?;
        // hickory 0.26: each resolver IP carries its own `connections` list
        // (UDP + TCP), and the configured port travels with each
        // `ConnectionConfig`. We honour the operator-supplied port (the
        // `SocketAddr::port()`) rather than silently switching to the
        // protocol default 53 — preserving the 0.24 behaviour where
        // `NameServerConfig::new` took a full `SocketAddr`.
        let mut name_servers = Vec::with_capacity(cfg.resolvers.len());
        for addr in &cfg.resolvers {
            let mut udp = ConnectionConfig::udp();
            udp.port = addr.port();
            let mut tcp = ConnectionConfig::tcp();
            tcp.port = addr.port();
            name_servers.push(NameServerConfig::new(addr.ip(), true, vec![udp, tcp]));
        }
        let resolver_cfg = ResolverConfig::from_parts(None, vec![], name_servers);
        let mut opts = ResolverOpts::default();
        opts.timeout = cfg.query_timeout;
        opts.attempts = 1;
        let resolver =
            TokioResolver::builder_with_config(resolver_cfg, TokioRuntimeProvider::default())
                .with_options(opts)
                .build()
                .map_err(|e| DiscoveryError::config(format!("hickory resolver build: {e}")))?;
        Ok(Self {
            cfg,
            resolver: Arc::new(resolver),
        })
    }

    async fn run_queries(&self, name: &str) -> Result<Vec<Observation>, DiscoveryError> {
        // hickory 0.26: every `*_lookup()` returns the generic `Lookup`
        // shape — there is no longer an `iter()` that yields specialised
        // RData. Each per-type helper walks `.answers()` and pattern-
        // matches on the `RData` variant.
        let mut out = Vec::new();
        out.extend(self.lookup_a(name).await);
        out.extend(self.lookup_aaaa(name).await);
        out.extend(self.lookup_mx(name).await);
        out.extend(self.lookup_txt(name).await);
        out.extend(self.lookup_cname(name).await);
        Ok(out)
    }

    async fn lookup_a(&self, name: &str) -> Vec<Observation> {
        use hickory_resolver::proto::rr::RData;
        let mut out = Vec::new();
        if let Ok(Ok(lookup)) =
            timeout(self.cfg.query_timeout, self.resolver.ipv4_lookup(name)).await
        {
            for rec in lookup.answers() {
                if let RData::A(a) = &rec.data {
                    out.push(Observation::DnsRecord {
                        record: DnsRecordKind::A,
                        value: a.to_string(),
                    });
                }
            }
        }
        out
    }

    async fn lookup_aaaa(&self, name: &str) -> Vec<Observation> {
        use hickory_resolver::proto::rr::RData;
        let mut out = Vec::new();
        if let Ok(Ok(lookup)) =
            timeout(self.cfg.query_timeout, self.resolver.ipv6_lookup(name)).await
        {
            for rec in lookup.answers() {
                if let RData::AAAA(aaaa) = &rec.data {
                    out.push(Observation::DnsRecord {
                        record: DnsRecordKind::Aaaa,
                        value: aaaa.to_string(),
                    });
                }
            }
        }
        out
    }

    async fn lookup_mx(&self, name: &str) -> Vec<Observation> {
        use hickory_resolver::proto::rr::RData;
        let mut out = Vec::new();
        if let Ok(Ok(lookup)) = timeout(self.cfg.query_timeout, self.resolver.mx_lookup(name)).await
        {
            for rec in lookup.answers() {
                if let RData::MX(mx) = &rec.data {
                    out.push(Observation::DnsRecord {
                        record: DnsRecordKind::Mx,
                        value: format!("{} {}", mx.preference, mx.exchange),
                    });
                }
            }
        }
        out
    }

    async fn lookup_txt(&self, name: &str) -> Vec<Observation> {
        use hickory_resolver::proto::rr::RData;
        let mut out = Vec::new();
        if let Ok(Ok(lookup)) =
            timeout(self.cfg.query_timeout, self.resolver.txt_lookup(name)).await
        {
            for rec in lookup.answers() {
                if let RData::TXT(txt) = &rec.data {
                    out.push(Observation::DnsRecord {
                        record: DnsRecordKind::Txt,
                        value: txt.to_string(),
                    });
                }
            }
        }
        out
    }

    async fn lookup_cname(&self, name: &str) -> Vec<Observation> {
        use hickory_resolver::proto::rr::{RData, RecordType};
        let mut out = Vec::new();
        // The hickory resolver's high-level API auto-follows CNAMEs, so we
        // issue a raw `lookup(..., RecordType::CNAME)` to surface the
        // alias chain explicitly. If the type lookup is unsupported we
        // silently skip — the rest of the scan still completes.
        if let Ok(Ok(lookup)) = timeout(
            self.cfg.query_timeout,
            self.resolver.lookup(name, RecordType::CNAME),
        )
        .await
        {
            for rec in lookup.answers() {
                if let RData::CNAME(cname) = &rec.data {
                    out.push(Observation::DnsRecord {
                        record: DnsRecordKind::Cname,
                        value: cname.to_string(),
                    });
                }
            }
        }
        out
    }
}

#[async_trait]
impl Scanner for DnsResolverScanner {
    fn id(&self) -> ScannerId {
        DNS_RESOLVER_ID
    }

    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            max_intensity: ScanIntensity::Standard,
            target_kinds: std::iter::once(TargetKind::Domain).collect(),
            max_throughput_obs_per_sec: 64,
        }
    }

    async fn scan(
        &self,
        ctx: ScanContext,
        target: ScopeTarget,
    ) -> Result<ScanResult, DiscoveryError> {
        let domain = match &target {
            ScopeTarget::Domain(d) => d.clone(),
            _ => {
                return Err(DiscoveryError::Config(format!(
                    "dns resolver only supports domain targets, got {target}",
                )));
            }
        };

        let _permit = ctx.rate_limiter.acquire(&target.canonical_key()).await?;

        let started_at = OffsetDateTime::now_utc();
        tracing::info!(scanner_id = %self.id(), target = %domain, "dns scan begin");

        let observations = self.run_queries(domain.as_str()).await?;

        let ended_at = OffsetDateTime::now_utc();
        tracing::info!(
            scanner_id = %self.id(),
            target = %domain,
            records = observations.len(),
            "dns scan end",
        );

        Ok(ScanResult {
            scanner_id: self.id(),
            target,
            observations,
            started_at,
            ended_at,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn empty_resolvers_rejected() {
        let r = DnsResolverScanner::new(DnsScannerConfig {
            resolvers: vec![],
            query_timeout: Duration::from_secs(1),
        });
        assert!(matches!(r, Err(DiscoveryError::Config(_))));
    }

    #[test]
    fn zero_timeout_rejected() {
        let r = DnsResolverScanner::new(DnsScannerConfig {
            resolvers: vec!["1.1.1.1:53".parse().unwrap()],
            query_timeout: Duration::from_secs(0),
        });
        assert!(matches!(r, Err(DiscoveryError::Config(_))));
    }

    #[test]
    fn capabilities_support_domain_only() {
        let s = DnsResolverScanner::new(DnsScannerConfig {
            resolvers: vec!["1.1.1.1:53".parse().unwrap()],
            query_timeout: Duration::from_secs(1),
        })
        .unwrap();
        let caps = s.capabilities();
        assert!(caps.target_kinds.contains(&TargetKind::Domain));
        assert!(!caps.target_kinds.contains(&TargetKind::Ip));
    }
}
