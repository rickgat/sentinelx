//! Non-intrusive TCP connect-probe.
//!
//! For each port in the configured set the scanner:
//!
//! 1. Acquires a rate-limiter token (one per connection attempt).
//! 2. Attempts a `connect` with a strict timeout.
//! 3. On success, performs a single read of up to `max_banner_bytes` bytes
//!    **without sending any payload**.
//!
//! Anything else — service-probe payloads, version triggers, protocol
//! fuzzing — is **explicitly forbidden**. This is a Phase 1 passive scanner.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::contracts::{ScanIntensity, ScopeTarget};
use crate::error::DiscoveryError;
use crate::model::observation::Observation;
use crate::model::scan_result::ScanResult;
use crate::service::scanner::{ScanContext, Scanner, ScannerCapabilities, ScannerId, TargetKind};

/// Stable id used to register / look up this scanner.
pub const TCP_PORT_PROBE_ID: ScannerId = ScannerId::new("tcp_port_probe_v1");

/// Configuration for the TCP port probe scanner.
#[derive(Debug, Clone)]
pub struct TcpPortProbeConfig {
    /// Ports to probe per target. Bounded by config; the orchestrator MUST
    /// pass a list whose length is `<= DiscoveryConfig::port_scan_max_ports`.
    pub ports: Vec<u16>,
    /// Per-connection connect timeout.
    pub connect_timeout: Duration,
    /// Per-connection read timeout when waiting for a banner.
    pub banner_read_timeout: Duration,
    /// Upper bound on banner bytes captured. Default budget is small —
    /// banners are diagnostic, not full responses.
    pub max_banner_bytes: usize,
}

impl TcpPortProbeConfig {
    /// Validate the configuration.
    pub fn check(&self) -> Result<(), DiscoveryError> {
        if self.ports.is_empty() {
            return Err(DiscoveryError::config(
                "tcp port probe requires at least one port",
            ));
        }
        if self.connect_timeout.is_zero() {
            return Err(DiscoveryError::config(
                "tcp port probe connect_timeout must be > 0",
            ));
        }
        if self.banner_read_timeout.is_zero() {
            return Err(DiscoveryError::config(
                "tcp port probe banner_read_timeout must be > 0",
            ));
        }
        if self.max_banner_bytes == 0 {
            return Err(DiscoveryError::config(
                "tcp port probe max_banner_bytes must be > 0",
            ));
        }
        Ok(())
    }
}

/// TCP connect-probe scanner.
#[derive(Debug)]
pub struct TcpPortProbeScanner {
    cfg: TcpPortProbeConfig,
}

impl TcpPortProbeScanner {
    /// Build a new scanner from a validated config.
    pub fn new(cfg: TcpPortProbeConfig) -> Result<Self, DiscoveryError> {
        cfg.check()?;
        Ok(Self { cfg })
    }

    async fn probe_one(&self, addr: SocketAddr) -> Result<Option<Observation>, DiscoveryError> {
        let connect = TcpStream::connect(addr);
        let stream = match timeout(self.cfg.connect_timeout, connect).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                // Closed / refused / unreachable: not an error, just "no open port".
                tracing::debug!(addr = %addr, error = %e, "tcp connect refused");
                return Ok(None);
            }
            Err(_) => {
                // Connect timed out — treat as closed.
                tracing::debug!(addr = %addr, "tcp connect timed out");
                return Ok(None);
            }
        };

        // Read up to N bytes for a banner. Do NOT send anything.
        let banner = self.try_read_banner(stream).await;
        Ok(Some(Observation::OpenPort {
            port: addr.port(),
            banner,
        }))
    }

    async fn try_read_banner(&self, mut stream: TcpStream) -> Option<String> {
        let mut buf = vec![0u8; self.cfg.max_banner_bytes];
        match timeout(self.cfg.banner_read_timeout, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                buf.truncate(n);
                let lossy = String::from_utf8_lossy(&buf).into_owned();
                lossy
                    .lines()
                    .next()
                    .map(str::trim)
                    .map(str::to_owned)
                    .filter(|s| !s.is_empty())
            }
            _ => None,
        }
    }

    fn target_to_ip(target: &ScopeTarget) -> Result<IpAddr, DiscoveryError> {
        match target {
            ScopeTarget::Ip(ip) => Ok(*ip),
            ScopeTarget::Cidr(net) => Ok(net.network()),
            other => Err(DiscoveryError::Config(format!(
                "tcp port probe requires an ip / cidr target, got {other}",
            ))),
        }
    }
}

#[async_trait]
impl Scanner for TcpPortProbeScanner {
    fn id(&self) -> ScannerId {
        TCP_PORT_PROBE_ID
    }

    fn capabilities(&self) -> ScannerCapabilities {
        ScannerCapabilities {
            max_intensity: ScanIntensity::Light,
            target_kinds: std::iter::once(TargetKind::Ip).collect(),
            max_throughput_obs_per_sec: 8,
        }
    }

    async fn scan(
        &self,
        ctx: ScanContext,
        target: ScopeTarget,
    ) -> Result<ScanResult, DiscoveryError> {
        let ip = Self::target_to_ip(&target)?;
        let started_at = OffsetDateTime::now_utc();
        tracing::info!(scanner_id = %self.id(), target = %target, ports = self.cfg.ports.len(), "tcp probe begin");

        let mut observations = Vec::new();
        for &port in &self.cfg.ports {
            let _permit = ctx.rate_limiter.acquire(&target.canonical_key()).await?;
            let addr = SocketAddr::new(ip, port);
            if let Some(obs) = self.probe_one(addr).await? {
                observations.push(obs);
            }
        }

        let ended_at = OffsetDateTime::now_utc();
        tracing::info!(scanner_id = %self.id(), target = %target, open = observations.len(), "tcp probe end");
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
    fn empty_ports_rejected() {
        let r = TcpPortProbeScanner::new(TcpPortProbeConfig {
            ports: vec![],
            connect_timeout: Duration::from_secs(1),
            banner_read_timeout: Duration::from_secs(1),
            max_banner_bytes: 256,
        });
        assert!(matches!(r, Err(DiscoveryError::Config(_))));
    }

    #[test]
    fn capabilities_support_ip_only() {
        let s = TcpPortProbeScanner::new(TcpPortProbeConfig {
            ports: vec![22],
            connect_timeout: Duration::from_secs(1),
            banner_read_timeout: Duration::from_secs(1),
            max_banner_bytes: 256,
        })
        .unwrap();
        assert!(s.capabilities().target_kinds.contains(&TargetKind::Ip));
    }
}
