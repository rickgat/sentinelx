//! Host inventory: the bundle of host facts the agent reports each tick.
//!
//! Submodules implement narrow parsers (`/etc/os-release`, `/proc/net/tcp`,
//! `/proc/mounts`, etc.) that all return owned, `Serialize`-friendly types.
//! This module assembles them into a single [`Inventory`] payload.

pub mod containers;
pub mod kernel;
pub mod mounts;
pub mod os_release;
pub mod sockets;

use std::path::{Path, PathBuf};

use serde::Serialize;

pub use containers::ContainerSummary;
pub use mounts::Mount;
pub use os_release::OsRelease;
pub use sockets::ListeningSocket;

use crate::fingerprint::HostFingerprint;

/// Default Linux paths the agent reads when present. Tests inject overrides.
const DEFAULT_OS_RELEASE: &str = "/etc/os-release";
const DEFAULT_KERNEL: &str = "/proc/sys/kernel/osrelease";
const DEFAULT_PROC_NET_TCP: &str = "/proc/net/tcp";
const DEFAULT_PROC_NET_TCP6: &str = "/proc/net/tcp6";
const DEFAULT_PROC_MOUNTS: &str = "/proc/mounts";

/// Schema version baked into every payload — bump when fields change.
pub const SCHEMA_VERSION: u8 = 1;

/// A single inventory snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct Inventory {
    pub schema_version: u8,
    #[serde(with = "time::serde::rfc3339")]
    pub collected_at: time::OffsetDateTime,
    pub host_fingerprint: String,
    pub os: Option<OsRelease>,
    pub kernel: Option<String>,
    pub mounts: Vec<Mount>,
    pub listening_sockets: Vec<ListeningSocket>,
    pub containers: Vec<ContainerSummary>,
}

/// Inputs that drive a single inventory collection.
#[derive(Debug, Clone)]
pub struct InventoryInputs {
    /// Hostname (typically from `hostname` syscall — caller resolves).
    pub hostname: String,
    /// Stable node UID (e.g. K8s node UID, or `/etc/machine-id`).
    pub node_uid: String,
    /// Optional path to the container runtime socket.
    pub runtime_socket: Option<PathBuf>,
}

/// Collect a real inventory from the default Linux paths. On non-Linux hosts
/// the missing files cause partial fields to be reported (the binary still
/// runs to completion in CI).
pub async fn collect(inputs: &InventoryInputs) -> Inventory {
    collect_from(
        inputs,
        Path::new(DEFAULT_OS_RELEASE),
        Path::new(DEFAULT_KERNEL),
        Path::new(DEFAULT_PROC_NET_TCP),
        Path::new(DEFAULT_PROC_NET_TCP6),
        Path::new(DEFAULT_PROC_MOUNTS),
    )
    .await
}

/// Collect an inventory from explicit paths (used by tests).
pub async fn collect_from(
    inputs: &InventoryInputs,
    os_release_path: &Path,
    kernel_path: &Path,
    proc_tcp_path: &Path,
    proc_tcp6_path: &Path,
    proc_mounts_path: &Path,
) -> Inventory {
    let os = read_os_release(os_release_path);
    let kernel = read_kernel_safe(kernel_path);
    let mounts = read_mounts(proc_mounts_path);
    let listening_sockets = read_sockets(proc_tcp_path, proc_tcp6_path);
    let containers = containers::collect_containers(inputs.runtime_socket.as_deref()).await;
    let fingerprint =
        HostFingerprint::compute(&inputs.hostname, &inputs.node_uid, kernel.as_deref());

    Inventory {
        schema_version: SCHEMA_VERSION,
        collected_at: time::OffsetDateTime::now_utc(),
        host_fingerprint: fingerprint.into_hex(),
        os,
        kernel,
        mounts,
        listening_sockets,
        containers,
    }
}

fn read_os_release(path: &Path) -> Option<OsRelease> {
    if !path.exists() {
        tracing::warn!(
            path = %path.display(),
            "running outside a Linux node — features degraded"
        );
        return None;
    }
    match std::fs::read_to_string(path) {
        Ok(contents) => Some(os_release::parse_os_release(&contents)),
        Err(err) => {
            tracing::warn!(error = %err, "failed to read os-release; skipping");
            None
        }
    }
}

fn read_kernel_safe(path: &Path) -> Option<String> {
    match kernel::read_kernel(path) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(error = %err, "failed to read kernel osrelease; skipping");
            None
        }
    }
}

fn read_mounts(path: &Path) -> Vec<Mount> {
    if !path.exists() {
        return Vec::new();
    }
    match std::fs::read_to_string(path) {
        Ok(contents) => mounts::parse_mounts(&contents),
        Err(err) => {
            tracing::warn!(error = %err, "failed to read mounts; skipping");
            Vec::new()
        }
    }
}

fn read_sockets(tcp: &Path, tcp6: &Path) -> Vec<ListeningSocket> {
    let mut all = Vec::new();
    if tcp.exists() {
        match std::fs::read_to_string(tcp) {
            Ok(contents) => all.extend(sockets::parse_proc_net_tcp(&contents)),
            Err(err) => tracing::warn!(error = %err, "failed to read /proc/net/tcp"),
        }
    }
    if tcp6.exists() {
        match std::fs::read_to_string(tcp6) {
            Ok(contents) => all.extend(sockets::parse_proc_net_tcp6(&contents)),
            Err(err) => tracing::warn!(error = %err, "failed to read /proc/net/tcp6"),
        }
    }
    all
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn inventory_serialises_to_expected_shape() {
        let inv = Inventory {
            schema_version: SCHEMA_VERSION,
            collected_at: time::OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            host_fingerprint: "deadbeef".to_owned(),
            os: Some(OsRelease {
                id: Some("ubuntu".to_owned()),
                version_id: Some("24.04".to_owned()),
                pretty_name: Some("Ubuntu 24.04 LTS".to_owned()),
            }),
            kernel: Some("6.8.0".to_owned()),
            mounts: vec![],
            listening_sockets: vec![],
            containers: vec![],
        };
        let json = serde_json::to_value(&inv).unwrap();
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["host_fingerprint"], "deadbeef");
        assert_eq!(json["os"]["id"], "ubuntu");
        assert_eq!(json["os"]["version_id"], "24.04");
        assert_eq!(json["kernel"], "6.8.0");
        assert!(json["mounts"].is_array());
        assert!(json["listening_sockets"].is_array());
        assert!(json["containers"].is_array());
        // RFC3339 timestamp present.
        assert!(json["collected_at"].is_string());
    }
}
