//! Software Composition Analysis scanner.
//!
//! Wraps [grype](https://github.com/anchore/grype) as a child process to
//! match installed packages against the OSV / GitHub Advisory / NVD
//! databases. The scanner accepts [`ScopeTarget::Url`] targets where the URL
//! scheme is one of:
//!
//! - `oci://image:tag` — container image (e.g. `oci://alpine:3.20`).
//! - `git+https://…` — git repository URL.
//! - `dir://…` — local filesystem path.
//!
//! Other schemes are rejected before any subprocess is invoked.
//!
//! ## Why subprocess?
//!
//! `grype`'s match database is multi-megabyte and updated daily; embedding
//! it in this crate would couple `SentinelX`'s release cadence to `grype`'s.
//! A shell-out is the pragmatic choice for Phase 1.
//!
//! ## Safety
//!
//! - The binary path is taken from configuration; no `PATH` lookups.
//! - The target URL is validated against an allowlist of schemes.
//! - The argument vector never includes shell metacharacters; `tokio::process::Command`
//!   uses `execvp`-style execution so there is no shell interpolation.
//! - Stdout is parsed as JSON; deserialisation failures degrade to an empty
//!   result set, never a panic.

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use time::OffsetDateTime;
use tokio::process::Command;
use tokio::time::timeout;

use crate::contracts::{ScanIntensity, ScopeTarget};
use crate::error::DiscoveryError;
use crate::model::observation::Observation;
use crate::model::scan_result::ScanResult;
use crate::service::scanner::{ScanContext, Scanner, ScannerCapabilities, ScannerId, TargetKind};

/// Stable id used to register / look up this scanner.
pub const SCA_SCANNER_ID: ScannerId = ScannerId::new("sca_grype_v1");

/// Allowed URL schemes for the SCA scanner's targets.
const ALLOWED_SCHEMES: &[&str] = &["oci", "git+https", "git+ssh", "dir"];

/// Configuration for [`ScaScanner`].
#[derive(Debug, Clone)]
pub struct ScaScannerConfig {
    /// Path to the `grype` binary. Absolute path — no `PATH` lookup.
    pub grype_binary: PathBuf,
    /// Wall-clock budget for one invocation.
    pub exec_timeout: Duration,
}

impl ScaScannerConfig {
    /// Validate the configuration.
    pub fn check(&self) -> Result<(), DiscoveryError> {
        if !self.grype_binary.is_absolute() {
            return Err(DiscoveryError::config(
                "sca.grype_binary must be an absolute path",
            ));
        }
        if self.exec_timeout.is_zero() {
            return Err(DiscoveryError::config("sca.exec_timeout must be > 0"));
        }
        Ok(())
    }
}

/// Grype-backed SCA scanner.
#[derive(Debug)]
pub struct ScaScanner {
    cfg: ScaScannerConfig,
}

impl ScaScanner {
    /// Build a new scanner from a validated config.
    pub fn new(cfg: ScaScannerConfig) -> Result<Self, DiscoveryError> {
        cfg.check()?;
        Ok(Self { cfg })
    }

    fn validate_target(target: &ScopeTarget) -> Result<String, DiscoveryError> {
        let ScopeTarget::Url(url) = target else {
            return Err(DiscoveryError::config(
                "sca scanner accepts only Url targets (oci:// / git+ / dir://)",
            ));
        };
        let scheme = url.scheme();
        if !ALLOWED_SCHEMES.contains(&scheme) {
            return Err(DiscoveryError::config(format!(
                "sca: unsupported scheme '{scheme}' (allowed: {ALLOWED_SCHEMES:?})",
            )));
        }
        Ok(url.to_string())
    }

    async fn run_grype(&self, target_arg: &str) -> Result<Vec<u8>, DiscoveryError> {
        let mut cmd = Command::new(&self.cfg.grype_binary);
        cmd.arg(target_arg).arg("-o").arg("json").arg("-q");
        cmd.kill_on_drop(true);

        let exec = cmd.output();
        let output = timeout(self.cfg.exec_timeout, exec)
            .await
            .map_err(|_| DiscoveryError::Timeout)?
            .map_err(|e| DiscoveryError::Io(format!("grype spawn: {e}")))?;

        if !output.status.success() {
            return Err(DiscoveryError::Io(format!(
                "grype exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(output.stdout)
    }
}

#[async_trait]
impl Scanner for ScaScanner {
    fn id(&self) -> ScannerId {
        SCA_SCANNER_ID
    }

    fn capabilities(&self) -> ScannerCapabilities {
        let mut target_kinds = std::collections::HashSet::new();
        target_kinds.insert(TargetKind::Url);
        ScannerCapabilities {
            max_intensity: ScanIntensity::Standard,
            target_kinds,
            max_throughput_obs_per_sec: 200,
        }
    }

    async fn scan(
        &self,
        ctx: ScanContext,
        target: ScopeTarget,
    ) -> Result<ScanResult, DiscoveryError> {
        let target_arg = Self::validate_target(&target)?;

        // One token per shell-out — grype is a single network/disk event.
        let _permit = ctx
            .rate_limiter
            .acquire(&target_arg)
            .await
            .map_err(|_| DiscoveryError::RateLimited)?;

        let started = OffsetDateTime::now_utc();
        let stdout = self.run_grype(&target_arg).await?;
        let ended = OffsetDateTime::now_utc();

        let observations = parse_grype_output(&stdout);
        tracing::info!(
            scanner = %SCA_SCANNER_ID,
            tenant_id = %ctx.tenant_id,
            engagement_id = %ctx.engagement_id,
            target = %target_arg,
            matches = observations.len(),
            "sca.scan.complete",
        );
        Ok(ScanResult {
            scanner_id: SCA_SCANNER_ID,
            target,
            observations,
            started_at: started,
            ended_at: ended,
        })
    }
}

/// Parse grype's JSON output into observations. Unknown / malformed fields
/// are tolerated — only the well-formed matches contribute observations.
pub fn parse_grype_output(bytes: &[u8]) -> Vec<Observation> {
    let Ok(root) = serde_json::from_slice::<Value>(bytes) else {
        return Vec::new();
    };
    let Some(matches) = root.get("matches").and_then(Value::as_array) else {
        return Vec::new();
    };
    matches
        .iter()
        .filter_map(parse_match)
        .collect::<Vec<Observation>>()
}

fn parse_match(m: &Value) -> Option<Observation> {
    let vuln = m.get("vulnerability")?;
    let artifact = m.get("artifact")?;
    let id = vuln.get("id").and_then(Value::as_str)?;
    let severity = vuln.get("severity").and_then(Value::as_str)?;
    let name = artifact.get("name").and_then(Value::as_str)?;
    let version = artifact.get("version").and_then(Value::as_str)?;
    let ecosystem = artifact
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let fix_versions = vuln
        .get("fix")
        .and_then(|f| f.get("versions"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Some(Observation::PackageVulnerability {
        package: format!("{ecosystem}:{name}"),
        version: version.to_owned(),
        vulnerability_id: id.to_owned(),
        severity: severity.to_owned(),
        fix_versions,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use url::Url;

    #[test]
    fn config_rejects_relative_binary() {
        let cfg = ScaScannerConfig {
            grype_binary: PathBuf::from("grype"),
            exec_timeout: Duration::from_secs(30),
        };
        assert!(cfg.check().is_err());
    }

    #[test]
    fn config_rejects_zero_timeout() {
        let cfg = ScaScannerConfig {
            grype_binary: PathBuf::from("/usr/local/bin/grype"),
            exec_timeout: Duration::ZERO,
        };
        assert!(cfg.check().is_err());
    }

    #[test]
    fn target_validator_accepts_oci() {
        let t = ScopeTarget::Url(Url::parse("oci://docker.io/library/alpine").unwrap());
        assert_eq!(
            ScaScanner::validate_target(&t).unwrap(),
            "oci://docker.io/library/alpine"
        );
    }

    #[test]
    fn target_validator_rejects_http() {
        let t = ScopeTarget::Url(Url::parse("https://example.com").unwrap());
        assert!(ScaScanner::validate_target(&t).is_err());
    }

    #[test]
    fn target_validator_rejects_domain_kind() {
        let t =
            ScopeTarget::Domain(crate::contracts::Fqdn::new("example.com").expect("static input"));
        assert!(ScaScanner::validate_target(&t).is_err());
    }

    #[test]
    fn parse_grype_extracts_matches() {
        let payload = br#"{
          "matches": [
            {
              "vulnerability": {
                "id": "CVE-2024-12345",
                "severity": "High",
                "fix": { "versions": ["1.2.4"] }
              },
              "artifact": { "name": "openssl", "version": "1.1.1", "type": "deb" }
            },
            {
              "vulnerability": { "id": "GHSA-abcd-1234-wxyz", "severity": "Critical" },
              "artifact": { "name": "lodash", "version": "4.17.20", "type": "npm" }
            }
          ]
        }"#;
        let obs = parse_grype_output(payload);
        assert_eq!(obs.len(), 2);
        match &obs[0] {
            Observation::PackageVulnerability {
                package,
                vulnerability_id,
                severity,
                fix_versions,
                ..
            } => {
                assert_eq!(package, "deb:openssl");
                assert_eq!(vulnerability_id, "CVE-2024-12345");
                assert_eq!(severity, "High");
                assert_eq!(fix_versions, &vec!["1.2.4".to_owned()]);
            }
            other => panic!("unexpected observation: {other:?}"),
        }
        match &obs[1] {
            Observation::PackageVulnerability {
                package,
                vulnerability_id,
                fix_versions,
                ..
            } => {
                assert_eq!(package, "npm:lodash");
                assert_eq!(vulnerability_id, "GHSA-abcd-1234-wxyz");
                assert!(fix_versions.is_empty());
            }
            other => panic!("unexpected observation: {other:?}"),
        }
    }

    #[test]
    fn parse_grype_tolerates_garbage() {
        assert!(parse_grype_output(b"not json").is_empty());
        assert!(parse_grype_output(b"{}").is_empty());
        assert!(parse_grype_output(b"{\"matches\":[]}").is_empty());
    }
}
