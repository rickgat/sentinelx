//! Container image vulnerability scanner.
//!
//! Wraps [trivy](https://github.com/aquasecurity/trivy) as a child process
//! to detect known CVEs in OS and language-ecosystem packages installed in
//! a container image.
//!
//! The scanner accepts [`ScopeTarget::Url`] targets where the URL scheme is
//! one of:
//!
//! - `oci://image:tag` — OCI-distribution image reference.
//! - `docker://image:tag` — Docker registry image reference.
//!
//! Other schemes are rejected before any subprocess is invoked.
//!
//! ## Why subprocess?
//!
//! `trivy`'s vulnerability database is multi-megabyte and updated daily;
//! embedding it in this crate would couple `SentinelX`'s release cadence
//! to `trivy`'s. A shell-out is the pragmatic choice for Phase 1 and
//! matches the design of [`crate::scanner::sca`].
//!
//! ## Safety
//!
//! - The binary path is taken from configuration; no `PATH` lookups.
//! - The target URL is validated against an allowlist of schemes.
//! - The scheme prefix is stripped before passing the reference to trivy;
//!   trivy receives only the image reference itself, never a URL.
//! - Stdout is parsed as JSON; deserialisation failures degrade to an
//!   empty result set, never a panic.

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
pub const CONTAINER_SCANNER_ID: ScannerId = ScannerId::new("container_trivy_v1");

/// Allowed URL schemes for the container scanner's targets.
const ALLOWED_SCHEMES: &[&str] = &["oci", "docker"];

/// Severity filter passed to `trivy image --severity`.
const TRIVY_SEVERITY_FILTER: &str = "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL";

/// Configuration for [`ContainerScanner`].
#[derive(Debug, Clone)]
pub struct ContainerScannerConfig {
    /// Path to the `trivy` binary. Must be absolute — no `PATH` lookup.
    pub trivy_binary: PathBuf,
    /// Wall-clock budget for one invocation.
    pub exec_timeout: Duration,
}

impl ContainerScannerConfig {
    /// Validate the configuration.
    pub fn check(&self) -> Result<(), DiscoveryError> {
        if !self.trivy_binary.is_absolute() {
            return Err(DiscoveryError::config(
                "container.trivy_binary must be an absolute path",
            ));
        }
        if self.exec_timeout.is_zero() {
            return Err(DiscoveryError::config("container.exec_timeout must be > 0"));
        }
        Ok(())
    }
}

/// Trivy-backed container image vulnerability scanner.
#[derive(Debug)]
pub struct ContainerScanner {
    cfg: ContainerScannerConfig,
}

impl ContainerScanner {
    /// Build a new scanner from a validated config.
    pub fn new(cfg: ContainerScannerConfig) -> Result<Self, DiscoveryError> {
        cfg.check()?;
        Ok(Self { cfg })
    }

    /// Validate the target and return the image reference with the scheme
    /// prefix stripped. The trimmed reference is what gets passed to trivy.
    fn validate_target(target: &ScopeTarget) -> Result<String, DiscoveryError> {
        let ScopeTarget::Url(url) = target else {
            return Err(DiscoveryError::config(
                "container scanner accepts only Url targets (oci:// / docker://)",
            ));
        };
        let scheme = url.scheme();
        if !ALLOWED_SCHEMES.contains(&scheme) {
            return Err(DiscoveryError::config(format!(
                "container: unsupported scheme '{scheme}' (allowed: {ALLOWED_SCHEMES:?})",
            )));
        }
        // Strip the `scheme://` prefix — trivy expects a bare image reference.
        let s = url.as_str();
        let prefix = format!("{scheme}://");
        let reference = s.strip_prefix(&prefix).unwrap_or(s).to_owned();
        if reference.is_empty() {
            return Err(DiscoveryError::config(
                "container: empty image reference after stripping scheme",
            ));
        }
        Ok(reference)
    }

    async fn run_trivy(&self, image_arg: &str) -> Result<Vec<u8>, DiscoveryError> {
        let mut cmd = Command::new(&self.cfg.trivy_binary);
        cmd.arg("image")
            .arg("--format")
            .arg("json")
            .arg("--quiet")
            .arg("--no-progress")
            .arg("--severity")
            .arg(TRIVY_SEVERITY_FILTER)
            .arg(image_arg);
        cmd.kill_on_drop(true);

        let exec = cmd.output();
        let output = timeout(self.cfg.exec_timeout, exec)
            .await
            .map_err(|_| DiscoveryError::Timeout)?
            .map_err(|e| DiscoveryError::Io(format!("trivy spawn: {e}")))?;

        if !output.status.success() {
            return Err(DiscoveryError::Io(format!(
                "trivy exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(output.stdout)
    }
}

#[async_trait]
impl Scanner for ContainerScanner {
    fn id(&self) -> ScannerId {
        CONTAINER_SCANNER_ID
    }

    fn capabilities(&self) -> ScannerCapabilities {
        let mut kinds = std::collections::HashSet::new();
        kinds.insert(TargetKind::Url);
        ScannerCapabilities {
            max_intensity: ScanIntensity::Standard,
            target_kinds: kinds,
            max_throughput_obs_per_sec: 200,
        }
    }

    async fn scan(
        &self,
        ctx: ScanContext,
        target: ScopeTarget,
    ) -> Result<ScanResult, DiscoveryError> {
        let image_arg = Self::validate_target(&target)?;

        // One token per shell-out — trivy is a single bulk event.
        let _permit = ctx
            .rate_limiter
            .acquire(&target.canonical_key())
            .await
            .map_err(|_| DiscoveryError::RateLimited)?;

        let started_at = OffsetDateTime::now_utc();
        let stdout = self.run_trivy(&image_arg).await?;
        let ended_at = OffsetDateTime::now_utc();

        let observations = parse_trivy_output(&stdout);
        tracing::info!(
            scanner = %CONTAINER_SCANNER_ID,
            tenant_id = %ctx.tenant_id,
            engagement_id = %ctx.engagement_id,
            target = %image_arg,
            matches = observations.len(),
            "container.scan.complete",
        );
        Ok(ScanResult {
            scanner_id: CONTAINER_SCANNER_ID,
            target,
            observations,
            started_at,
            ended_at,
        })
    }
}

/// Parse trivy's JSON output into observations. Unknown / malformed fields
/// are tolerated — only the well-formed vulnerability entries contribute
/// observations.
pub fn parse_trivy_output(bytes: &[u8]) -> Vec<Observation> {
    let Ok(root) = serde_json::from_slice::<Value>(bytes) else {
        return Vec::new();
    };
    let Some(results) = root.get("Results").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out: Vec<Observation> = Vec::new();
    for result in results {
        let pkg_type = result
            .get("Type")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let Some(vulns) = result.get("Vulnerabilities").and_then(Value::as_array) else {
            continue;
        };
        for vuln in vulns {
            if let Some(obs) = parse_vulnerability(pkg_type, vuln) {
                out.push(obs);
            }
        }
    }
    out
}

fn parse_vulnerability(pkg_type: &str, v: &Value) -> Option<Observation> {
    let id = v.get("VulnerabilityID").and_then(Value::as_str)?;
    let name = v.get("PkgName").and_then(Value::as_str)?;
    let version = v
        .get("InstalledVersion")
        .and_then(Value::as_str)
        .unwrap_or("");
    let severity = v
        .get("Severity")
        .and_then(Value::as_str)
        .unwrap_or("UNKNOWN");
    let fix = v.get("FixedVersion").and_then(Value::as_str).unwrap_or("");
    let fix_versions = if fix.is_empty() {
        Vec::new()
    } else {
        vec![fix.to_owned()]
    };
    Some(Observation::PackageVulnerability {
        package: format!("{pkg_type}:{name}"),
        version: version.to_owned(),
        vulnerability_id: id.to_owned(),
        severity: severity.to_ascii_lowercase(),
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
        let cfg = ContainerScannerConfig {
            trivy_binary: PathBuf::from("trivy"),
            exec_timeout: Duration::from_secs(30),
        };
        assert!(cfg.check().is_err());
    }

    #[test]
    fn config_rejects_zero_timeout() {
        let cfg = ContainerScannerConfig {
            trivy_binary: PathBuf::from("/usr/local/bin/trivy"),
            exec_timeout: Duration::ZERO,
        };
        assert!(cfg.check().is_err());
    }

    #[test]
    fn config_accepts_valid() {
        let cfg = ContainerScannerConfig {
            trivy_binary: PathBuf::from("/usr/local/bin/trivy"),
            exec_timeout: Duration::from_secs(60),
        };
        assert!(cfg.check().is_ok());
    }

    #[test]
    fn new_rejects_bad_config() {
        let cfg = ContainerScannerConfig {
            trivy_binary: PathBuf::from("trivy"),
            exec_timeout: Duration::from_secs(30),
        };
        assert!(matches!(
            ContainerScanner::new(cfg),
            Err(DiscoveryError::Config(_))
        ));
    }

    #[test]
    fn target_validator_accepts_oci() {
        let t = ScopeTarget::Url(Url::parse("oci://docker.io/library/alpine").unwrap());
        let arg = ContainerScanner::validate_target(&t).unwrap();
        assert_eq!(arg, "docker.io/library/alpine");
    }

    #[test]
    fn target_validator_accepts_docker() {
        let t = ScopeTarget::Url(Url::parse("docker://registry.io/library/nginx").unwrap());
        let arg = ContainerScanner::validate_target(&t).unwrap();
        assert_eq!(arg, "registry.io/library/nginx");
    }

    #[test]
    fn target_validator_rejects_http_scheme() {
        let t = ScopeTarget::Url(Url::parse("https://example.com/").unwrap());
        assert!(ContainerScanner::validate_target(&t).is_err());
    }

    #[test]
    fn target_validator_rejects_dir_scheme() {
        let t = ScopeTarget::Url(Url::parse("dir:///srv/app").unwrap());
        assert!(ContainerScanner::validate_target(&t).is_err());
    }

    #[test]
    fn target_validator_rejects_non_url() {
        let t =
            ScopeTarget::Domain(crate::contracts::Fqdn::new("example.com").expect("static input"));
        assert!(ContainerScanner::validate_target(&t).is_err());
    }

    #[test]
    fn parse_extracts_two_findings_from_trivy_payload() {
        let payload = br#"{
          "Results": [
            {
              "Target": "alpine:3.20 (alpine 3.20.0)",
              "Class": "os-pkgs",
              "Type": "alpine",
              "Vulnerabilities": [
                {
                  "VulnerabilityID": "CVE-2024-12345",
                  "PkgName": "openssl",
                  "InstalledVersion": "3.0.0",
                  "FixedVersion": "3.0.1",
                  "Severity": "HIGH",
                  "Title": "openssl bug"
                },
                {
                  "VulnerabilityID": "CVE-2024-99999",
                  "PkgName": "busybox",
                  "InstalledVersion": "1.36.0",
                  "Severity": "LOW"
                }
              ]
            }
          ]
        }"#;
        let obs = parse_trivy_output(payload);
        assert_eq!(obs.len(), 2);
        match &obs[0] {
            Observation::PackageVulnerability {
                package,
                version,
                vulnerability_id,
                severity,
                fix_versions,
            } => {
                assert_eq!(package, "alpine:openssl");
                assert_eq!(version, "3.0.0");
                assert_eq!(vulnerability_id, "CVE-2024-12345");
                assert_eq!(severity, "high");
                assert_eq!(fix_versions, &vec!["3.0.1".to_owned()]);
            }
            other => panic!("unexpected observation: {other:?}"),
        }
        match &obs[1] {
            Observation::PackageVulnerability {
                package,
                vulnerability_id,
                severity,
                fix_versions,
                ..
            } => {
                assert_eq!(package, "alpine:busybox");
                assert_eq!(vulnerability_id, "CVE-2024-99999");
                assert_eq!(severity, "low");
                assert!(fix_versions.is_empty());
            }
            other => panic!("unexpected observation: {other:?}"),
        }
    }

    #[test]
    fn parse_tolerates_empty() {
        assert!(parse_trivy_output(b"").is_empty());
        assert!(parse_trivy_output(b"{}").is_empty());
        assert!(parse_trivy_output(b"{\"Results\":[]}").is_empty());
        assert!(parse_trivy_output(
            b"{\"Results\":[{\"Type\":\"alpine\",\"Vulnerabilities\":[]}]}"
        )
        .is_empty());
    }

    #[test]
    fn parse_tolerates_garbage() {
        assert!(parse_trivy_output(b"not json").is_empty());
        assert!(parse_trivy_output(b"{\"Results\":\"oops\"}").is_empty());
        assert!(parse_trivy_output(b"null").is_empty());
    }

    #[test]
    fn parse_skips_entries_missing_id() {
        let payload = br#"{
          "Results": [
            {
              "Type": "alpine",
              "Vulnerabilities": [
                {"PkgName": "openssl", "Severity": "HIGH"}
              ]
            }
          ]
        }"#;
        assert!(parse_trivy_output(payload).is_empty());
    }

    #[test]
    fn parse_defaults_severity_to_lowercased_unknown() {
        let payload = br#"{
          "Results": [
            {
              "Type": "alpine",
              "Vulnerabilities": [
                {"VulnerabilityID": "CVE-1", "PkgName": "x"}
              ]
            }
          ]
        }"#;
        let obs = parse_trivy_output(payload);
        assert_eq!(obs.len(), 1);
        match &obs[0] {
            Observation::PackageVulnerability { severity, .. } => assert_eq!(severity, "unknown"),
            other => panic!("unexpected observation: {other:?}"),
        }
    }
}
