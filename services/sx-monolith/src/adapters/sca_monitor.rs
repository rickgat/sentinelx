//! Continuous SCA / SBOM monitoring (#6).
//!
//! A background job that periodically parses a dependency-vulnerability
//! report (grype JSON, as produced by the `sbom-and-grype` CI job and
//! checked in under `sbom/`) and materialises each package vulnerability as
//! a platform `Finding`. Because findings flow through the shared repo, a
//! `Critical` dependency vuln automatically fans out to the incident sinks
//! via the alerting decorator (#2) — closing the "SCA in CI only" gap.
//!
//! Zero-config: runs only when bootstrap is enabled with a tenant id and the
//! configured SBOM report exists; otherwise it no-ops (production operators
//! point `SX_SCA_SBOM_PATH` at their scanner output). Inserts are
//! idempotent — the finding id is a deterministic digest of
//! `(tenant, package, version, vuln_id)`, so re-runs re-read the same row.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use sx_api::port::FindingRepositoryPort;
use sx_api::view::finding_view::FindingView;
use sx_discovery::model::observation::Observation;
use sx_discovery::scanner::parse_grype_output;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::task::JoinHandle;
use tracing::{info, warn};
use uuid::Uuid;

/// Default re-scan cadence.
const SCAN_INTERVAL: Duration = Duration::from_secs(3_600);

/// Deterministic UUID from a key (sha-256 → first 16 bytes). Stable across
/// runs so finding inserts are idempotent.
fn det_uuid(key: &str) -> Uuid {
    let digest = Sha256::digest(key.as_bytes());
    let bytes = digest
        .as_slice()
        .first_chunk::<16>()
        .copied()
        .unwrap_or([0u8; 16]);
    Uuid::from_bytes(bytes)
}

/// Normalise a grype severity tag onto the platform's severity vocabulary.
fn normalise_severity(raw: &str) -> &'static str {
    match raw.to_ascii_lowercase().as_str() {
        "critical" => "critical",
        "high" => "high",
        "medium" => "medium",
        "low" | "negligible" => "low",
        _ => "info",
    }
}

/// Convert one SCA observation into a `FindingView` for the given tenant.
/// Returns `None` for non-package observations.
fn observation_to_finding(
    tenant_id: Uuid,
    obs: &Observation,
    now_rfc3339: &str,
) -> Option<FindingView> {
    let Observation::PackageVulnerability {
        package,
        version,
        vulnerability_id,
        severity,
        fix_versions,
    } = obs
    else {
        return None;
    };
    let id = det_uuid(&format!(
        "{tenant_id}:{package}:{version}:{vulnerability_id}"
    ));
    let asset_id = det_uuid(&format!("{tenant_id}:sbom-dependency-surface"));
    let fix = if fix_versions.is_empty() {
        "no fixed version published".to_owned()
    } else {
        format!("fixed in {}", fix_versions.join(", "))
    };
    Some(FindingView {
        id: id.to_string(),
        tenant_id: tenant_id.to_string(),
        asset_id: asset_id.to_string(),
        severity: normalise_severity(severity).to_owned(),
        status: "open".to_owned(),
        title: format!("{package} {version}: {vulnerability_id}"),
        description: format!(
            "Dependency `{package}@{version}` is affected by {vulnerability_id} ({fix}). \
             Source: SCA/SBOM continuous monitor."
        ),
        cvss: None,
        cve_id: vulnerability_id
            .starts_with("CVE-")
            .then(|| vulnerability_id.clone()),
        first_seen: now_rfc3339.to_owned(),
        last_seen: now_rfc3339.to_owned(),
        metadata: Some(serde_json::json!({
            "source": "sca-monitor",
            "package": package,
            "version": version,
            "vulnerability_id": vulnerability_id,
            "fix_versions": fix_versions,
        })),
    })
}

/// Run one scan pass: parse the report and upsert each finding. Returns the
/// number of findings materialised, or an error if the report is unreadable.
async fn scan_once(
    findings: &Arc<dyn FindingRepositoryPort>,
    tenant_id: Uuid,
    path: &PathBuf,
) -> std::io::Result<usize> {
    let bytes = tokio::fs::read(path).await?;
    let observations = parse_grype_output(&bytes);
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
    let mut count = 0usize;
    for obs in &observations {
        if let Some(view) = observation_to_finding(tenant_id, obs, &now) {
            match findings.insert(view).await {
                Ok(_) => count += 1,
                Err(e) => warn!(
                    target: "adapters.sca_monitor",
                    error = %e,
                    "failed to upsert SCA finding"
                ),
            }
        }
    }
    Ok(count)
}

/// Spawn the SCA monitor loop. `None` (no spawn) when the preconditions are
/// not met, so the composition root stays a one-liner.
pub(crate) fn spawn(
    findings: Arc<dyn FindingRepositoryPort>,
    tenant_id: Option<Uuid>,
    sbom_path: PathBuf,
) -> Option<JoinHandle<()>> {
    let tenant_id = tenant_id?;
    if !sbom_path.exists() {
        info!(
            target: "adapters.sca_monitor",
            path = %sbom_path.display(),
            "SCA monitor idle — no SBOM vulnerability report found"
        );
        return None;
    }
    info!(
        target: "adapters.sca_monitor",
        path = %sbom_path.display(),
        "SCA/SBOM continuous monitor enabled"
    );
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(SCAN_INTERVAL);
        loop {
            ticker.tick().await;
            match scan_once(&findings, tenant_id, &sbom_path).await {
                Ok(n) => info!(
                    target: "adapters.sca_monitor",
                    findings = n,
                    "SCA scan pass complete"
                ),
                Err(e) => warn!(
                    target: "adapters.sca_monitor",
                    error = %e,
                    "SCA scan pass failed to read report"
                ),
            }
        }
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn det_uuid_is_stable_and_distinct() {
        assert_eq!(det_uuid("a"), det_uuid("a"));
        assert_ne!(det_uuid("a"), det_uuid("b"));
    }

    #[test]
    fn severity_normalisation() {
        assert_eq!(normalise_severity("Critical"), "critical");
        assert_eq!(normalise_severity("Negligible"), "low");
        assert_eq!(normalise_severity("Unknown"), "info");
    }

    #[test]
    fn converts_package_vulnerability() {
        let tid = Uuid::nil();
        let obs = Observation::PackageVulnerability {
            package: "npm:lodash".to_owned(),
            version: "4.17.20".to_owned(),
            vulnerability_id: "CVE-2021-23337".to_owned(),
            severity: "High".to_owned(),
            fix_versions: vec!["4.17.21".to_owned()],
        };
        let f = observation_to_finding(tid, &obs, "1970-01-01T00:00:00Z").unwrap();
        assert_eq!(f.severity, "high");
        assert_eq!(f.cve_id.as_deref(), Some("CVE-2021-23337"));
        assert!(f.title.contains("lodash"));
        assert!(f.description.contains("4.17.21"));
        // Deterministic id: same input → same id.
        let f2 = observation_to_finding(tid, &obs, "1970-01-01T00:00:00Z").unwrap();
        assert_eq!(f.id, f2.id);
    }

    #[test]
    fn non_package_observation_is_skipped() {
        let obs = Observation::OpenPort {
            port: 443,
            banner: None,
        };
        assert!(observation_to_finding(Uuid::nil(), &obs, "t").is_none());
    }
}
