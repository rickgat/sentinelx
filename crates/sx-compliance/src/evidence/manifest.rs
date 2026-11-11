//! Evidence shipment manifest.
//!
//! The [`EvidenceManifest`] is a single, top-level JSON document that
//! describes a batch of evidence artifacts uploaded to an object store.
//! It is intentionally minimal: each entry records the control id, the
//! object-store key the artifact was uploaded to, and the SHA-256 of
//! the artifact's bytes for tamper detection.
//!
//! Manifests are produced by
//! [`crate::evidence::s3_ship::ship_directory`] and are also written to
//! the object store as the final upload of a shipment, so an auditor
//! pulling the manifest alone can verify all referenced artifacts.

use serde::{Deserialize, Serialize};

/// A single artifact entry inside an [`EvidenceManifest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Framework-local control identifier the artifact was produced for.
    pub control_id: String,
    /// Fully-qualified object-store key the artifact was uploaded to.
    pub s3_key: String,
    /// Lowercase hex SHA-256 of the uploaded artifact body.
    pub sha256: String,
}

/// Manifest describing a single shipment of evidence artifacts.
///
/// `started_at` and `finished_at` are RFC-3339 UTC strings — the
/// shipper stamps them so the manifest is byte-identical regardless of
/// the consumer's timezone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceManifest {
    /// Opaque identifier for this shipment run (a UUID is typical).
    pub run_id: String,
    /// Framework label this manifest covers (`"soc2"`, `"iso27001"`, or `"all"`).
    pub framework: String,
    /// RFC-3339 UTC start of the shipment.
    pub started_at: String,
    /// RFC-3339 UTC finish of the shipment.
    pub finished_at: String,
    /// One entry per uploaded artifact, in upload order.
    pub artifacts: Vec<ManifestEntry>,
}

impl EvidenceManifest {
    /// Construct an empty manifest with the supplied identifiers.
    #[must_use]
    pub fn new(
        run_id: impl Into<String>,
        framework: impl Into<String>,
        started_at: impl Into<String>,
    ) -> Self {
        let started = started_at.into();
        Self {
            run_id: run_id.into(),
            framework: framework.into(),
            finished_at: started.clone(),
            started_at: started,
            artifacts: Vec::new(),
        }
    }

    /// Append a single artifact entry to the manifest.
    pub fn push(&mut self, entry: ManifestEntry) {
        self.artifacts.push(entry);
    }

    /// Number of artifact entries currently in the manifest.
    #[must_use]
    pub fn len(&self) -> usize {
        self.artifacts.len()
    }

    /// Whether the manifest currently has zero entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.artifacts.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn manifest_round_trips_through_json() {
        let mut m = EvidenceManifest::new("run-1", "soc2", "2026-05-31T00:00:00Z");
        m.finished_at = "2026-05-31T00:00:05Z".into();
        m.push(ManifestEntry {
            control_id: "CC1.1".into(),
            s3_key: "s3://b/soc2/20260531/soc2__CC1_1.json".into(),
            sha256: "abc123".into(),
        });
        m.push(ManifestEntry {
            control_id: "CC6.1".into(),
            s3_key: "s3://b/soc2/20260531/soc2__CC6_1.json".into(),
            sha256: "def456".into(),
        });

        let s = serde_json::to_string_pretty(&m).unwrap();
        let back: EvidenceManifest = serde_json::from_str(&s).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.len(), 2);
        assert!(!back.is_empty());
    }

    #[test]
    fn empty_manifest_is_empty() {
        let m = EvidenceManifest::new("r", "all", "2026-05-31T00:00:00Z");
        assert!(m.is_empty());
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn manifest_preserves_artifact_order() {
        let mut m = EvidenceManifest::new("r", "soc2", "t0");
        for id in ["CC1.1", "CC6.1", "CC7.2"] {
            m.push(ManifestEntry {
                control_id: id.into(),
                s3_key: format!("k/{id}"),
                sha256: "0".into(),
            });
        }
        let ids: Vec<&str> = m.artifacts.iter().map(|e| e.control_id.as_str()).collect();
        assert_eq!(ids, vec!["CC1.1", "CC6.1", "CC7.2"]);
    }
}
