//! A single fact emitted by a scanner.
//!
//! An [`Observation`] is the smallest unit of data a scanner can emit. A
//! [`crate::model::scan_result::ScanResult`] is, in effect, a time-bounded
//! `Vec<Observation>` annotated with the scanner that produced it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sx_core::value_object::compliance::ComplianceTags;
use sx_core::value_object::cvss_v31::CvssV31;
use sx_core::value_object::cwe::CweId;
use sx_core::value_object::mitre_attack::MitreAttackTechnique;

/// DNS record kinds emitted by [`crate::scanner::dns_resolver`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordKind {
    /// IPv4 address record.
    A,
    /// IPv6 address record.
    Aaaa,
    /// Canonical name record.
    Cname,
    /// Mail exchanger record.
    Mx,
    /// Text record.
    Txt,
}

impl DnsRecordKind {
    /// Short string form, used in `tracing` fields.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Mx => "MX",
            Self::Txt => "TXT",
        }
    }
}

/// TLS certificate fingerprint captured during an HTTPS probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Subject common-name, if present.
    pub subject_cn: Option<String>,
    /// Issuer common-name, if present.
    pub issuer_cn: Option<String>,
    /// Subject alternative names.
    pub san: Vec<String>,
}

/// One fact observed by a scanner.
///
/// TOP5-#3 Phase 1 added the optional enrichment payload
/// ([`Observation::HttpVulnerability::cvss`] / `cwe` / `mitre_attack` /
/// `compliance`) to the `HttpVulnerability` variant. Because `CvssV31`
/// carries an `f64`, the enum no longer derives `Eq` — `PartialEq` is
/// retained for tests that compare scan results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Observation {
    /// A DNS record returned by an authoritative or recursive resolver.
    DnsRecord {
        /// Record type (A, AAAA, CNAME, MX, TXT).
        record: DnsRecordKind,
        /// Stringified record value.
        value: String,
    },
    /// An open TCP port discovered via connect-probe.
    OpenPort {
        /// Port number (1..=65535).
        port: u16,
        /// Optional first banner line read after connect. `None` if the
        /// remote did not speak first within the read timeout.
        banner: Option<String>,
    },
    /// A standalone banner line — emitted by services that send multiple
    /// distinct welcome messages.
    BannerLine {
        /// Port the banner was read on.
        port: u16,
        /// Banner content.
        line: String,
    },
    /// A single HTTP response. Headers are lowercased and sanitised — any
    /// `set-cookie` value is replaced by a placeholder before storage.
    HttpResponse {
        /// HTTP status code.
        status: u16,
        /// URL the response came from.
        url: String,
        /// Headers (lowercased keys, sanitised values).
        headers: BTreeMap<String, String>,
        /// Best-effort server identifier extracted from headers.
        server: Option<String>,
        /// Best-effort `x-powered-by` framework hint.
        framework: Option<String>,
    },
    /// TLS certificate metadata captured during an HTTPS probe.
    Certificate(CertificateInfo),
    /// One vulnerable package match emitted by the SCA scanner.
    PackageVulnerability {
        /// Ecosystem-qualified package name (e.g. `npm:lodash`).
        package: String,
        /// Installed version observed on the target.
        version: String,
        /// Vulnerability identifier (CVE, GHSA, OSV, …).
        vulnerability_id: String,
        /// Severity tag reported by the matcher (`Critical`, `High`, …).
        severity: String,
        /// Versions that fix the issue, when known.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        fix_versions: Vec<String>,
    },
    /// One web-application security check failure (header audit, cookie
    /// hygiene, missing TLS, etc.) emitted by the web-app DAST scanner.
    ///
    /// TOP5-#3 Phase 1 added the optional enrichment fields below. They
    /// default to `None`/empty so legacy emitters compile unchanged and
    /// the JSON payload omits absent fields.
    HttpVulnerability {
        /// Stable check identifier (e.g. `HDR.STRICT_TRANSPORT_SECURITY.MISSING`).
        check_id: String,
        /// Severity tag (`info`, `low`, `medium`, `high`, `critical`).
        severity: String,
        /// URL the check was evaluated against.
        url: String,
        /// Human-readable description of the finding.
        message: String,
        /// Optional remediation hint.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        remediation: Option<String>,
        /// CVSS v3.1 base metric payload (TOP5-#3 Phase 1).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cvss: Option<CvssV31>,
        /// CWE identifiers describing the underlying weakness class(es).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        cwe: Vec<CweId>,
        /// MITRE ATT&CK techniques this finding maps to.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        mitre_attack: Vec<MitreAttackTechnique>,
        /// Compliance-framework control mappings.
        #[serde(default, skip_serializing_if = "ComplianceTags::is_empty")]
        compliance: ComplianceTags,
    },
    /// One secret-leak finding emitted by the secret scanner. The secret
    /// value itself is **never** included — only a fingerprint hash.
    SecretFinding {
        /// Rule identifier (e.g. `aws-access-key-id`).
        rule_id: String,
        /// Severity tag.
        severity: String,
        /// Optional file path the leak was found in.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        file: Option<String>,
        /// Optional line number.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        line: Option<u32>,
        /// Hex-encoded SHA-256 of the leaked secret. The raw secret is
        /// never stored.
        fingerprint: String,
    },
    /// One Infrastructure-as-Code misconfiguration emitted by the `IaC`
    /// scanner (Checkov / tfsec / KICS wrappers).
    IacMisconfiguration {
        /// Framework (`terraform`, `cloudformation`, `helm`, `kubernetes`).
        framework: String,
        /// File path relative to the scanned root.
        file: String,
        /// Optional line number inside the file.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        line: Option<u32>,
        /// Stable check identifier (e.g. `CKV_AWS_20`).
        check_id: String,
        /// Severity tag.
        severity: String,
        /// Human-readable description.
        message: String,
    },
    /// One TLS / cryptography weakness emitted by the TLS scanner.
    TlsWeakness {
        /// Host:port endpoint that was probed.
        endpoint: String,
        /// TLS protocol version (e.g. `TLSv1.0`, `TLSv1.3`).
        protocol: String,
        /// Optional cipher suite.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cipher: Option<String>,
        /// Stable check identifier (e.g. `weak-cipher`, `expired-cert`).
        check_id: String,
        /// Severity tag.
        severity: String,
        /// Human-readable description.
        message: String,
    },
    /// One cloud-infrastructure misconfiguration emitted by the CSPM
    /// scanner.
    ///
    /// TOP5-#3 Phase 2 (P2-006) added the optional enrichment fields
    /// below. Prowler does not emit CVSS, so `cvss` stays `None` — but
    /// `cwe` / `compliance` are projected through from the Prowler OCSF
    /// payload (CWE-xxx scanned out of the `risk` free-text field,
    /// compliance frameworks parsed from Prowler's `compliance` object).
    /// All fields default to `None` / empty so the JSON payload is
    /// backwards-compatible.
    CloudMisconfiguration {
        /// Stable check identifier (e.g. `iam_no_root_access_keys`).
        check_id: String,
        /// Severity tag.
        severity: String,
        /// Cloud provider (`aws`, `gcp`, `azure`).
        provider: String,
        /// Region/zone, when applicable.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        region: Option<String>,
        /// Service identifier (e.g. `s3`, `iam`, `ec2`).
        service: String,
        /// Resource identifier (e.g. ARN, project id).
        resource: String,
        /// Human-readable description.
        message: String,
        /// CVSS v3.1 base metric payload. Prowler does not emit CVSS
        /// scores for its checks; this field is reserved for future
        /// hand-curated mappings and stays `None` today.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cvss: Option<CvssV31>,
        /// CWE identifiers extracted from Prowler's `risk` /
        /// `risk_details` free-text fields when a `CWE-xxx` mention is
        /// present.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        cwe: Vec<CweId>,
        /// MITRE ATT&CK techniques. Empty until a Prowler-id →
        /// ATT&CK mapping table lands (P2-006 follow-up).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        mitre_attack: Vec<MitreAttackTechnique>,
        /// Compliance-framework control mappings projected from
        /// Prowler's OCSF `compliance` object (NIST 800-53, ISO 27001,
        /// PCI DSS, SOC 2, HIPAA).
        #[serde(default, skip_serializing_if = "ComplianceTags::is_empty")]
        compliance: ComplianceTags,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn dns_record_kind_strings() {
        assert_eq!(DnsRecordKind::A.as_str(), "A");
        assert_eq!(DnsRecordKind::Aaaa.as_str(), "AAAA");
        assert_eq!(DnsRecordKind::Cname.as_str(), "CNAME");
        assert_eq!(DnsRecordKind::Mx.as_str(), "MX");
        assert_eq!(DnsRecordKind::Txt.as_str(), "TXT");
    }

    #[test]
    fn observation_serializes_round_trip() {
        let obs = Observation::OpenPort {
            port: 22,
            banner: Some("SSH-2.0-OpenSSH".into()),
        };
        let json = serde_json::to_string(&obs).unwrap();
        let back: Observation = serde_json::from_str(&json).unwrap();
        assert_eq!(obs, back);
    }
}
