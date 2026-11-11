//! Concrete scanner implementations shipped with Phase 1.
//!
//! Eleven scanners total:
//! - Network: DNS resolver, TCP port probe, HTTP fingerprint, web-app DAST,
//!   API REST checks, TLS weakness probe.
//! - Code/supply chain: SCA (grype), secret (gitleaks), `IaC` (checkov),
//!   container (trivy).
//! - Cloud: CSPM (prowler / AWS).
//!
//! None send exploit payloads, traverse paths, or attempt auth bypass.

pub mod api_scanner;
pub mod container;
pub mod cspm;
pub mod ct_monitor;
pub mod dns_resolver;
pub mod graphql_introspect;
pub mod grpc_reflect;
pub mod header_enrichment;
pub mod http_fingerprint;
pub mod iac;
pub mod k8s_discovery;
pub mod repo_sbom;
pub mod sca;
pub mod secret;
pub mod tcp_port_probe;
pub mod tls;
pub mod webapp;
pub mod webapp_crawler;
pub mod wrappers;

pub use api_scanner::{ApiScanner, ApiScannerConfig, API_SCANNER_ID};
pub use container::{
    parse_trivy_output, ContainerScanner, ContainerScannerConfig, CONTAINER_SCANNER_ID,
};
pub use cspm::{parse_prowler_ocsf, CspmScanner, CspmScannerConfig, CSPM_SCANNER_ID};
pub use dns_resolver::{DnsResolverScanner, DnsScannerConfig};
pub use http_fingerprint::{HttpFingerprintConfig, HttpFingerprintScanner};
pub use iac::{parse_checkov_output, IacScanner, IacScannerConfig, IAC_SCANNER_ID};
pub use sca::{parse_grype_output, ScaScanner, ScaScannerConfig, SCA_SCANNER_ID};
pub use secret::{parse_gitleaks_output, SecretScanner, SecretScannerConfig, SECRET_SCANNER_ID};
pub use tcp_port_probe::{TcpPortProbeConfig, TcpPortProbeScanner};
pub use tls::{TlsScanner, TlsScannerConfig, TLS_SCANNER_ID};
pub use webapp::{WebAppScanner, WebAppScannerConfig, WEBAPP_SCANNER_ID};
