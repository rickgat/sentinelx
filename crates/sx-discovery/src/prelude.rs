//! Re-exports for typical call sites.

pub use crate::api_dast::{
    run_dast, ApiDastConfig, ApiDastFinding, ApiDastReport, PostmanCollection,
};
pub use crate::contracts::{
    Engagement, EngagementId, Fqdn, InMemoryKillSwitch, InMemoryScopeValidator, KillSwitch,
    KillSwitchScope, ScanIntensity, ScanRequest, ScopeTarget, ScopeValidator, TenantId,
};
pub use crate::controller::{RegisterScannerUseCase, RunDiscoveryOutput, RunDiscoveryUseCase};
pub use crate::error::DiscoveryError;
pub use crate::model::{DiscoveredAsset, Observation, ScanResult};
pub use crate::scanner::{
    DnsResolverScanner, DnsScannerConfig, HttpFingerprintConfig, HttpFingerprintScanner,
    TcpPortProbeConfig, TcpPortProbeScanner,
};
pub use crate::service::{
    RateLimiter, RateLimiterConfig, SafetyGate, ScanContext, Scanner, ScannerCapabilities,
    ScannerId, ScannerRegistry, TargetKind,
};
pub use crate::view::{ScanResultView, StartDiscoveryRequest};

pub use crate::prowler_import::{
    build_resource_id, parse_prowler_v4_json, AuditSink, CheckIdRegistry, CloudProvider, DedupeKey,
    Deduplicator, ImportProwlerInput, ImportProwlerOutput, ImportProwlerUseCase,
    InMemoryMulticloudSink, KevCatalog, MappedCheck, MulticloudCspmFinding, MulticloudFindingSink,
    NullAuditSink, NullKevCatalog, ProwlerFinding, ProwlerImportAuditEvent, ProwlerImportError,
    ProwlerStatus, RecordingAuditSink, ResourceIdParts, Severity, TenantCloudRegistry,
};
