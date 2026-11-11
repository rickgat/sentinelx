//! # `sx-intel-feeds`
//!
//! STIX 2.1 / TAXII 2.1 client for `SentinelX`'s threat intel pipeline.
//!
//! The crate is intentionally *standalone*: it does not wire itself into
//! `sx-monolith` yet. Instead, it exposes a small, well-typed surface that
//! a future round can plumb into the ingest pipeline:
//!
//! * [`indicator::Indicator`] — the normalised record produced by parsing
//!   feeds. Equivalent to a single observable with metadata.
//! * [`stix`] — minimal STIX 2.1 JSON bundle parser. Supports `indicator`
//!   SDOs whose `pattern` field encodes ipv4/ipv6/domain/url/file hash
//!   observables. Other SDO types are *skipped* (logged as warnings) but
//!   do not abort the parse.
//! * [`taxii`] — TAXII 2.1 client with `discover`, `list_collections`, and
//!   `objects` operations. Authentication uses a bearer token stored as
//!   [`secrecy::SecretString`] and is never logged.
//!
//! ## STIX pattern → `Indicator` mapping
//!
//! | STIX pattern fragment                                     | `IndicatorKind`             |
//! |-----------------------------------------------------------|-----------------------------|
//! | `[ipv4-addr:value = 'X']`                                 | `Ipv4`                      |
//! | `[ipv6-addr:value = 'X']`                                 | `Ipv6`                      |
//! | `[domain-name:value = 'X']`                               | `Domain`                    |
//! | `[url:value = 'X']`                                       | `Url`                       |
//! | `[email-addr:value = 'X']`                                | `Email`                     |
//! | `[file:hashes.'MD5' = 'X']`                               | `FileHash(Md5)`             |
//! | `[file:hashes.'SHA-1' = 'X']`                             | `FileHash(Sha1)`            |
//! | `[file:hashes.'SHA-256' = 'X']`                           | `FileHash(Sha256)`          |
//! | anything else (compound, network-traffic, x-mitre, …)     | skipped with a warning      |
//!
//! ## Safety
//!
//! * `#![forbid(unsafe_code)]`.
//! * All authentication material is wrapped in [`secrecy::SecretString`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod commercial;
pub mod commercial_scheduler;
pub mod cred_rotation;
pub mod crowdstrike;
pub mod cve_master;
pub mod diversity;
pub mod epss;
pub mod feeds;
pub mod indicator;
pub mod kev;
pub mod mandiant;
pub mod nvd;
pub mod rate_limit;
pub mod scheduler;
pub mod stix;
pub mod taxii;
pub mod taxii_auth;

pub use crate::commercial::{CommercialIntelFeed, EnrichedIndicator, IntelError, Tlp};
pub use crate::commercial_scheduler::{
    dedupe_indicators, CommercialAuditEvent, CommercialAuditSink, CommercialFeedsScheduler,
    CommercialSchedulerError, InMemoryAuditSink, InMemoryIndicatorSink, IndicatorSink,
    ProviderKind, RateLimitedFeed, StoredIndicatorRow, TenantCredentialStore, TenantFeedTarget,
    CROWDSTRIKE_RPM, DEFAULT_COMMERCIAL_POLL_INTERVAL_SECS, DEFAULT_SECRETS_PREFIX, MANDIANT_RPM,
    RATE_LIMIT_WINDOW,
};
pub use crate::cred_rotation::{
    CredentialRotationAuditEvent, CredentialRotationAuditSink, CredentialRotationScheduler,
    InMemoryCredentialAuditSink, InMemoryRotationStateStore, RotationPortRegistry,
    RotationSchedulerError, RotationSeverity, RotationStateError, RotationStateRow,
    RotationStateStore, RotationVendor, StaticRotationRegistry, DEFAULT_ROTATION_CADENCE,
    FAILURE_BUDGET, PCI_ROTATION_CADENCE, ROTATION_TICK_INTERVAL,
};
pub use crate::crowdstrike::{CrowdStrikeCloud, CrowdStrikeConfig, CrowdStrikeFeed};
pub use crate::cve_master::{
    merge, CveMasterError, CveMasterRow, EpssFetcher, KevFetcher, NvdFetcher, Severity,
};
pub use crate::diversity::{
    DiversityConfig, DiversityMatcher, FeedFamily, FeedSource, IndicatorConfidence, MatchOutcome,
    Project, Sector, Vendor, DEFAULT_MIN_INDEPENDENT_SOURCES, FAMILY_CORRELATION_DAMPING,
};
pub use crate::feeds::{
    lru_score, Clock, FeedError, FeedId, FeedOrchestrator, FeedStatus, InMemoryRepository,
    PollOutcome, StoredIndicator, SystemClock, TenantId, TenantIocRepository, DEFAULT_SEVERITY,
    SILENT_FEED_THRESHOLD, TENANT_INDICATOR_CAP,
};
pub use crate::indicator::{HashKind, Indicator, IndicatorKind};
pub use crate::mandiant::{MandiantAuth, MandiantConfig, MandiantFeed};
pub use crate::rate_limit::TokenBucket;
pub use crate::scheduler::{
    AuditEvent, CveMasterStore, Scheduler, SyncOutcome, SyncSource, SyncState, DEFAULT_BACKFILL,
};
pub use crate::taxii::{TaxiiClient, TaxiiCollection, TaxiiDiscovery, TaxiiError, TaxiiObjects};
pub use crate::taxii_auth::{
    AlertingHook, EncryptedTaxiiAuth, Pem, RotationAlertHook, TaxiiAuth, TaxiiAuthError,
    TaxiiAuthVault,
};
