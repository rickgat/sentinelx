//! `sx-log-ingest` — OCSF 1.x log ingestion pipeline.
//!
//! Provides:
//! - A minimal canonical OCSF event schema ([`OcsfEvent`]).
//! - Built-in parsers for AWS CloudTrail, RFC 5424 syslog, and Suricata
//!   EVE JSON.
//! - A pluggable [`LogParserRegistry`] keyed on source-type tokens.
//! - An in-memory ring-buffer [`LogIngestService`] (one VecDeque per
//!   tenant, capped at [`PER_TENANT_CAPACITY`]) with an optional
//!   correlation hook so the SOC engine can react to ingested events.
//!
//! ClickHouse persistence and Kafka transport are deliberately deferred —
//! this MVP focuses on the schema + parser + listing surface.
//!
//! # Safety
//!
//! - `#![forbid(unsafe_code)]`.
//! - No panics, no `unwrap`/`expect` outside `#[cfg(test)]`.

#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown)]

pub mod error;
pub mod parser;
pub mod rate_limit;
pub mod registry;
pub mod schema;
pub mod service;

pub use error::{LogIngestError, ParseError};
pub use parser::{CloudTrailParser, LogParser, Rfc5424Parser, SuricataEveParser};
pub use rate_limit::{
    BucketSnapshot, LimiterSnapshot, RateDecision, RateLimiter, TenantOverride, Tier, TierRates,
    TierRatesTable, RATE_LIMITED_COUNTER,
};
pub use registry::LogParserRegistry;
pub use schema::{Observable, OcsfEvent, OcsfMetadata, Severity};
pub use service::{CorrelationHook, LogIngestService, PER_TENANT_CAPACITY};
