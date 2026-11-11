//! Bug-bounty platform bridge (P3-010).
//!
//! ## Outbound
//!
//! HackerOne + Bugcrowd clients push *triaged* SentinelX findings
//! (severity ≥ `High`) as **draft internal program notes** — never as
//! researcher-visible public reports. The severity floor is enforced
//! locally so a misconfigured caller never accidentally leaks low-noise
//! detections to the public bug-bounty pipeline.
//!
//! ## Inbound
//!
//! Researcher reports posted by a platform to the webhook endpoint
//! `POST /v1/integrations/bugbounty/inbound/{platform}` are:
//!
//! 1. Verified for HMAC-SHA256 signature (constant-time compare).
//! 2. Mapped to a canonical [`webhook::CanonicalFinding`] with
//!    `source = "bugbounty.<platform>.researcher_<id>"`.
//! 3. De-duplicated against the tenant's existing findings via a TF-IDF
//!    cosine fingerprint of `title + description` (threshold
//!    [`dedupe::DEDUP_THRESHOLD`] = 0.85).
//!
//! ## Credentials
//!
//! Per-tenant program credentials are persisted via the
//! [`sx_secrets::SecretsProvider`] trait. Each platform has its own
//! credential schema:
//!
//! * **HackerOne** — API username + API token (HTTP Basic auth).
//! * **Bugcrowd** — bearer API token only.
//!
//! Both also persist an inbound webhook HMAC secret under a separate
//! secret-store path. Tokens and HMAC secrets are *never* held inside
//! the [`config::BugBountyConnectionConfig`] row — only the
//! [`SecretsProvider`] paths are.
//!
//! ## Audit
//!
//! Every outbound push and every inbound ingest emits a
//! [`audit::BugBountyAuditEvent`]. The recorded shape carries the
//! tenant id, the connector kind, the operation, the outcome, the
//! source identifier, and (on dedupe) the existing finding the
//! candidate matched against. Tokens, headers, URLs, and raw payloads
//! are never recorded.

pub mod audit;
pub mod bugcrowd;
pub mod config;
pub mod connector;
pub mod dedupe;
pub mod hackerone;
pub mod webhook;

pub use audit::{
    BugBountyAuditEvent, BugBountyAuditOp, BugBountyAuditOutcome, BugBountyAuditSink,
    NoopAuditSink, RecordingAuditSink,
};
pub use bugcrowd::{BugcrowdConnector, BUGCROWD_BASE_URL};
pub use config::{
    load_token, load_webhook_secret, BugBountyConfigStore, BugBountyConnectionConfig, ConfigError,
    InMemoryBugBountyConfigStore,
};
pub use connector::{
    is_pushable, BugBountyConnector, BugBountyKind, BugcrowdCredentials, ConnectorError,
    HackerOneCredentials, PushOutcome, TriagedFinding, MIN_PUSH_SEVERITY,
};
pub use dedupe::{DedupResult, Deduplicator, ExistingFinding, DEDUP_THRESHOLD};
pub use hackerone::{HackerOneConnector, HACKERONE_BASE_URL};
pub use webhook::{
    map_to_finding, signature_header_for, verify_signature, CanonicalFinding, WebhookError,
    BUGCROWD_SIGNATURE_HEADER, HACKERONE_SIGNATURE_HEADER,
};
