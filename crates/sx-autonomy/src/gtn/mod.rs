//! Global Threat Network — active mode.
//!
//! The Global Threat Network (GTN) has two operational modes:
//!
//! - **Passive** — the existing [`crate::service::threat_network`] client
//!   posts opt-in, peppered, anonymised vulnerability-frequency
//!   observations to a remote ledger. The client is the data source; the
//!   ledger does the cross-tenant correlation.
//! - **Active** — this module. `SentinelX` itself performs the cross-tenant
//!   correlation in-process via a k-anonymous aggregator. The aggregator
//!   only emits a finding when at least `k` distinct tenants observe a
//!   similar indicator inside a rolling window. Tenant identities are
//!   collapsed to a count at the emission boundary.
//!
//! See [`aggregator::ThreatAggregator`] for the merge rules
//! (Levenshtein on IOC strings OR shared CVE id) and the k-anonymity
//! floor enforced at construction time.

pub mod aggregator;
pub mod summary;
