//! Concrete `Pg<Name>Repository` implementations.
//!
//! Each module hosts a single repository struct that wraps a
//! [`sqlx::PgPool`] (cheap to [`Clone`]) and a per-instance
//! `statement_timeout_ms` value applied via
//! [`crate::tenant_context::TenantContext::apply`] on every
//! transaction.

pub mod approvals;
mod asset;
pub mod audit_chain_heads;
mod cve;
mod engagement;
mod finding;
mod soc_rules;
mod tenant;
mod user;
pub mod webhook_signing_keys;

pub use approvals::{ApprovalRepository, ApprovalRow, NewApproval, PgApprovalRepository};
pub use asset::PgAssetRepository;
pub use audit_chain_heads::PgChainHeadSource;
pub use cve::PgCveRepository;
pub use engagement::PgEngagementRepository;
pub use finding::PgFindingRepository;
pub use soc_rules::{PgSocRuleRepository, SocRuleRow};
pub use tenant::PgTenantRepository;
pub use user::PgUserRepository;
pub use webhook_signing_keys::{
    build_pg_rotator as build_pg_webhook_rotator, EncryptedSigningKeyStore,
    PgWebhookSigningKeyRepository,
};
