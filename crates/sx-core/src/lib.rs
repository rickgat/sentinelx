//! `sx-core` — the `SentinelX` domain layer.
//!
//! This crate is the pure-domain heart of `SentinelX`. It defines:
//!
//! - **Entities**: rich domain models with invariants enforced at construction
//!   ([`entity::tenant::Tenant`], [`entity::user::User`],
//!   [`entity::engagement::Engagement`], [`entity::asset::Asset`],
//!   [`entity::finding::Finding`], [`entity::cve::Cve`], etc.).
//! - **Value objects**: immutable, validated primitives
//!   ([`value_object::ids`], [`value_object::severity::Severity`],
//!   [`value_object::cvss::CvssScore`], [`value_object::fqdn::Fqdn`],
//!   [`value_object::scope::ScopeTarget`], …).
//! - **Domain errors**: [`error::DomainError`].
//! - **Ports**: `#[async_trait]` repository trait definitions under
//!   [`port`] — adapter crates provide concrete implementations.
//!
//! ## Hard constraints
//!
//! - **Zero I/O**. No database, network, filesystem, or environment access
//!   from this crate.
//! - **Zero hardcoded business policy**. Anything that is a tunable
//!   (CVSS severity bands, probe-intensity rate limits, …) is accepted
//!   from the caller via a constructor parameter or behind a trait.
//! - All public items are documented and round-trip through `serde`
//!   where it makes sense.
//!
//! See [`prelude`] for a convenience glob.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod entity;
pub mod error;
pub mod port;
pub mod prelude;
pub mod reference;
pub mod sarif;
pub mod value_object;

pub use error::DomainError;
