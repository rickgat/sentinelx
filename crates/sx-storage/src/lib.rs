//! # sx-storage — `PostgreSQL` persistence adapters for `SentinelX`
//!
//! This crate provides:
//! - A configurable [`sqlx::PgPool`] builder (see [`pool::build_pool`]).
//! - A [`tenant_context::TenantContext`] helper that establishes the
//!   `app.current_tenant_id` GUC and a per-transaction `statement_timeout`
//!   for Postgres Row-Level Security (RLS).
//! - Concrete `Pg<Name>Repository` adapters implementing the repository
//!   ports declared in [`crate::domain::port`].
//! - SQL migration files under `migrations/` covering schema, indexes,
//!   and RLS policies.
//!
//! ## Design trade-offs
//!
//! - **No compile-time SQL macros.** All queries use the runtime
//!   [`sqlx::query`] / [`sqlx::query_as`] APIs because `DATABASE_URL` is
//!   not guaranteed to be set during isolated `cargo check` runs in CI.
//!   This sacrifices the macro's compile-time SQL type-checking for the
//!   ability to build the crate without an attached database.
//! - **Defense-in-depth tenant isolation.** Every repository method
//!   begins a transaction, calls [`tenant_context::TenantContext::apply`]
//!   (which `SET LOCAL`s the tenant id GUC for RLS) **and** binds the
//!   tenant id as a literal predicate in every `WHERE` clause. Either
//!   layer alone would prevent cross-tenant leakage; both together make
//!   defection harder.
//! - **Local domain contracts.** While the workspace still bootstraps,
//!   `sx-core` does not yet publish `entity` / `port` modules. To keep
//!   this crate compilable in isolation we declare slim mirror types
//!   under [`crate::domain`]. They are designed to be **drop-in
//!   replaceable** with `sx_core::entity` / `sx_core::port` once those
//!   are published, at which point the only change required here is
//!   swapping the `use` paths.
//!
//! ## Security posture
//!
//! - All queries are parameterised; no string concatenation of user
//!   input.
//! - The connection URL is held in [`secrecy::SecretString`]; only the
//!   `host`, `port`, and database name are logged (via [`url::Url`]
//!   parsing — but `url` is not a dep of this crate, so the pool builder
//!   parses with `sqlx::postgres::PgConnectOptions` instead).
//! - `#![forbid(unsafe_code)]` and strict clippy gates are enforced at
//!   the workspace level.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod domain;
pub mod error;
pub mod pagination;
pub mod pool;
#[cfg(any(test, feature = "test-asserts"))]
pub mod pool_assert;
pub mod prelude;
pub mod repository;
pub mod tenant_context;

pub use error::StorageError;
