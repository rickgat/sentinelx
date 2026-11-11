//! `sx-scim` — SCIM 2.0 (System for Cross-domain Identity Management) for
//! `SentinelX`.
//!
//! Implements the subset of RFC 7643 (schema) and RFC 7644 (protocol)
//! required to onboard Okta / Azure AD / Google Workspace SCIM provisioning
//! agents. This crate is **transport-agnostic**: the HTTP surface lives in
//! `sx-api`; this crate provides the schema types, filter parser, and the
//! [`service::ScimProvisioner`] trait the HTTP layer consumes.
//!
//! ## MVP scope (P0-005)
//!
//! - **Resources** — `User` (full CRUD + filter list) and `Group`
//!   (create / read / list). Per the task brief, PATCH is modeled as a
//!   full replace (PUT semantics).
//! - **Filter** — `eq`, `co`, `sw`, `ew` operators with `and` / `or`
//!   composition. Path syntax supports nested attributes
//!   (`name.givenName`, `emails.value`).
//! - **Bearer auth** — per-tenant SCIM token validated by the adapter
//!   layer (constant-time compare in `sx-monolith`).
//! - **Audit** — every mutation is logged via the adapter.
//!
//! ## Layout
//!
//! ```text
//! src/
//! ├── error.rs                ScimError
//! ├── prelude.rs
//! ├── schema/                 ScimUser / ScimGroup / Meta / Name / Email / ...
//! ├── filter/                 Filter AST + tokeniser + parser
//! └── service/                ScimProvisioner trait + InMemoryScimProvisioner
//! ```

#![forbid(unsafe_code)]
#![allow(clippy::doc_markdown)]
// Pedantic / nursery allowances scoped to the scaffolding shape of
// this crate. SCIM types intentionally mirror the wire shapes from
// RFC 7643 (`familyName`, `givenName` — both end in `Name`) and the
// `InMemoryScimProvisioner` keeps a `Mutex<HashMap>` per tenant which
// trips `significant_drop_tightening` on every short-lived guard.
#![allow(clippy::struct_field_names)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::assigning_clones)]
#![allow(clippy::type_complexity)]

pub mod error;
pub mod filter;
pub mod prelude;
pub mod schema;
pub mod scope;
pub mod service;

pub use error::ScimError;
pub use scope::{parse_scopes, scopes_cover, ScimRotationPolicy, ScimScope, ScopeParseError};
