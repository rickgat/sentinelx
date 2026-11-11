//! # `sx-iam` — `SentinelX` Identity, Authentication, Authorization
//!
//! This crate provides:
//!
//! * **Password hashing** — Argon2id, parameters driven by config, never
//!   panics, constant-time verify.
//! * **JWT issuance & validation** — HS256, RS256, `EdDSA`. Algorithm,
//!   issuer, audience, `kid`, and TTLs are all driven by config; the
//!   `none` algorithm is rejected categorically.
//! * **RBAC** — `resource:action` matching with `*` wildcards on either
//!   side, exposed as a tiny stateless engine and a [`controller::AuthorizeUseCase`].
//! * **Login lockout** — pluggable via the [`service::LoginAttemptTracker`]
//!   trait; thresholds from config.
//!
//! ## Layout — MVC + a service layer
//!
//! ```text
//! controller/   ── use cases (Authenticate, IssueToken, ValidateToken,
//!                  RefreshToken, Authorize) — orchestration only.
//! model/        ── internal domain values (Credentials, Session,
//!                  AccessClaims, Token).
//! view/         ── HTTP-facing DTOs (LoginRequest, TokenResponse, …).
//! service/      ── algorithm implementations behind traits
//!                  (PasswordHasher, TokenIssuer, TokenValidator,
//!                  RbacEngine, LoginAttemptTracker).
//! ```
//!
//! ## Boundary contracts
//!
//! * `UserRepository` is an inbound trait (implemented by `sx-storage`).
//! * `LoginAttemptTracker` is an inbound trait (Redis impl downstream).
//! * `IamConfig` and `JwtConfig` come from `sx-config`.
//!
//! See [`prelude`] for the full re-export list.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// Pedantic & nursery lints we deliberately accept:
//   - `missing_const_for_fn`: methods that *could* be const but aren't —
//     we prioritise readability and the ability to evolve internals.
//   - `missing_fields_in_debug`: Debug impls intentionally redact secret
//     / handle fields.
//   - `needless_pass_by_value`: argument types are small structs whose
//     ownership semantics communicate intent better than borrows.
//   - `unused_self` / `trivially_copy_pass_by_ref`: keeps engine APIs
//     idiomatic (method-style) and future-proof for adding state.
//   - `single_match_else`: explicit matches read better when both arms
//     do non-trivial work.
//   - `significant_drop_tightening`: in tests' fake stores; not worth
//     restructuring the test helper.
//   - `option_if_let_else`: matches read better in some flow-sensitive
//     branches than the `Option::map_or` rewrite.
#![allow(
    clippy::missing_const_for_fn,
    clippy::missing_fields_in_debug,
    clippy::needless_pass_by_value,
    clippy::unused_self,
    clippy::trivially_copy_pass_by_ref,
    clippy::single_match_else,
    clippy::option_if_let_else,
    clippy::significant_drop_tightening,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions
)]

pub mod config;
pub mod controller;
pub mod domain;
pub mod error;
pub mod model;
pub mod port;
pub mod prelude;
pub mod service;
pub mod view;

pub use error::IamError;
