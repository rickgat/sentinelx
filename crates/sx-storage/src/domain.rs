//! Local mirror of the `sx-core` domain contracts.
//!
//! While the workspace bootstraps, `sx-core` does not yet publish
//! `entity` and `port` modules. Rather than wait, we declare local
//! mirrors here so this crate can build and pass `cargo clippy` /
//! `cargo test` in isolation.
//!
//! When `sx-core` adds its real modules, the only required change is
//! to flip the re-exports in [`crate::domain`] to point at
//! `sx_core::entity` / `sx_core::port` / `sx_core::value_object`. The
//! shapes here are deliberately a structural subset of what `sx-core`
//! will offer.

pub mod entity;
pub mod error;
pub mod port;
pub mod value_object;

pub use error::DomainError;
