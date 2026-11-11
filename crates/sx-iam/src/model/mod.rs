//! Domain *models* used by the IAM use cases.
//!
//! These types are owned by the controllers (use cases). They are distinct
//! from the wire-format DTOs in [`crate::view`]: a `LoginRequest` carries
//! transport concerns (validation, deserialisation) while
//! `Credentials` is the internal value the use case operates on.

pub mod claims;
pub mod credentials;
pub mod oidc_client;
pub mod session;
pub mod token;
pub mod webauthn;

pub use claims::AccessClaims;
pub use credentials::Credentials;
pub use oidc_client::{ClientAuthMethod, ClientId, ClientSecret, OidcClient, OidcClientRowId};
pub use session::{Session, SessionId};
pub use token::{Token, TokenKind};
pub use webauthn::{
    AaguidAction, AaguidPolicy, AttestationPolicy, MdsEntry, MdsStatus, StoredCredential, TenantRp,
};
