//! Service layer — pure-logic implementations behind traits.
//!
//! The use cases in [`crate::controller`] only depend on the traits in
//! this module. Production binaries wire the `Argon2idHasher`,
//! `JwtIssuer`, `JwtValidator`, and (downstream) Redis-backed
//! `LoginAttemptTracker` impls; tests can swap in mocks.

pub mod client_assertion;
pub mod clock;
pub mod impossible_travel;
pub mod jwks_publish;
pub mod login_attempt_tracker;
pub mod logout;
pub mod oidc_verifier;
pub mod password_hasher;
pub mod rbac;
pub mod saml;
pub mod token_issuer;
pub mod token_validator;
pub mod totp;
pub mod webauthn;

pub use client_assertion::{
    verify_client_assertion, ClientAssertionClaims, ClientAssertionConfig, InMemoryJtiCache,
    JtiReplayCache, VerifiedAssertion, CLIENT_ASSERTION_TYPE_JWT_BEARER, DEFAULT_REPLAY_WINDOW,
};
pub use clock::{Clock, SystemClock};
pub use impossible_travel::{
    ImpossibleTravelConfig, ImpossibleTravelError, ImpossibleTravelOutcome,
    ImpossibleTravelService, SocFindingSink, TracingSocFindingSink,
};
pub use jwks_publish::{JwksDocument, PublishedJwk, SigningKeyRegistry};
pub use login_attempt_tracker::{AttemptKey, LoginAttemptTracker};
pub use logout::{
    build_rp_logout_redirect, parse_saml_logout_request, parse_saml_logout_response,
    verify_logout_token, LogoutTokenClaims, LogoutTokenVerifierConfig, RpLogoutRedirect,
    SamlLogoutRequest, SamlLogoutResponse, BACKCHANNEL_LOGOUT_EVENT, SAML_STATUS_SUCCESS,
};
pub use oidc_verifier::{JwksOidcVerifier, OidcClaims, OidcVerifier, OidcVerifierConfig};
pub use password_hasher::{Argon2idHasher, PasswordHasher};
pub use rbac::RbacEngine;
pub use token_issuer::{IssueInput, JwtIssuer, TokenIssuer};
pub use token_validator::{
    JwtValidator, KeyResolver, StaticKeyResolver, TokenValidator, UnverifiedHeader,
};
