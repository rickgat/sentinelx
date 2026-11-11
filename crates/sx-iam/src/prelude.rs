//! Convenience re-exports for downstream crates.
//!
//! Importing `sx_iam::prelude::*` gives you everything most callers need
//! to drive the use cases.

pub use crate::config::{IamConfig, JwtAlgorithm, JwtConfig, LockoutPolicy, PasswordConfig};
pub use crate::controller::{
    AuthenticateUserUseCase, AuthorizeUseCase, CreateUserInput, CreateUserUseCase,
    CreateUserWithHashInput, CreateUserWithHashUseCase, IssueTokenUseCase, RefreshTokenUseCase,
    ValidateTokenUseCase,
};
pub use crate::domain::{Permission, Role, RoleId, TenantId, User, UserId};
pub use crate::error::IamError;
pub use crate::model::{AccessClaims, Credentials, Session, SessionId, Token};
pub use crate::port::UserRepository;
pub use crate::service::{
    Argon2idHasher, AttemptKey, Clock, JwtIssuer, JwtValidator, KeyResolver, LoginAttemptTracker,
    PasswordHasher, RbacEngine, StaticKeyResolver, SystemClock, TokenIssuer, TokenValidator,
};
pub use crate::view::{IamErrorResponse, LoginRequest, LoginResponse, TokenResponse};
