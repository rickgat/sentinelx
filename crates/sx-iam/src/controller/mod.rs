//! Use cases (Controller layer).
//!
//! Each module is a single use case implemented as a struct holding its
//! injected dependencies with one `execute(...)` method. There is no
//! cross-use-case state and no shared mutable storage.

pub mod authenticate_user;
pub mod authorize;
pub mod client_token;
pub mod create_user;
pub mod exchange_oidc;
pub mod issue_token;
pub mod refresh_token;
pub mod rotate_client_secret;
pub mod validate_token;
pub mod webauthn;

pub use authenticate_user::AuthenticateUserUseCase;
pub use authorize::AuthorizeUseCase;
pub use client_token::{ClientCredentialsTokenOutput, ClientCredentialsTokenUseCase};
pub use create_user::{
    CreateUserInput, CreateUserUseCase, CreateUserWithHashInput, CreateUserWithHashUseCase,
};
pub use exchange_oidc::{ExchangeOidcConfig, ExchangeOidcOutput, ExchangeOidcUseCase};
pub use issue_token::IssueTokenUseCase;
pub use refresh_token::RefreshTokenUseCase;
pub use rotate_client_secret::{
    RotateOidcClientSecretOutput, RotateOidcClientSecretUseCase, RotationConfig,
    DEFAULT_GRACE_WINDOW, DEFAULT_ROTATION_CADENCE,
};
pub use validate_token::ValidateTokenUseCase;
pub use webauthn::{
    LoginFinishInput, LoginFinishOutput, LoginFinishUseCase, LoginStartInput, LoginStartOutput,
    LoginStartUseCase, RegisterFinishInput, RegisterFinishOutput, RegisterFinishUseCase,
    RegisterStartInput, RegisterStartOutput, RegisterStartUseCase,
};
