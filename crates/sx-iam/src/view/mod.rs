//! HTTP-facing DTOs (View layer in the MVC split).
//!
//! These are the types the API layer (`sx-api`) hands to / receives from
//! the controllers. Internal domain types live in [`crate::model`] —
//! converting between them is intentionally a use-case responsibility.

pub mod error_view;
pub mod login_request;
pub mod login_response;
pub mod token_response;

pub use error_view::IamErrorResponse;
pub use login_request::LoginRequest;
pub use login_response::LoginResponse;
pub use token_response::TokenResponse;
