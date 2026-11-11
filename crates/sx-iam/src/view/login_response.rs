//! HTTP-layer DTO returned from the login endpoint.

use serde::Serialize;

use crate::view::TokenResponse;

/// Body of a `200 OK` login response.
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    /// String-form user id.
    pub user_id: String,
    /// String-form tenant id.
    pub tenant_id: String,
    /// Role names assigned to the user.
    pub roles: Vec<String>,
    /// Token pair (access + refresh).
    pub token: TokenResponse,
}
