//! HTTP-layer DTO representing an OAuth2-style bearer token pair.

use secrecy::ExposeSecret;
use serde::Serialize;

use crate::model::Token;

/// `application/json` body returned from token-issuing endpoints.
///
/// Follows the OAuth 2.0 RFC 6749 §5.1 shape so off-the-shelf clients can
/// consume it without remapping.
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    /// Signed access JWT — serialised plaintext (the wire requires it).
    pub access_token: String,
    /// Signed refresh JWT — serialised plaintext (the wire requires it).
    pub refresh_token: String,
    /// Always `"Bearer"` for this implementation.
    pub token_type: &'static str,
    /// Lifetime of `access_token`, in seconds.
    pub expires_in: u64,
}

impl TokenResponse {
    /// Build a wire response from the internal [`Token`].
    ///
    /// This is the *only* place we cross the `SecretString` boundary —
    /// the JWT must be sent verbatim over the wire, so exposing the
    /// inner string here is unavoidable. The receiver is responsible
    /// for not logging the result.
    #[must_use]
    pub fn from_token(token: &Token) -> Self {
        Self {
            access_token: token.access.expose_secret().to_owned(),
            refresh_token: token.refresh.expose_secret().to_owned(),
            token_type: "Bearer",
            expires_in: token.expires_in,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[test]
    fn from_token_round_trips_strings() {
        let t = Token {
            access: SecretString::from("aaa".to_string()),
            refresh: SecretString::from("bbb".to_string()),
            expires_in: 900,
        };
        let r = TokenResponse::from_token(&t);
        assert_eq!(r.access_token, "aaa");
        assert_eq!(r.refresh_token, "bbb");
        assert_eq!(r.token_type, "Bearer");
        assert_eq!(r.expires_in, 900);
    }
}
