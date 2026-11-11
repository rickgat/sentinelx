//! Token pair returned by [`crate::controller::IssueTokenUseCase`].
//!
//! Both halves are wrapped in [`SecretString`] so they cannot leak via
//! `Debug` / logs.

use secrecy::SecretString;

/// Classifier paired with a `Token` when returned across boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    /// Short-lived access token.
    Access,
    /// Long-lived refresh token (`#[serde(rename = "refresh")]`).
    Refresh,
}

/// A pair of (access, refresh) JWTs plus the access lifetime in seconds.
#[derive(Debug)]
pub struct Token {
    /// Signed access JWT.
    pub access: SecretString,
    /// Signed refresh JWT.
    pub refresh: SecretString,
    /// Lifetime of the access token, in seconds.
    pub expires_in: u64,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[test]
    fn token_debug_does_not_leak() {
        let t = Token {
            access: SecretString::from("aaa.bbb.ccc".to_string()),
            refresh: SecretString::from("ddd.eee.fff".to_string()),
            expires_in: 900,
        };
        let dbg = format!("{t:?}");
        assert!(!dbg.contains("aaa.bbb.ccc"));
        assert!(!dbg.contains("ddd.eee.fff"));
    }
}
