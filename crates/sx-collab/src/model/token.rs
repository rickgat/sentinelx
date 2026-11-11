//! Opaque 16-hex-character OOB callback token.
//!
//! A `Token` is the per-finding identifier embedded in the DNS / HTTP / SMTP
//! interaction the platform asks an attacker-controlled target to reach.
//!
//! ## Construction
//!
//! `Token::new()` allocates 16 random bytes from the OS CSPRNG, runs them
//! through SHA-256, hex-encodes the digest, and keeps the first 16 lowercase
//! hex characters.  That is the public token form.
//!
//! ## Why 16 hex (64 bits)?
//!
//! 64 bits is large enough that the collision probability across the
//! platform's lifetime stays astronomically below
//! `MAX_TOKENS_PER_TENANT`, while short enough to fit comfortably as a DNS
//! label (max 63 characters) under a multi-label base domain such as
//! `oob.sentinelx.example`.
//!
//! Tokens are opaque — never log the embedded random material as
//! anything but the token string itself.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::CollabError;

/// Number of hex characters in a token.
pub const TOKEN_LEN: usize = 16;

/// An OOB callback token, guaranteed to be a 16-character lowercase hex
/// string.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Token(String);

impl Token {
    /// Mint a fresh random token.
    ///
    /// The token is the lowercase hex of `SHA-256(random 16 bytes)`,
    /// truncated to 16 characters.
    #[must_use]
    pub fn new() -> Self {
        let mut seed = [0_u8; 16];
        // `getrandom` via the `rand` crate would also work; we stay on the
        // crate's existing dependency surface and use `Uuid::new_v4` as a
        // CSPRNG-backed source of random bytes.
        let id = uuid::Uuid::new_v4();
        seed.copy_from_slice(id.as_bytes());
        let mut hasher = Sha256::new();
        hasher.update(seed);
        let digest = hasher.finalize();
        let hexed = hex::encode(digest);
        // Truncate to `TOKEN_LEN` ASCII hex characters.  `hex::encode` always
        // produces lowercase ASCII so the slice is byte-safe.
        let mut s = hexed;
        s.truncate(TOKEN_LEN);
        Self(s)
    }

    /// Parse and validate an externally-supplied token string.
    pub fn parse(s: &str) -> Result<Self, CollabError> {
        if s.len() != TOKEN_LEN {
            return Err(CollabError::invalid_token(format!(
                "token must be {TOKEN_LEN} hex chars, got {}",
                s.len()
            )));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        {
            return Err(CollabError::invalid_token(
                "token must be lowercase hex".to_string(),
            ));
        }
        Ok(Self(s.to_string()))
    }

    /// Borrow the canonical string form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for Token {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Token {
    type Error = CollabError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Token> for String {
    fn from(t: Token) -> Self {
        t.0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{Token, TOKEN_LEN};

    #[test]
    fn token_new_is_16_hex() {
        let t = Token::new();
        assert_eq!(t.as_str().len(), TOKEN_LEN);
        assert!(t.as_str().chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!t.as_str().chars().any(|c| c.is_uppercase()));
    }

    #[test]
    fn token_parse_round_trip() {
        let t = Token::new();
        let parsed = Token::parse(t.as_str()).unwrap();
        assert_eq!(t, parsed);
    }

    #[test]
    fn token_parse_rejects_short() {
        let e = Token::parse("abc").expect_err("short token must fail");
        assert!(e.to_string().contains("16 hex"));
    }

    #[test]
    fn token_parse_rejects_long() {
        assert!(Token::parse("0123456789abcdef0").is_err());
    }

    #[test]
    fn token_parse_rejects_non_hex() {
        assert!(Token::parse("zzzz567890abcdef").is_err());
    }

    #[test]
    fn token_parse_rejects_uppercase() {
        assert!(Token::parse("0123456789ABCDEF").is_err());
    }

    #[test]
    fn token_new_values_differ() {
        // Vanishingly unlikely to collide.
        let a = Token::new();
        let b = Token::new();
        assert_ne!(a, b);
    }
}
