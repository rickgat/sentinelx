//! `ValidateTokenUseCase` — turn a raw bearer string into [`AccessClaims`].
//!
//! Accepts either `"Bearer foo.bar.baz"` or plain `"foo.bar.baz"`.

use std::sync::Arc;

use crate::model::AccessClaims;
use crate::service::TokenValidator;
use crate::IamError;

/// Use case: validate a raw bearer token.
pub struct ValidateTokenUseCase<V: TokenValidator> {
    validator: Arc<V>,
}

impl<V: TokenValidator> std::fmt::Debug for ValidateTokenUseCase<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidateTokenUseCase").finish()
    }
}

impl<V: TokenValidator> ValidateTokenUseCase<V> {
    /// Build the use case.
    pub fn new(validator: Arc<V>) -> Self {
        Self { validator }
    }

    /// Validate `raw` (with or without `"Bearer "` prefix) and return
    /// its claims.
    pub fn execute(&self, raw: &str) -> Result<AccessClaims, IamError> {
        let token = strip_bearer(raw);
        if token.is_empty() {
            return Err(IamError::InvalidToken);
        }
        self.validator.validate(token)
    }
}

/// Strip an optional case-insensitive `"Bearer "` prefix.
fn strip_bearer(raw: &str) -> &str {
    let trimmed = raw.trim();
    let lower = trimmed.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("bearer ") {
        let offset = trimmed.len() - rest.len();
        trimmed[offset..].trim()
    } else {
        trimmed
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn strip_bearer_handles_prefix() {
        assert_eq!(strip_bearer("Bearer xyz"), "xyz");
        assert_eq!(strip_bearer("bearer xyz"), "xyz");
        assert_eq!(strip_bearer("BEARER xyz"), "xyz");
        assert_eq!(strip_bearer("xyz"), "xyz");
        assert_eq!(strip_bearer("   Bearer    xyz  "), "xyz");
    }
}
