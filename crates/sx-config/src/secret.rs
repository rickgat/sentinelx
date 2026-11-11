//! Small helpers around [`secrecy::SecretString`].
//!
//! `SecretString` already redacts itself in `Debug` output and zeros its
//! backing memory on drop. This module exists to provide a single shared
//! constructor / comparison surface so other sx-config modules can avoid
//! depending on `secrecy` internals directly.

use secrecy::{ExposeSecret, SecretString};

/// Wraps a plaintext string in a [`SecretString`].
///
/// Prefer this over `SecretString::from(...)` in call sites so that the
/// intent ("this is a secret") is grep-able.
#[inline]
pub fn wrap(value: impl Into<String>) -> SecretString {
    SecretString::from(value.into())
}

/// Returns whether the wrapped secret is the empty string.
///
/// Useful inside `validator` custom validators where we need to assert a
/// secret was supplied without ever logging it.
#[must_use]
pub fn is_empty(secret: &SecretString) -> bool {
    secret.expose_secret().is_empty()
}

/// Returns the byte length of the wrapped secret.
///
/// Used by validators (e.g. JWT signing keys must be ≥ 32 bytes for HS256).
#[must_use]
pub fn len(secret: &SecretString) -> usize {
    secret.expose_secret().len()
}

/// Borrow the underlying string slice.
///
/// Use sparingly: the lifetime of the returned reference is tied to the
/// `SecretString`, and any storage of the returned data MUST itself live
/// inside a `SecretString` so the platform's secret-handling invariants
/// are preserved.
#[must_use]
pub fn expose_str(secret: &SecretString) -> &str {
    secret.expose_secret()
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn wrap_and_len_match() {
        let s = wrap("hunter2");
        assert_eq!(len(&s), 7);
        assert!(!is_empty(&s));
    }

    #[test]
    fn empty_detection_works() {
        let s = wrap("");
        assert!(is_empty(&s));
        assert_eq!(len(&s), 0);
    }

    #[test]
    fn debug_redacts_value() {
        // `SecretString`'s Debug should never leak the plaintext.
        let s = wrap("hunter2");
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("hunter2"), "secret leaked in Debug: {dbg}");
    }
}
