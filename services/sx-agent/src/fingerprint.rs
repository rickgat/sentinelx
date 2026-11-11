//! Host fingerprint.
//!
//! `hex(sha256(hostname || node_uid || kernel))`. The three inputs are
//! joined by NUL bytes so a hostname like `"foo\u{0}bar"` cannot collide
//! with a different (hostname, `node_uid`) pair — defensive even though
//! POSIX hostnames don't permit NUL.

use sha2::{Digest, Sha256};

/// Opaque host fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFingerprint(String);

impl HostFingerprint {
    /// Compute a fingerprint from the three concatenated inputs.
    ///
    /// `kernel` is treated as the empty string when `None` so the resulting
    /// fingerprint is stable across kernel-less environments.
    pub fn compute(hostname: &str, node_uid: &str, kernel: Option<&str>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(hostname.as_bytes());
        hasher.update([0u8]);
        hasher.update(node_uid.as_bytes());
        hasher.update([0u8]);
        hasher.update(kernel.unwrap_or("").as_bytes());
        Self(hex::encode(hasher.finalize()))
    }

    /// Lowercase hex digest. Used by tests; the runtime path consumes the
    /// fingerprint via [`Self::into_hex`].
    #[must_use]
    #[allow(dead_code)]
    pub fn as_hex(&self) -> &str {
        &self.0
    }

    /// Consume the fingerprint into its hex form.
    #[must_use]
    pub fn into_hex(self) -> String {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_fingerprint_is_deterministic_for_same_inputs() {
        let a = HostFingerprint::compute("node-1", "uid-abc", Some("6.8.0"));
        let b = HostFingerprint::compute("node-1", "uid-abc", Some("6.8.0"));
        assert_eq!(a, b);
        // 32 bytes -> 64 hex chars.
        assert_eq!(a.as_hex().len(), 64);
    }

    #[test]
    fn host_fingerprint_changes_when_kernel_changes() {
        let a = HostFingerprint::compute("node-1", "uid-abc", Some("6.8.0"));
        let b = HostFingerprint::compute("node-1", "uid-abc", Some("6.9.0"));
        assert_ne!(a, b);
    }

    #[test]
    fn host_fingerprint_changes_when_uid_changes() {
        let a = HostFingerprint::compute("node-1", "uid-abc", None);
        let b = HostFingerprint::compute("node-1", "uid-xyz", None);
        assert_ne!(a, b);
    }
}
