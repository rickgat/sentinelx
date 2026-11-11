//! Token allocator: bind `(tenant_id, finding_id) -> Token` both ways.

use std::collections::HashMap;
use std::sync::RwLock;

use sx_core::value_object::ids::TenantId;

use crate::model::token::Token;

/// Reverse-lookup payload returned by [`TokenAllocator::lookup`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantBinding {
    /// Tenant that owns the originating finding.
    pub tenant_id: TenantId,
    /// Finding identifier, encoded as the caller wishes.  We treat it as
    /// opaque here so this crate need not depend on every finding kind.
    pub finding_id: String,
}

/// Two-way token registry.
///
/// Thread-safe via a single `RwLock`.  Lookups are constant-time hash-map
/// reads; allocation is `O(1)` amortised.
#[derive(Debug, Default)]
pub struct TokenAllocator {
    forward: RwLock<HashMap<(TenantId, String), Token>>,
    reverse: RwLock<HashMap<Token, TenantBinding>>,
}

impl TokenAllocator {
    /// Empty allocator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a fresh token and bind it to `(tenant_id, finding_id)`.
    ///
    /// If `(tenant_id, finding_id)` was already bound, the existing token
    /// is returned unchanged — allocations are idempotent.
    ///
    /// # Panics
    ///
    /// Panics only if the internal `RwLock` is poisoned, which would
    /// indicate a prior panic inside this allocator.  Production code paths
    /// MUST NOT panic; we surface the poisoning as a logical bug.
    pub fn allocate(&self, tenant_id: TenantId, finding_id: String) -> Token {
        // Fast path: existing binding.
        {
            let fwd = match self.forward.read() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            if let Some(existing) = fwd.get(&(tenant_id, finding_id.clone())) {
                return existing.clone();
            }
        }
        let token = Token::new();
        let mut fwd = match self.forward.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut rev = match self.reverse.write() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Re-check under the write lock to avoid the lost-update race.
        if let Some(existing) = fwd.get(&(tenant_id, finding_id.clone())) {
            return existing.clone();
        }
        fwd.insert((tenant_id, finding_id.clone()), token.clone());
        rev.insert(
            token.clone(),
            TenantBinding {
                tenant_id,
                finding_id,
            },
        );
        token
    }

    /// Return the `(tenant_id, finding_id)` for `token`, if any.
    #[must_use]
    pub fn lookup(&self, token: &Token) -> Option<TenantBinding> {
        let rev = match self.reverse.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        rev.get(token).cloned()
    }

    /// Total number of live bindings (for diagnostics / capacity metrics).
    #[must_use]
    pub fn len(&self) -> usize {
        let rev = match self.reverse.read() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        rev.len()
    }

    /// `true` when the allocator holds no bindings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::TokenAllocator;
    use sx_core::value_object::ids::TenantId;

    #[test]
    fn token_allocator_round_trip() {
        let alloc = TokenAllocator::new();
        let tid = TenantId::new();
        let fid = "F-001".to_string();
        let t = alloc.allocate(tid, fid.clone());
        let binding = alloc.lookup(&t).unwrap();
        assert_eq!(binding.tenant_id, tid);
        assert_eq!(binding.finding_id, fid);
        assert_eq!(alloc.len(), 1);
        assert!(!alloc.is_empty());
    }

    #[test]
    fn token_allocator_idempotent() {
        let alloc = TokenAllocator::new();
        let tid = TenantId::new();
        let a = alloc.allocate(tid, "F".into());
        let b = alloc.allocate(tid, "F".into());
        assert_eq!(a, b);
        assert_eq!(alloc.len(), 1);
    }

    #[test]
    fn lookup_unknown_is_none() {
        let alloc = TokenAllocator::new();
        let t = crate::model::token::Token::new();
        assert!(alloc.lookup(&t).is_none());
    }
}
