//! Anonymisation of feature rows before they reach a trainer.

use crate::model::feature::{FeatureValue, FeatureVector};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Drops a configured set of PII fields and hashes a configured set of
/// categorical fields with a tenant-scoped pepper.
///
/// Hashing uses `hex(sha256(pepper || ":" || value))[..16]`.
#[derive(Debug, Clone)]
pub struct Anonymiser {
    pepper: SecretString,
    drop_fields: HashSet<String>,
    hash_fields: HashSet<String>,
}

impl Anonymiser {
    /// Construct a new anonymiser.
    #[must_use]
    pub const fn new(
        pepper: SecretString,
        drop_fields: HashSet<String>,
        hash_fields: HashSet<String>,
    ) -> Self {
        Self {
            pepper,
            drop_fields,
            hash_fields,
        }
    }

    /// Anonymise a feature row.
    ///
    /// - Fields listed in `drop_fields` are removed entirely.
    /// - Fields listed in `hash_fields` are hashed in place:
    ///   - `Bool` values are first stringified ("true" / "false") then hashed
    ///     and the resulting digest replaces the value as a `Category`.
    ///   - `Number` values are stringified with `to_string` then hashed.
    ///   - `Category` values are hashed directly.
    /// - All other fields are passed through unchanged.
    #[must_use]
    pub fn anonymise(&self, row: FeatureVector) -> FeatureVector {
        let mut out = FeatureVector::new();
        for (name, value) in row {
            if self.drop_fields.contains(&name) {
                continue;
            }
            if self.hash_fields.contains(&name) {
                let plaintext = match &value {
                    FeatureValue::Bool(b) => b.to_string(),
                    FeatureValue::Number(n) => n.to_string(),
                    FeatureValue::Category(c) => c.clone(),
                };
                let digest = self.hash(&plaintext);
                out.insert(name, FeatureValue::Category(digest));
            } else {
                out.insert(name, value);
            }
        }
        out
    }

    /// Hash a raw plaintext string to a 16-character lowercase hex digest.
    #[must_use]
    pub fn hash(&self, value: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.pepper.expose_secret().as_bytes());
        hasher.update(b":");
        hasher.update(value.as_bytes());
        let full = hex::encode(hasher.finalize());
        // First 16 hex chars = 64 bits of entropy. Plenty for anonymisation.
        full.get(..16).unwrap_or(&full).to_owned()
    }
}
