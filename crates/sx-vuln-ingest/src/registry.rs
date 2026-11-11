//! External plugin id → internal `check_id` mapping.
//!
//! Per P0-002 the platform owns a stable `check_id` namespace independent
//! of any one scanner. For MVP the registry is deterministic:
//!
//! - Nessus plugin `12345` → internal `NESSUS.12345`.
//! - OpenVAS OID `1.3.6.1.4.1.25623.1.0.103674` → `OPENVAS.103674` (last
//!   numeric segment) when present, else `OPENVAS.<raw>` with non-id chars
//!   stripped.
//!
//! Callers that need a richer mapping (curated registry, vendor → MITRE
//! mapping) plug in via [`CheckIdRegistry::with_overrides`].

use std::collections::HashMap;

use crate::model::SourceFormat;

/// Mapping registry for external plugin ids → internal check ids.
#[derive(Debug, Clone, Default)]
pub struct CheckIdRegistry {
    overrides: HashMap<(SourceFormat, String), String>,
}

impl CheckIdRegistry {
    /// Build an empty registry — every lookup falls back to the canonical
    /// `<SCANNER>.<plugin-id>` form.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a registry with a caller-supplied override table.
    #[must_use]
    pub fn with_overrides(overrides: HashMap<(SourceFormat, String), String>) -> Self {
        Self { overrides }
    }

    /// Register one override after construction. Idempotent.
    pub fn insert(
        &mut self,
        source: SourceFormat,
        external: impl Into<String>,
        internal: impl Into<String>,
    ) {
        self.overrides
            .insert((source, external.into()), internal.into());
    }

    /// Resolve `external` to the internal `check_id` using the source's
    /// canonical form, or an override when registered.
    #[must_use]
    pub fn resolve(&self, source: SourceFormat, external: &str) -> String {
        if let Some(over) = self.overrides.get(&(source, external.to_owned())) {
            return over.clone();
        }
        canonical_check_id(source, external)
    }
}

/// Canonical `check_id` form when no override is registered.
fn canonical_check_id(source: SourceFormat, external: &str) -> String {
    let cleaned: String = external
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    match source {
        SourceFormat::Nessus => format!("NESSUS.{cleaned}"),
        SourceFormat::Openvas => {
            // Take the last numeric segment of the OID when present; that is
            // the user-visible OpenVAS test id (e.g. `103674`).
            let tail = external
                .rsplit('.')
                .next()
                .filter(|t| !t.is_empty() && t.chars().all(|c| c.is_ascii_digit()))
                .unwrap_or(cleaned.as_str());
            format!("OPENVAS.{tail}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_nessus_id_is_prefixed() {
        let reg = CheckIdRegistry::new();
        assert_eq!(reg.resolve(SourceFormat::Nessus, "12345"), "NESSUS.12345");
    }

    #[test]
    fn canonical_openvas_id_uses_last_numeric_segment() {
        let reg = CheckIdRegistry::new();
        assert_eq!(
            reg.resolve(SourceFormat::Openvas, "1.3.6.1.4.1.25623.1.0.103674"),
            "OPENVAS.103674"
        );
    }

    #[test]
    fn canonical_openvas_id_falls_back_to_cleaned_form() {
        let reg = CheckIdRegistry::new();
        let id = reg.resolve(SourceFormat::Openvas, "abc-xyz");
        assert!(id.starts_with("OPENVAS."));
        assert!(!id.contains('-'));
    }

    #[test]
    fn override_takes_priority() {
        let mut reg = CheckIdRegistry::new();
        reg.insert(SourceFormat::Nessus, "12345", "SX.CHK.OPENSSL.LOW");
        assert_eq!(
            reg.resolve(SourceFormat::Nessus, "12345"),
            "SX.CHK.OPENSSL.LOW"
        );
    }

    #[test]
    fn override_does_not_leak_across_sources() {
        let mut reg = CheckIdRegistry::new();
        reg.insert(SourceFormat::Nessus, "12345", "SX.CHK.A");
        assert_eq!(reg.resolve(SourceFormat::Openvas, "12345"), "OPENVAS.12345");
    }

    #[test]
    fn unknown_chars_are_scrubbed() {
        let reg = CheckIdRegistry::new();
        assert_eq!(
            reg.resolve(SourceFormat::Nessus, "12 34!56"),
            "NESSUS.12_34_56"
        );
    }
}
