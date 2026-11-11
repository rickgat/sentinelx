//! Compliance-framework control identifiers attached to findings.
//!
//! Each newtype here is a thin wrapper around the canonical string id used
//! by the source framework (NIST 800-53 Rev 5, ISO/IEC 27001:2022 Annex A,
//! PCI DSS 4.0, SOC 2 Trust Services Criteria, HIPAA Security Rule
//! safeguards). We do **not** maintain a closed enum of every control —
//! frameworks evolve, and an open string newtype lets callers attach
//! controls that ship in future revisions without recompiling.
//!
//! Validation is therefore syntactic only: each constructor checks an
//! ID-pattern regex appropriate to its framework.
//!
//! The aggregate [`ComplianceTags`] holds zero-or-more controls per
//! framework and is what gets embedded on a [`crate::entity::finding::Finding`].

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::DomainError;

// ---------------------------------------------------------------------------
// NIST 800-53 Rev 5 — control identifier (e.g. `AC-2`, `SC-8`, `SI-4(2)`).
// ---------------------------------------------------------------------------

/// NIST SP 800-53 Rev 5 control identifier.
///
/// The canonical form is `<FAMILY>-<NUM>` with an optional
/// `(<ENHANCEMENT>)` suffix, e.g. `AC-2`, `SC-8`, `SI-4(2)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NistControl(String);

impl NistControl {
    /// Construct, validating the canonical pattern.
    pub fn new(id: impl Into<String>) -> Result<Self, DomainError> {
        let id = id.into();
        validate_nist(&id)?;
        Ok(Self(id))
    }

    /// String form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_nist(id: &str) -> Result<(), DomainError> {
    // <FAMILY>-<NUM>[(<ENH>)] — family is 2-3 ASCII uppercase letters,
    // NUM is one or more digits, optional enhancement in parens is digits.
    let mut chars = id.chars();
    let mut family_len = 0_usize;
    for c in chars.by_ref() {
        if c == '-' {
            break;
        }
        if !c.is_ascii_uppercase() {
            return Err(DomainError::invalid(format!(
                "NIST control family must be uppercase ASCII letters, got {id:?}",
            )));
        }
        family_len = family_len.saturating_add(1);
        if family_len > 3 {
            return Err(DomainError::invalid(format!(
                "NIST control family too long in {id:?}",
            )));
        }
    }
    if family_len < 2 {
        return Err(DomainError::invalid(format!(
            "NIST control family too short in {id:?}",
        )));
    }
    let rest: String = chars.collect();
    if rest.is_empty() {
        return Err(DomainError::invalid(format!(
            "NIST control needs digits after '-', got {id:?}",
        )));
    }
    // Split on optional parenthesised enhancement.
    let (num, enh) = match rest.split_once('(') {
        Some((n, e)) => {
            let e = e.strip_suffix(')').ok_or_else(|| {
                DomainError::invalid(format!("NIST enhancement missing ')': {id:?}"))
            })?;
            (n, Some(e))
        }
        None => (rest.as_str(), None),
    };
    if num.is_empty() || !num.chars().all(|c| c.is_ascii_digit()) {
        return Err(DomainError::invalid(format!(
            "NIST control number must be digits, got {id:?}",
        )));
    }
    if let Some(e) = enh {
        if e.is_empty() || !e.chars().all(|c| c.is_ascii_digit()) {
            return Err(DomainError::invalid(format!(
                "NIST enhancement must be digits, got {id:?}",
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ISO/IEC 27001:2022 Annex A control id (e.g. `A.5.1`, `A.13.1.1`).
// ---------------------------------------------------------------------------

/// ISO/IEC 27001 Annex A control identifier (e.g. `A.13.1.1`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IsoControl(String);

impl IsoControl {
    /// Construct, validating that the id starts with `A.` followed by
    /// dot-separated numeric components.
    pub fn new(id: impl Into<String>) -> Result<Self, DomainError> {
        let id = id.into();
        validate_iso(&id)?;
        Ok(Self(id))
    }

    /// String form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_iso(id: &str) -> Result<(), DomainError> {
    let stripped = id.strip_prefix("A.").ok_or_else(|| {
        DomainError::invalid(format!(
            "ISO 27001 control must start with 'A.', got {id:?}"
        ))
    })?;
    if stripped.is_empty() {
        return Err(DomainError::invalid(format!(
            "ISO 27001 control id has no numeric components: {id:?}",
        )));
    }
    for part in stripped.split('.') {
        if part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()) {
            return Err(DomainError::invalid(format!(
                "ISO 27001 control component must be digits, got {id:?}",
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PCI DSS 4.0 requirement id (e.g. `4.1`, `4.2.1`, `6.4.3`).
// ---------------------------------------------------------------------------

/// PCI DSS 4.0 requirement identifier (e.g. `4.1`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PciRequirement(String);

impl PciRequirement {
    /// Construct, validating dot-separated numeric components.
    pub fn new(id: impl Into<String>) -> Result<Self, DomainError> {
        let id = id.into();
        validate_pci(&id)?;
        Ok(Self(id))
    }

    /// String form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_pci(id: &str) -> Result<(), DomainError> {
    if id.is_empty() {
        return Err(DomainError::invalid("PCI requirement id cannot be empty"));
    }
    for part in id.split('.') {
        if part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()) {
            return Err(DomainError::invalid(format!(
                "PCI requirement component must be digits, got {id:?}",
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SOC 2 Trust Services Criterion id (e.g. `CC6.1`, `CC7.2`, `A1.1`).
// ---------------------------------------------------------------------------

/// SOC 2 Trust Services Criterion identifier (e.g. `CC6.1`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Soc2Criterion(String);

impl Soc2Criterion {
    /// Construct, validating the canonical SOC 2 TSC pattern.
    pub fn new(id: impl Into<String>) -> Result<Self, DomainError> {
        let id = id.into();
        validate_soc2(&id)?;
        Ok(Self(id))
    }

    /// String form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_soc2(id: &str) -> Result<(), DomainError> {
    // Pattern: 1-3 ASCII uppercase letters, then a `<digit>.<digit>+` tail.
    let mut prefix_len = 0_usize;
    let mut iter = id.chars().peekable();
    while let Some(&c) = iter.peek() {
        if c.is_ascii_uppercase() {
            prefix_len = prefix_len.saturating_add(1);
            iter.next();
        } else {
            break;
        }
    }
    if !(1..=3).contains(&prefix_len) {
        return Err(DomainError::invalid(format!(
            "SOC 2 criterion prefix must be 1-3 uppercase letters, got {id:?}",
        )));
    }
    let tail: String = iter.collect();
    let (major, minor) = tail.split_once('.').ok_or_else(|| {
        DomainError::invalid(format!("SOC 2 criterion needs '.' separator, got {id:?}"))
    })?;
    if major.is_empty()
        || !major.chars().all(|c| c.is_ascii_digit())
        || minor.is_empty()
        || !minor.chars().all(|c| c.is_ascii_digit())
    {
        return Err(DomainError::invalid(format!(
            "SOC 2 criterion tail must be DIGIT.DIGIT+, got {id:?}",
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// HIPAA Security Rule safeguard id (e.g. `164.308(a)(1)(i)`).
// ---------------------------------------------------------------------------

/// HIPAA Security Rule safeguard identifier.
///
/// We accept any non-empty string that looks like a 45 CFR § citation
/// (starts with `164.`) because the full grammar is unwieldy and
/// the citation format is the de-facto identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HipaaSafeguard(String);

impl HipaaSafeguard {
    /// Construct, validating the `164.` prefix.
    pub fn new(id: impl Into<String>) -> Result<Self, DomainError> {
        let id = id.into();
        if !id.starts_with("164.") {
            return Err(DomainError::invalid(format!(
                "HIPAA safeguard id must start with '164.' (45 CFR §164.x), got {id:?}",
            )));
        }
        if id.chars().any(char::is_whitespace) {
            return Err(DomainError::invalid(format!(
                "HIPAA safeguard id cannot contain whitespace, got {id:?}",
            )));
        }
        Ok(Self(id))
    }

    /// String form.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Display + serde for every newtype.
// ---------------------------------------------------------------------------

macro_rules! impl_str_serde {
    ($t:ty) => {
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::new(s).map_err(serde::de::Error::custom)
            }
        }
    };
}

impl_str_serde!(NistControl);
impl_str_serde!(IsoControl);
impl_str_serde!(PciRequirement);
impl_str_serde!(Soc2Criterion);
impl_str_serde!(HipaaSafeguard);

// ---------------------------------------------------------------------------
// Aggregate
// ---------------------------------------------------------------------------

/// All compliance-framework controls a finding maps to.
///
/// Every field defaults to an empty vector; absent frameworks serialise
/// as `[]` (or, with `#[serde(default, skip_serializing_if = "Vec::is_empty")]`
/// on the wrapping `Finding` field, are omitted entirely).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceTags {
    /// NIST SP 800-53 Rev 5 controls.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nist_800_53: Vec<NistControl>,
    /// ISO/IEC 27001 Annex A controls.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub iso_27001: Vec<IsoControl>,
    /// PCI DSS 4.0 requirements.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pci_dss: Vec<PciRequirement>,
    /// SOC 2 Trust Services Criteria.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub soc2: Vec<Soc2Criterion>,
    /// HIPAA Security Rule safeguards.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hipaa: Vec<HipaaSafeguard>,
}

impl ComplianceTags {
    /// `true` if no framework carries any control.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.nist_800_53.is_empty()
            && self.iso_27001.is_empty()
            && self.pci_dss.is_empty()
            && self.soc2.is_empty()
            && self.hipaa.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn nist_accepts_canonical() {
        assert_eq!(NistControl::new("AC-2").unwrap().as_str(), "AC-2");
        assert_eq!(NistControl::new("SC-8").unwrap().as_str(), "SC-8");
        assert_eq!(NistControl::new("SI-4(2)").unwrap().as_str(), "SI-4(2)");
    }

    #[test]
    fn nist_rejects_bad_family() {
        assert!(matches!(
            NistControl::new("ac-2"),
            Err(DomainError::InvalidValue(_)),
        ));
        assert!(matches!(
            NistControl::new("A-2"),
            Err(DomainError::InvalidValue(_)),
        ));
        assert!(matches!(
            NistControl::new("ACDE-2"),
            Err(DomainError::InvalidValue(_)),
        ));
    }

    #[test]
    fn nist_rejects_bad_number() {
        assert!(matches!(
            NistControl::new("AC-"),
            Err(DomainError::InvalidValue(_)),
        ));
        assert!(matches!(
            NistControl::new("AC-XX"),
            Err(DomainError::InvalidValue(_)),
        ));
    }

    #[test]
    fn iso_accepts_canonical() {
        assert_eq!(IsoControl::new("A.5.1").unwrap().as_str(), "A.5.1");
        assert_eq!(IsoControl::new("A.13.1.1").unwrap().as_str(), "A.13.1.1",);
    }

    #[test]
    fn iso_rejects_missing_prefix() {
        assert!(matches!(
            IsoControl::new("5.1"),
            Err(DomainError::InvalidValue(_)),
        ));
    }

    #[test]
    fn pci_accepts_canonical() {
        assert_eq!(PciRequirement::new("4.1").unwrap().as_str(), "4.1");
        assert_eq!(PciRequirement::new("6.4.3").unwrap().as_str(), "6.4.3");
    }

    #[test]
    fn pci_rejects_letters() {
        assert!(matches!(
            PciRequirement::new("4.X"),
            Err(DomainError::InvalidValue(_)),
        ));
    }

    #[test]
    fn soc2_accepts_canonical() {
        assert_eq!(Soc2Criterion::new("CC6.1").unwrap().as_str(), "CC6.1");
        assert_eq!(Soc2Criterion::new("A1.1").unwrap().as_str(), "A1.1");
    }

    #[test]
    fn soc2_rejects_lowercase_prefix() {
        assert!(matches!(
            Soc2Criterion::new("cc6.1"),
            Err(DomainError::InvalidValue(_)),
        ));
    }

    #[test]
    fn hipaa_requires_164_prefix() {
        assert!(HipaaSafeguard::new("164.308(a)(1)(i)").is_ok());
        assert!(matches!(
            HipaaSafeguard::new("HIPAA-1"),
            Err(DomainError::InvalidValue(_)),
        ));
    }

    #[test]
    fn empty_tags_round_trip_to_empty_object() {
        let tags = ComplianceTags::default();
        assert!(tags.is_empty());
        let json = serde_json::to_string(&tags).unwrap();
        assert_eq!(json, "{}");
        let back: ComplianceTags = serde_json::from_str(&json).unwrap();
        assert_eq!(back, tags);
    }

    #[test]
    fn populated_tags_round_trip() {
        let tags = ComplianceTags {
            nist_800_53: vec![NistControl::new("SC-8").unwrap()],
            iso_27001: vec![IsoControl::new("A.13.1.1").unwrap()],
            pci_dss: vec![PciRequirement::new("4.1").unwrap()],
            soc2: vec![Soc2Criterion::new("CC6.1").unwrap()],
            hipaa: vec![HipaaSafeguard::new("164.312(e)(1)").unwrap()],
        };
        let json = serde_json::to_string(&tags).unwrap();
        let back: ComplianceTags = serde_json::from_str(&json).unwrap();
        assert_eq!(back, tags);
    }
}
