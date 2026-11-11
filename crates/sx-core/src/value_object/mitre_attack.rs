//! MITRE ATT&CK tactic / technique / sub-technique identifiers.
//!
//! Identifiers follow MITRE's canonical scheme:
//! - tactic id: `TA####` (e.g. `TA0009` Collection)
//! - technique id: `T####` (e.g. `T1040` Network Sniffing)
//! - sub-technique id: `T####.###` (e.g. `T1059.001` `PowerShell`)
//!
//! We validate only the syntactic shape — semantic membership in the
//! ATT&CK matrix changes over time and is the consumer's responsibility
//! to keep in sync with the MITRE STIX bundle.

use serde::{Deserialize, Serialize};

use crate::error::DomainError;

/// A MITRE ATT&CK technique reference associated with a finding.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MitreAttackTechnique {
    /// Tactic id (e.g. `TA0009`).
    pub tactic: String,
    /// Technique id (e.g. `T1040`).
    pub technique: String,
    /// Optional sub-technique id (e.g. `T1059.001`). If present, must
    /// share the technique prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtechnique: Option<String>,
}

impl MitreAttackTechnique {
    /// Build a new ATT&CK reference, validating each id's syntactic shape.
    pub fn new(
        tactic: impl Into<String>,
        technique: impl Into<String>,
        subtechnique: Option<String>,
    ) -> Result<Self, DomainError> {
        let tactic = tactic.into();
        let technique = technique.into();
        validate_tactic_id(&tactic)?;
        validate_technique_id(&technique)?;
        if let Some(sub) = &subtechnique {
            validate_subtechnique_id(sub)?;
            if !sub.starts_with(&format!("{technique}.")) {
                return Err(DomainError::invariant(format!(
                    "sub-technique {sub:?} does not share prefix of technique {technique:?}",
                )));
            }
        }
        Ok(Self {
            tactic,
            technique,
            subtechnique,
        })
    }
}

fn validate_tactic_id(id: &str) -> Result<(), DomainError> {
    let suffix = id.strip_prefix("TA").ok_or_else(|| {
        DomainError::invalid(format!("ATT&CK tactic id must start with 'TA', got {id:?}"))
    })?;
    if suffix.len() != 4 || !suffix.chars().all(|c| c.is_ascii_digit()) {
        return Err(DomainError::invalid(format!(
            "ATT&CK tactic id must be TA followed by 4 digits, got {id:?}",
        )));
    }
    Ok(())
}

fn validate_technique_id(id: &str) -> Result<(), DomainError> {
    let suffix = id.strip_prefix('T').ok_or_else(|| {
        DomainError::invalid(format!(
            "ATT&CK technique id must start with 'T', got {id:?}"
        ))
    })?;
    if suffix.len() != 4 || !suffix.chars().all(|c| c.is_ascii_digit()) {
        return Err(DomainError::invalid(format!(
            "ATT&CK technique id must be T followed by 4 digits, got {id:?}",
        )));
    }
    Ok(())
}

fn validate_subtechnique_id(id: &str) -> Result<(), DomainError> {
    let (parent, sub) = id.split_once('.').ok_or_else(|| {
        DomainError::invalid(format!(
            "ATT&CK sub-technique id must contain '.', got {id:?}",
        ))
    })?;
    validate_technique_id(parent)?;
    if sub.len() != 3 || !sub.chars().all(|c| c.is_ascii_digit()) {
        return Err(DomainError::invalid(format!(
            "ATT&CK sub-technique suffix must be 3 digits, got {id:?}",
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_ids() {
        let t = MitreAttackTechnique::new("TA0009", "T1040", None).unwrap();
        assert_eq!(t.tactic, "TA0009");
        assert_eq!(t.technique, "T1040");
        assert!(t.subtechnique.is_none());
    }

    #[test]
    fn accepts_subtechnique() {
        let t = MitreAttackTechnique::new("TA0002", "T1059", Some("T1059.001".into())).unwrap();
        assert_eq!(t.subtechnique.as_deref(), Some("T1059.001"));
    }

    #[test]
    fn rejects_subtechnique_with_wrong_parent() {
        let r = MitreAttackTechnique::new("TA0002", "T1059", Some("T1086.001".into()));
        assert!(matches!(r, Err(DomainError::InvariantViolation(_))));
    }

    #[test]
    fn rejects_short_tactic_id() {
        let r = MitreAttackTechnique::new("TA9", "T1040", None);
        assert!(matches!(r, Err(DomainError::InvalidValue(_))));
    }

    #[test]
    fn rejects_short_technique_id() {
        let r = MitreAttackTechnique::new("TA0009", "T40", None);
        assert!(matches!(r, Err(DomainError::InvalidValue(_))));
    }

    #[test]
    fn serde_round_trip() {
        let t = MitreAttackTechnique::new("TA0002", "T1059", Some("T1059.001".into())).unwrap();
        let json = serde_json::to_string(&t).unwrap();
        let back: MitreAttackTechnique = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }

    #[test]
    fn serde_omits_empty_subtechnique() {
        let t = MitreAttackTechnique::new("TA0009", "T1040", None).unwrap();
        let json = serde_json::to_string(&t).unwrap();
        assert!(!json.contains("subtechnique"));
    }
}
