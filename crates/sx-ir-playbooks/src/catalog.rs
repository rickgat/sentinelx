//! Pre-canned playbook catalog.
//!
//! Each playbook is embedded as JSON (via `include_str!`) so the wire
//! schema is the single source of truth — operators copying the JSON into
//! their own runbook collection see the exact shape the service accepts.
//!
//! The five built-ins cover the highest-frequency scenarios called out
//! in P3-004 plus CRIT-002:
//!
//! * `ransomware`
//! * `data_exfiltration`
//! * `credential_compromise`
//! * `insider_threat`
//! * `audit_chain_compromise` — CRIT-002, auto-fired by the
//!   background chain verifier on `audit.chain.broken` events.
//!
//! Each one covers all four NIST SP 800-61 Rev 2 phases so the
//! per-phase checklist UI has at least one row per column.

use crate::error::IrPlaybookError;
use crate::playbook::Playbook;

/// Stable ids exposed via the `/v1/ir/playbooks` catalog endpoint.
pub const BUILTIN_PLAYBOOK_IDS: &[&str] = &[
    "ransomware",
    "data_exfiltration",
    "credential_compromise",
    "insider_threat",
    "audit_chain_compromise",
];

/// Catalog id of the playbook auto-fired by the audit-chain verifier when
/// it detects a broken-state chain. Mirrored as a constant so the
/// auto-fire wiring in `service.rs` and the sx-audit verifier cannot
/// accidentally drift from the JSON's `id` field.
pub const AUDIT_CHAIN_COMPROMISE_PLAYBOOK_ID: &str = "audit_chain_compromise";

const RANSOMWARE_JSON: &str = include_str!("../catalog/ransomware.json");
const DATA_EXFIL_JSON: &str = include_str!("../catalog/data_exfiltration.json");
const CRED_COMPROMISE_JSON: &str = include_str!("../catalog/credential_compromise.json");
const INSIDER_THREAT_JSON: &str = include_str!("../catalog/insider_threat.json");
const AUDIT_CHAIN_COMPROMISE_JSON: &str = include_str!("../catalog/audit_chain_compromise.json");

/// Parse + validate every built-in playbook. Returned in the same order
/// as [`BUILTIN_PLAYBOOK_IDS`].
pub fn builtin_catalog() -> Result<Vec<Playbook>, IrPlaybookError> {
    Ok(vec![
        Playbook::from_json(RANSOMWARE_JSON)?,
        Playbook::from_json(DATA_EXFIL_JSON)?,
        Playbook::from_json(CRED_COMPROMISE_JSON)?,
        Playbook::from_json(INSIDER_THREAT_JSON)?,
        Playbook::from_json(AUDIT_CHAIN_COMPROMISE_JSON)?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phase::IrPhase;

    #[test]
    fn loads_every_builtin() {
        let pbs = builtin_catalog().expect("catalog loads");
        let ids: Vec<&str> = pbs.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, BUILTIN_PLAYBOOK_IDS);
    }

    #[test]
    fn every_builtin_validates() {
        for pb in builtin_catalog().expect("catalog loads") {
            pb.validate().expect("playbook validates");
            assert!(!pb.steps.is_empty());
        }
    }

    #[test]
    fn every_builtin_covers_every_phase() {
        for pb in builtin_catalog().expect("catalog loads") {
            for phase in IrPhase::ordered() {
                assert!(
                    pb.steps.iter().any(|s| s.phase == phase),
                    "playbook '{}' missing phase '{}'",
                    pb.id,
                    phase.as_str()
                );
            }
        }
    }
}
