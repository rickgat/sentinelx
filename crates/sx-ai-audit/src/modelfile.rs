//! Model-file supply-chain scanner.
//!
//! Two independent checks that operate purely on a `&[u8]` (no filesystem
//! traversal, no deserialisation of attacker-controlled data):
//!
//! * [`scan_pickle`] — flags dangerous Python pickle opcodes
//!   (`GLOBAL`/`STACK_GLOBAL`/`REDUCE`/`INST`/`OBJ`/`NEWOBJ`) that reference
//!   code-execution modules (`os`, `subprocess`, `builtins`, `posix`, …).
//!   This is how malicious `.pkl` / PyTorch `.bin` payloads smuggle RCE.
//! * [`validate_safetensors`] — parses the 8-byte little-endian header
//!   length + JSON header of a safetensors file and flags oversized or
//!   malformed headers.
//!
//! [`scan_model_file`] dispatches on the leading magic and runs the
//! appropriate check(s).

use serde::{Deserialize, Serialize};

use crate::mapping::{AtlasTechnique, OwaspLlmTop10, Severity};

/// The category of a model-file finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelFileFindingKind {
    /// A dangerous pickle opcode referencing a code-execution module.
    DangerousPickleOpcode,
    /// A pickle `REDUCE`/`NEWOBJ` callable invocation (executes on load).
    PickleReduce,
    /// The safetensors header length is implausible / out of bounds.
    SafetensorsHeaderOutOfBounds,
    /// The safetensors JSON header failed to parse.
    SafetensorsMalformedHeader,
}

impl ModelFileFindingKind {
    /// Short, machine-readable code matching the serde tag.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::DangerousPickleOpcode => "dangerous_pickle_opcode",
            Self::PickleReduce => "pickle_reduce",
            Self::SafetensorsHeaderOutOfBounds => "safetensors_header_out_of_bounds",
            Self::SafetensorsMalformedHeader => "safetensors_malformed_header",
        }
    }
}

/// One structured model-file finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelFileFinding {
    /// What was detected.
    pub kind: ModelFileFindingKind,
    /// Severity bucket.
    pub severity: Severity,
    /// Operator-readable detail.
    pub detail: String,
    /// Byte offset of the detection, when meaningful.
    pub offset: Option<u64>,
    /// OWASP LLM Top-10 id this maps to.
    pub owasp_id: String,
    /// MITRE ATLAS technique id this maps to.
    pub atlas_id: String,
}

// --- Pickle opcode constants (subset relevant to code execution) ---------

/// `GLOBAL` — `c` (0x63): push a global, named by the following two lines.
const OP_GLOBAL: u8 = b'c';
/// `STACK_GLOBAL` — 0x93: push a global named by two stack strings.
const OP_STACK_GLOBAL: u8 = 0x93;
/// `REDUCE` — `R` (0x52): call callable(args) — executes on unpickle.
const OP_REDUCE: u8 = b'R';
/// `INST` — `i` (0x69): build a class instance (legacy GLOBAL+REDUCE).
const OP_INST: u8 = b'i';
/// `OBJ` — `o` (0x6f): build an object from a stack class.
const OP_OBJ: u8 = b'o';
/// `NEWOBJ` — 0x81: build via `cls.__new__`.
const OP_NEWOBJ: u8 = 0x81;
/// `NEWOBJ_EX` — 0x92: `NEWOBJ` with kwargs.
const OP_NEWOBJ_EX: u8 = 0x92;

/// Module / callable names whose presence near a `GLOBAL` opcode is a
/// code-execution red flag.
const DANGEROUS_NAMES: &[&str] = &[
    "os",
    "nt",
    "posix",
    "subprocess",
    "builtins",
    "__builtin__",
    "importlib",
    "pty",
    "socket",
    "system",
    "popen",
    "exec",
    "eval",
    "runpy",
    "commands",
];

fn maps(kind: ModelFileFindingKind) -> (String, String) {
    // Every model-file finding is an ML supply-chain / poisoning concern.
    let atlas = match kind {
        ModelFileFindingKind::DangerousPickleOpcode | ModelFileFindingKind::PickleReduce => {
            AtlasTechnique::T0018BackdoorMlModel
        }
        ModelFileFindingKind::SafetensorsHeaderOutOfBounds
        | ModelFileFindingKind::SafetensorsMalformedHeader => {
            AtlasTechnique::T0010MlSupplyChainCompromise
        }
    };
    (
        OwaspLlmTop10::Llm03SupplyChain.id().to_owned(),
        atlas.id().to_owned(),
    )
}

fn finding(
    kind: ModelFileFindingKind,
    severity: Severity,
    detail: String,
    offset: Option<u64>,
) -> ModelFileFinding {
    let (owasp_id, atlas_id) = maps(kind);
    ModelFileFinding {
        kind,
        severity,
        detail,
        offset,
        owasp_id,
        atlas_id,
    }
}

/// `true` if `bytes` looks like a Python pickle stream (starts with the
/// `PROTO` opcode `0x80`, or a bare legacy `GLOBAL`/`(` opcode).
#[must_use]
pub fn looks_like_pickle(bytes: &[u8]) -> bool {
    matches!(bytes.first(), Some(&(0x80 | b'(' | OP_GLOBAL)))
}

/// Scan a byte slice for dangerous pickle opcodes.
///
/// The scan is intentionally conservative and offset-reporting: it does
/// **not** unpickle anything. It walks the stream byte-by-byte looking for
/// `GLOBAL`/`STACK_GLOBAL`/`REDUCE`/`INST`/`OBJ`/`NEWOBJ` opcodes and, for
/// the name-carrying ones, checks whether a dangerous module/callable name
/// appears in the surrounding window.
#[must_use]
pub fn scan_pickle(bytes: &[u8]) -> Vec<ModelFileFinding> {
    let mut findings = Vec::new();

    for (idx, &byte) in bytes.iter().enumerate() {
        let offset = idx as u64;
        match byte {
            OP_GLOBAL | OP_INST => {
                // GLOBAL/INST are followed by `module\nname\n`. Read the
                // window after the opcode and look for a dangerous token.
                if let Some(name) = dangerous_name_after(bytes, idx + 1) {
                    findings.push(finding(
                        ModelFileFindingKind::DangerousPickleOpcode,
                        Severity::Critical,
                        format!("pickle GLOBAL/INST references dangerous module `{name}`"),
                        Some(offset),
                    ));
                }
            }
            OP_STACK_GLOBAL | OP_OBJ | OP_NEWOBJ | OP_NEWOBJ_EX => {
                // The module/name were pushed earlier as unicode strings.
                // Flag when a dangerous token appears anywhere in the
                // preceding window.
                if let Some(name) = dangerous_name_before(bytes, idx) {
                    findings.push(finding(
                        ModelFileFindingKind::DangerousPickleOpcode,
                        Severity::High,
                        format!("pickle STACK_GLOBAL/NEWOBJ near dangerous token `{name}`"),
                        Some(offset),
                    ));
                }
            }
            OP_REDUCE => {
                findings.push(finding(
                    ModelFileFindingKind::PickleReduce,
                    Severity::Medium,
                    "pickle REDUCE opcode — a callable is invoked on unpickle".to_owned(),
                    Some(offset),
                ));
            }
            _ => {}
        }
    }

    findings
}

/// Look for a dangerous token in the bytes immediately after a name-carrying
/// opcode (bounded window).
fn dangerous_name_after(bytes: &[u8], start: usize) -> Option<&'static str> {
    let end = start.saturating_add(64).min(bytes.len());
    let window = bytes.get(start..end)?;
    match_dangerous(window)
}

/// Look for a dangerous token in the bytes before a stack-based opcode
/// (bounded window).
fn dangerous_name_before(bytes: &[u8], idx: usize) -> Option<&'static str> {
    let start = idx.saturating_sub(64);
    let window = bytes.get(start..idx)?;
    match_dangerous(window)
}

/// Return the first dangerous token found as a delimited word in `window`.
fn match_dangerous(window: &[u8]) -> Option<&'static str> {
    let text = String::from_utf8_lossy(window);
    // Require a word-ish boundary so a dangerous token is not matched inside
    // a longer benign identifier.
    DANGEROUS_NAMES.iter().copied().find(|name| {
        text.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(|tok| tok == *name)
    })
}

/// Maximum plausible safetensors JSON header length (128 MiB). Anything
/// larger is almost certainly a malformed / hostile header-length field.
pub const MAX_SAFETENSORS_HEADER: u64 = 128 * 1024 * 1024;

/// Validate a safetensors file's header.
///
/// Layout: `[u64 LE header_len][header_len bytes of JSON][tensor data...]`.
/// Flags an out-of-bounds `header_len` and a JSON header that does not parse
/// to an object.
#[must_use]
pub fn validate_safetensors(bytes: &[u8]) -> Vec<ModelFileFinding> {
    let mut findings = Vec::new();

    let Some(len_bytes) = bytes.get(0..8) else {
        findings.push(finding(
            ModelFileFindingKind::SafetensorsHeaderOutOfBounds,
            Severity::High,
            "file is shorter than the 8-byte safetensors header length prefix".to_owned(),
            Some(0),
        ));
        return findings;
    };

    // `len_bytes` is exactly 8 bytes, so the conversion cannot fail.
    let arr: [u8; 8] = match len_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return findings,
    };
    let header_len = u64::from_le_bytes(arr);
    let body_len = (bytes.len() as u64).saturating_sub(8);

    if !(2..=MAX_SAFETENSORS_HEADER).contains(&header_len) || header_len > body_len {
        findings.push(finding(
            ModelFileFindingKind::SafetensorsHeaderOutOfBounds,
            Severity::High,
            format!(
                "safetensors header length {header_len} is out of bounds (body is {body_len} bytes, cap {MAX_SAFETENSORS_HEADER})"
            ),
            Some(0),
        ));
        return findings;
    }

    // `header_len` fits in the body (checked above), so it fits in usize on
    // every host we build for; the slice is therefore in-bounds.
    let Ok(header_len_usize) = usize::try_from(header_len) else {
        return findings;
    };
    let header_end = 8usize.saturating_add(header_len_usize);
    let Some(header) = bytes.get(8..header_end) else {
        findings.push(finding(
            ModelFileFindingKind::SafetensorsHeaderOutOfBounds,
            Severity::High,
            "safetensors header length points past the end of the file".to_owned(),
            Some(8),
        ));
        return findings;
    };

    match serde_json::from_slice::<serde_json::Value>(header) {
        Ok(v) if v.is_object() => {}
        Ok(_) => findings.push(finding(
            ModelFileFindingKind::SafetensorsMalformedHeader,
            Severity::Medium,
            "safetensors header parsed but is not a JSON object".to_owned(),
            Some(8),
        )),
        Err(e) => findings.push(finding(
            ModelFileFindingKind::SafetensorsMalformedHeader,
            Severity::Medium,
            format!("safetensors JSON header failed to parse: {e}"),
            Some(8),
        )),
    }

    findings
}

/// Dispatch on the leading magic and run the appropriate scan(s).
///
/// Pickle streams are scanned for dangerous opcodes; everything else is
/// treated as a candidate safetensors file and its header is validated.
#[must_use]
pub fn scan_model_file(bytes: &[u8]) -> Vec<ModelFileFinding> {
    if looks_like_pickle(bytes) {
        scan_pickle(bytes)
    } else {
        validate_safetensors(bytes)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn detects_global_os_system() {
        // PROTO 2, then GLOBAL `os\nsystem\n`, then REDUCE.
        let mut bytes = vec![0x80, 0x02];
        bytes.push(OP_GLOBAL);
        bytes.extend_from_slice(b"os\nsystem\n");
        bytes.push(OP_REDUCE);
        let findings = scan_model_file(&bytes);
        assert!(findings
            .iter()
            .any(|f| f.kind == ModelFileFindingKind::DangerousPickleOpcode
                && f.severity == Severity::Critical));
        assert!(findings
            .iter()
            .any(|f| f.kind == ModelFileFindingKind::PickleReduce));
    }

    #[test]
    fn benign_pickle_has_no_dangerous_opcode_finding() {
        // PROTO 2, GLOBAL `collections\nOrderedDict\n`, STOP.
        let mut bytes = vec![0x80, 0x02];
        bytes.push(OP_GLOBAL);
        bytes.extend_from_slice(b"collections\nOrderedDict\n");
        bytes.push(b'.');
        let findings = scan_pickle(&bytes);
        assert!(findings
            .iter()
            .all(|f| f.kind != ModelFileFindingKind::DangerousPickleOpcode));
    }

    #[test]
    fn valid_safetensors_header_is_clean() {
        let header = br#"{"__metadata__":{"format":"pt"}}"#;
        let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
        bytes.extend_from_slice(header);
        bytes.extend_from_slice(&[0u8; 16]); // fake tensor body
        let findings = validate_safetensors(&bytes);
        assert!(findings.is_empty(), "unexpected findings: {findings:?}");
    }

    #[test]
    fn oversized_header_length_is_flagged() {
        // header_len = u64::MAX, no body.
        let bytes = u64::MAX.to_le_bytes().to_vec();
        let findings = validate_safetensors(&bytes);
        assert!(findings
            .iter()
            .any(|f| f.kind == ModelFileFindingKind::SafetensorsHeaderOutOfBounds));
    }

    #[test]
    fn malformed_json_header_is_flagged() {
        let header = b"{not valid json";
        let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
        bytes.extend_from_slice(header);
        bytes.extend_from_slice(&[0u8; 4]);
        let findings = validate_safetensors(&bytes);
        assert!(findings
            .iter()
            .any(|f| f.kind == ModelFileFindingKind::SafetensorsMalformedHeader));
    }

    #[test]
    fn truncated_file_is_flagged() {
        let findings = validate_safetensors(&[0u8, 1, 2]);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].kind,
            ModelFileFindingKind::SafetensorsHeaderOutOfBounds
        );
    }

    #[test]
    fn findings_carry_supply_chain_mapping() {
        let mut bytes = vec![0x80, 0x02, OP_GLOBAL];
        bytes.extend_from_slice(b"subprocess\ncall\n");
        bytes.push(OP_REDUCE);
        let findings = scan_pickle(&bytes);
        assert!(findings.iter().all(|f| f.owasp_id == "LLM03"));
    }
}
