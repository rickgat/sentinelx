//! Parser for `/etc/os-release`.
//!
//! The file is a tiny subset of shell-syntax: `KEY=VALUE` lines where the
//! value may or may not be double-quoted. We deliberately implement a
//! standalone parser instead of pulling a crate so the agent stays small.

use serde::Serialize;

/// A subset of the `/etc/os-release` keys we report upstream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct OsRelease {
    /// `ID` field (e.g. `"ubuntu"`).
    pub id: Option<String>,
    /// `VERSION_ID` field (e.g. `"24.04"`).
    pub version_id: Option<String>,
    /// `PRETTY_NAME` field (e.g. `"Ubuntu 24.04 LTS"`).
    pub pretty_name: Option<String>,
}

/// Parses an `os-release` document from a string.
///
/// Unknown keys are silently ignored. Quoted values are unquoted only when
/// the entire value is wrapped in matching single or double quotes.
#[must_use]
pub fn parse_os_release(contents: &str) -> OsRelease {
    let mut out = OsRelease::default();
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let value = unquote(v);
        match k.trim() {
            "ID" => out.id = Some(value),
            "VERSION_ID" => out.version_id = Some(value),
            "PRETTY_NAME" => out.pretty_name = Some(value),
            _ => {}
        }
    }
    out
}

fn unquote(raw: &str) -> String {
    let trimmed = raw.trim();
    let bytes = trimmed.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes.first().copied();
        let last = bytes.last().copied();
        if (first == Some(b'"') && last == Some(b'"'))
            || (first == Some(b'\'') && last == Some(b'\''))
        {
            // Strip first and last char (single-byte ASCII quote).
            return trimmed
                .get(1..trimmed.len().saturating_sub(1))
                .unwrap_or("")
                .to_owned();
        }
    }
    trimmed.to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_os_release_extracts_id_and_version() {
        let sample = r#"
NAME="Ubuntu"
VERSION="24.04 LTS (Noble Numbat)"
ID=ubuntu
VERSION_ID="24.04"
PRETTY_NAME="Ubuntu 24.04 LTS"
HOME_URL="https://www.ubuntu.com/"
"#;
        let parsed = parse_os_release(sample);
        assert_eq!(parsed.id.as_deref(), Some("ubuntu"));
        assert_eq!(parsed.version_id.as_deref(), Some("24.04"));
        assert_eq!(parsed.pretty_name.as_deref(), Some("Ubuntu 24.04 LTS"));
    }

    #[test]
    fn parse_os_release_ignores_comments_and_blank_lines() {
        let sample = "# comment\n\nID=alpine\n";
        let parsed = parse_os_release(sample);
        assert_eq!(parsed.id.as_deref(), Some("alpine"));
        assert!(parsed.version_id.is_none());
    }
}
