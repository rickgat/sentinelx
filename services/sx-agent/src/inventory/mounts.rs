//! Parser for `/proc/mounts`.
//!
//! The file is space-separated with octal-escapes for any literal space in
//! the device or mountpoint fields (kernel emits `\040` for a space). We
//! handle that escape so paths like `/mnt/My Drive` parse correctly.

use serde::Serialize;

/// A single mount entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Mount {
    pub source: String,
    pub mountpoint: String,
    pub fstype: String,
    pub options: String,
}

/// Parses `/proc/mounts`-style content into a vector of [`Mount`].
///
/// Lines with fewer than four fields are silently skipped — the kernel
/// guarantees the format but cautious parsing keeps the agent crash-free if
/// it ever sees a synthetic or truncated fixture.
#[must_use]
pub fn parse_mounts(contents: &str) -> Vec<Mount> {
    let mut out = Vec::new();
    for line in contents.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let Some(source) = fields.next() else {
            continue;
        };
        let Some(mountpoint) = fields.next() else {
            continue;
        };
        let Some(fstype) = fields.next() else {
            continue;
        };
        let Some(options) = fields.next() else {
            continue;
        };
        out.push(Mount {
            source: unescape_mount_field(source),
            mountpoint: unescape_mount_field(mountpoint),
            fstype: unescape_mount_field(fstype),
            options: unescape_mount_field(options),
        });
    }
    out
}

/// Decodes the four octal escape sequences the kernel uses in mount lines:
/// `\040` space, `\011` tab, `\012` newline, `\134` backslash.
fn unescape_mount_field(raw: &str) -> String {
    if !raw.contains('\\') {
        return raw.to_owned();
    }
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(raw.len());
    let mut i = 0;
    while i < bytes.len() {
        let cur = match bytes.get(i) {
            Some(b) => *b,
            None => break,
        };
        if cur == b'\\' && i.saturating_add(4) <= bytes.len() {
            // Try to read three octal digits.
            if let Some(s) = raw.get(i + 1..i + 4) {
                if s.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
                    if let Ok(v) = u8::from_str_radix(s, 8) {
                        out.push(v as char);
                        i += 4;
                        continue;
                    }
                }
            }
        }
        out.push(cur as char);
        i += 1;
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn parse_mounts_handles_spaces_in_mountpoint() {
        let sample = "/dev/sda1 / ext4 rw,relatime 0 0\n/dev/sdb1 /mnt/My\\040Drive ext4 rw 0 0\n";
        let parsed = parse_mounts(sample);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].source, "/dev/sda1");
        assert_eq!(parsed[0].mountpoint, "/");
        assert_eq!(parsed[1].mountpoint, "/mnt/My Drive");
        assert_eq!(parsed[1].fstype, "ext4");
    }

    #[test]
    fn parse_mounts_skips_blank_lines() {
        let sample = "\n\n/dev/sda1 / ext4 rw 0 0\n";
        let parsed = parse_mounts(sample);
        assert_eq!(parsed.len(), 1);
    }
}
