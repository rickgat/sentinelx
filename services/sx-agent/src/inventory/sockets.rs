//! Parser for `/proc/net/tcp` and `/proc/net/tcp6` listening-socket tables.
//!
//! The kernel emits hex-encoded address/port pairs and a state byte. We only
//! surface sockets in the `LISTEN` state (`0x0A`) and parse just the fields
//! we need — address family, ip, port, inode. The fixture-based test suite
//! lets us exercise this on any platform (macOS CI included).

use serde::Serialize;

/// A socket the kernel has reported as listening.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ListeningSocket {
    /// `"v4"` or `"v6"`.
    pub family: &'static str,
    /// Dotted-quad IPv4 (`"127.0.0.1"`) or coalesced IPv6 (`"::1"`).
    pub local_address: String,
    /// Port the socket is bound to.
    pub port: u16,
    /// Kernel inode (useful for matching processes via `/proc/*/fd`).
    pub inode: u64,
}

const TCP_STATE_LISTEN: u8 = 0x0A;

/// Parses an IPv4 `/proc/net/tcp`-style table.
#[must_use]
pub fn parse_proc_net_tcp(contents: &str) -> Vec<ListeningSocket> {
    parse_inner(contents, false)
}

/// Parses an IPv6 `/proc/net/tcp6`-style table.
#[must_use]
pub fn parse_proc_net_tcp6(contents: &str) -> Vec<ListeningSocket> {
    parse_inner(contents, true)
}

fn parse_inner(contents: &str, is_v6: bool) -> Vec<ListeningSocket> {
    let mut out = Vec::new();
    for (idx, line) in contents.lines().enumerate() {
        if idx == 0 {
            continue; // header
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        // sl local_address rem_address st tx_queue rx_queue tr tm-when retrnsmt uid timeout inode
        let Some(local) = fields.get(1) else { continue };
        let Some(state) = fields.get(3) else { continue };
        let Some(inode) = fields.get(9) else { continue };
        let Ok(state_byte) = u8::from_str_radix(state, 16) else {
            continue;
        };
        if state_byte != TCP_STATE_LISTEN {
            continue;
        }
        let Some((addr_hex, port_hex)) = local.split_once(':') else {
            continue;
        };
        let Ok(port) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        let Ok(inode_num) = inode.parse::<u64>() else {
            continue;
        };
        let parsed = if is_v6 {
            decode_ipv6(addr_hex)
        } else {
            decode_ipv4(addr_hex)
        };
        let Some(addr_str) = parsed else { continue };
        out.push(ListeningSocket {
            family: if is_v6 { "v6" } else { "v4" },
            local_address: addr_str,
            port,
            inode: inode_num,
        });
    }
    out
}

/// IPv4: kernel emits little-endian-per-byte hex, e.g. `0100007F` == `127.0.0.1`.
fn decode_ipv4(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, slot) in octets.iter_mut().enumerate() {
        let off = i * 2;
        let chunk = hex.get(off..off + 2)?;
        *slot = u8::from_str_radix(chunk, 16).ok()?;
    }
    // Kernel emits little-endian per the historical /proc format.
    octets.reverse();
    let [a, b, c, d] = octets;
    Some(format!("{a}.{b}.{c}.{d}"))
}

/// IPv6: 32 hex chars representing four 32-bit words, each stored
/// little-endian within itself. We reconstruct the canonical 8-group form.
fn decode_ipv6(hex: &str) -> Option<String> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (i, slot) in bytes.iter_mut().enumerate() {
        let off = i * 2;
        let chunk = hex.get(off..off + 2)?;
        *slot = u8::from_str_radix(chunk, 16).ok()?;
    }
    // Each 32-bit word is little-endian — swap within each 4-byte group.
    for group in 0..4 {
        let base = group * 4;
        bytes.swap(base, base + 3);
        bytes.swap(base + 1, base + 2);
    }
    // Render as 8 groups of 4 hex chars; let the consumer collapse if they care.
    let mut groups = [0u16; 8];
    for (i, slot) in groups.iter_mut().enumerate() {
        let off = i * 2;
        let hi = bytes.get(off).copied()?;
        let lo = bytes.get(off + 1).copied()?;
        *slot = (u16::from(hi) << 8) | u16::from(lo);
    }
    // Detect loopback ::1 specifically.
    if groups == [0, 0, 0, 0, 0, 0, 0, 1] {
        return Some("::1".to_owned());
    }
    if groups == [0u16; 8] {
        return Some("::".to_owned());
    }
    Some(
        groups
            .iter()
            .map(|g| format!("{g:x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    const SAMPLE_V4: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n   1: 0100007F:1F91 00000000:0000 06 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0\n";

    const SAMPLE_V6: &str = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22345 1 0000000000000000 100 0 0 10 0\n";

    #[test]
    fn parse_proc_net_tcp_extracts_listening_socket() {
        let parsed = parse_proc_net_tcp(SAMPLE_V4);
        assert_eq!(parsed.len(), 1);
        let s = &parsed[0];
        assert_eq!(s.family, "v4");
        assert_eq!(s.local_address, "127.0.0.1");
        assert_eq!(s.port, 8080);
        assert_eq!(s.inode, 12345);
    }

    #[test]
    fn parse_proc_net_tcp6_extracts_listening_socket() {
        let parsed = parse_proc_net_tcp6(SAMPLE_V6);
        assert_eq!(parsed.len(), 1);
        let s = &parsed[0];
        assert_eq!(s.family, "v6");
        assert_eq!(s.local_address, "::1");
        assert_eq!(s.port, 8080);
        assert_eq!(s.inode, 22345);
    }
}
