//! Syslog / CEF UDP forwarder.
//!
//! Emits `ArcSight` CEF (Common Event Format) records over UDP. The line
//! format we produce is:
//!
//! ```text
//! CEF:0|SentinelX|monolith|1.0|{action}|{title}|{severity}|act={actor} src={source}
//! ```
//!
//! Where `severity` is the CEF 0-10 score derived from
//! [`crate::siem::Severity::cef_score`].
//!
//! CEF requires that pipes (`|`) and backslashes (`\`) in header fields,
//! and equals (`=`) in extensions, are escaped. We escape conservatively
//! so downstream parsers never split a record at the wrong boundary.

use std::fmt;

use tokio::net::UdpSocket;
use tracing::debug;

use crate::error::IntegrationError;
use crate::siem::AuditEvent;

/// UDP socket-based CEF forwarder.
///
/// The socket is bound and connected at construction time. The
/// `host_facility` field is reserved for future RFC-5424 framing — at
/// the moment we emit bare CEF, which is what every common SIEM
/// (`ArcSight`, `QRadar`, Sentinel) accepts on a syslog UDP listener.
pub struct SyslogCefForwarder {
    socket: UdpSocket,
    host_facility: String,
}

impl fmt::Debug for SyslogCefForwarder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyslogCefForwarder")
            .field("host_facility", &self.host_facility)
            .field(
                "local_addr",
                &self.socket.local_addr().ok().map(|a| a.to_string()),
            )
            .finish()
    }
}

impl SyslogCefForwarder {
    /// Construct a forwarder from an *already-bound* UDP socket.
    ///
    /// The socket should typically be `connect()`-ed to the SIEM
    /// receiver so subsequent `send` calls don't need an address.
    #[must_use]
    pub const fn new(socket: UdpSocket, host_facility: String) -> Self {
        Self {
            socket,
            host_facility,
        }
    }

    /// Send a single event as a CEF record over UDP.
    ///
    /// If the underlying socket was not `connect()`-ed to a peer the
    /// `send` syscall returns an `io::Error` which we surface as
    /// [`IntegrationError::Transport`].
    pub async fn send(&self, event: &AuditEvent) -> Result<(), IntegrationError> {
        let line = format_cef(event);
        debug!(
            target: "sx_integrations::siem::syslog_cef",
            len = line.len(),
            host_facility = %self.host_facility,
            "sending cef record"
        );
        self.socket.send(line.as_bytes()).await?;
        Ok(())
    }
}

/// Render an [`AuditEvent`] as a single-line CEF record.
#[must_use]
pub fn format_cef(event: &AuditEvent) -> String {
    let action = escape_header(&event.action);
    let title = escape_header(&event.title);
    let severity = event.severity.cef_score();
    let actor = event.actor.as_deref().map_or("-", |s| s);
    let source = event.source.as_deref().map_or("-", |s| s);
    let actor = escape_extension(actor);
    let source = escape_extension(source);
    format!("CEF:0|SentinelX|monolith|1.0|{action}|{title}|{severity}|act={actor} src={source}")
}

/// Escape pipes and backslashes in a CEF header field.
fn escape_header(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '|' => out.push_str(r"\|"),
            other => out.push(other),
        }
    }
    out
}

/// Escape `=` and `\` in a CEF extension-value field.
fn escape_extension(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '=' => out.push_str(r"\="),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::siem::Severity;
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;

    fn event(sev: Severity) -> AuditEvent {
        AuditEvent {
            action: "policy.violation".to_owned(),
            title: "blocked outbound".to_owned(),
            severity: sev,
            actor: Some("svc-egress".to_owned()),
            source: Some("10.1.2.3".to_owned()),
            fields: serde_json::Map::new(),
        }
    }

    #[test]
    fn cef_header_format_is_correct() {
        let line = format_cef(&event(Severity::High));
        assert!(
            line.starts_with("CEF:0|SentinelX|monolith|1.0|policy.violation|blocked outbound|7|"),
            "unexpected header: {line}"
        );
        assert!(line.contains("act=svc-egress"));
        assert!(line.contains("src=10.1.2.3"));
    }

    #[test]
    fn severity_mapping_covers_all_five_levels() {
        let table = [
            (Severity::Info, 0u8),
            (Severity::Low, 3),
            (Severity::Medium, 5),
            (Severity::High, 7),
            (Severity::Critical, 10),
        ];
        for (sev, expected) in table {
            assert_eq!(sev.cef_score(), expected, "wrong score for {sev:?}");
            let line = format_cef(&event(sev));
            assert!(
                line.contains(&format!("|{expected}|")),
                "score {expected} missing in {line}"
            );
        }
    }

    #[test]
    fn header_field_pipes_and_backslashes_are_escaped() {
        let mut ev = event(Severity::Low);
        ev.action = r"weird|action\here".to_owned();
        let line = format_cef(&ev);
        assert!(
            line.contains(r"weird\|action\\here"),
            "escaping incorrect: {line}"
        );
    }

    #[tokio::test]
    async fn send_to_bound_peer_succeeds() {
        // Receiver
        let recv = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recv_addr: SocketAddr = recv.local_addr().unwrap();

        // Sender connected to the receiver
        let send_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        send_sock.connect(recv_addr).await.unwrap();
        let fwd = SyslogCefForwarder::new(send_sock, "host.example/local0".to_owned());

        fwd.send(&event(Severity::Critical)).await.unwrap();

        let mut buf = [0u8; 2048];
        let (n, _peer) = recv.recv_from(&mut buf).await.unwrap();
        let received = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(received.starts_with("CEF:0|SentinelX|monolith|1.0|"));
        assert!(received.contains("|10|"));
    }

    #[tokio::test]
    async fn send_without_connected_peer_returns_transport_error() {
        // Bound but not connected → `send` syscall fails with ENOTCONN /
        // EDESTADDRREQ depending on the OS, but always as an io::Error
        // we surface as Transport.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fwd = SyslogCefForwarder::new(sock, "h".to_owned());

        let err = fwd.send(&event(Severity::Low)).await.unwrap_err();
        assert!(
            matches!(err, IntegrationError::Transport(_)),
            "expected Transport, got {err:?}"
        );
    }

    #[test]
    fn debug_impl_does_not_panic() {
        // Construct a forwarder with a runtime in scope so we can bind.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let dbg = rt.block_on(async {
            let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let fwd = SyslogCefForwarder::new(sock, "facility-7".to_owned());
            format!("{fwd:?}")
        });
        assert!(dbg.contains("facility-7"));
    }
}
