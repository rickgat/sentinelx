//! Inbound Slack slash commands.
//!
//! Slack POSTs `application/x-www-form-urlencoded` bodies to our
//! `/integrations/slack/commands` endpoint. Every request carries two
//! headers we MUST verify before doing anything with the body:
//!
//! * `X-Slack-Request-Timestamp` — RFC 3339-ish epoch seconds.
//! * `X-Slack-Signature` — `v0={hex(HMAC-SHA256(secret, "v0:" + ts + ":" + body))}`.
//!
//! Verification rules (per Slack RFC):
//!
//! 1. Reject if the timestamp is more than `SIGNATURE_REPLAY_WINDOW`
//!    seconds out of sync with our wall clock. Default: 5 minutes — same
//!    value Slack uses in their official guidance.
//! 2. Build the base string `"v0:" + ts + ":" + body` and HMAC-SHA256 it
//!    with the workspace signing secret.
//! 3. Compare against the supplied signature using
//!    [`subtle::ConstantTimeEq`] — never `==`. Timing-safe compare is
//!    mandatory for HMAC signatures.
//!
//! ## MVP slash commands
//!
//! * `/sentinelx ack <finding_id>` — acknowledge a finding.
//! * `/sentinelx assign <finding_id> @user` — assign to a user.
//! * `/sentinelx mute <finding_id> 24h` — silence the finding for a
//!   given duration.
//!
//! The parser surfaces a structured [`SlackCommand`] enum the caller can
//! route into the finding triage pipeline. The verifier never logs the
//! signing secret, the signature, or the request body.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tracing::warn;

/// Maximum allowed clock skew between Slack's timestamp and ours.
///
/// Slack documents 5 minutes as the upper bound for replay-resistance.
pub const SIGNATURE_REPLAY_WINDOW_SECS: i64 = 300;

/// Slack signature version prefix. Hard-coded as `v0` per the RFC; the
/// crate will need a new constant when Slack rolls a `v1` scheme.
const SIGNATURE_VERSION: &str = "v0";

/// Errors surfaced while verifying an inbound Slack signature.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum InboundError {
    /// The `X-Slack-Request-Timestamp` header was missing or could not
    /// be parsed as an integer epoch-seconds value.
    #[error("missing or malformed X-Slack-Request-Timestamp header")]
    BadTimestamp,

    /// The supplied timestamp was more than [`SIGNATURE_REPLAY_WINDOW_SECS`]
    /// out of sync with our wall clock.
    #[error("timestamp outside replay window")]
    StaleTimestamp,

    /// The `X-Slack-Signature` header was missing or did not start with
    /// the supported version prefix.
    #[error("missing or malformed X-Slack-Signature header")]
    BadSignature,

    /// The HMAC comparison failed.
    #[error("signature mismatch")]
    SignatureMismatch,

    /// The body parsed as form-encoded data but the slash-command shape
    /// is wrong (missing `command` field, unknown verb, ...).
    #[error("malformed slash command: {0}")]
    MalformedCommand(String),
}

/// Verified Slack slash command.
///
/// Construct via [`parse_slash_command`] after the request body and
/// headers have been signature-verified with
/// [`verify_slack_signature`]. The shape captures both the verb (one of
/// ack / assign / mute) and the user identity Slack hands us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlackCommand {
    /// `/sentinelx ack <finding_id>`.
    Ack {
        /// Finding identifier the user wants to acknowledge.
        finding_id: String,
        /// Slack user id of the requester.
        user_id: String,
    },
    /// `/sentinelx assign <finding_id> @user`.
    Assign {
        /// Finding identifier to assign.
        finding_id: String,
        /// Assignee handle (`@user` style).
        assignee: String,
        /// Slack user id of the requester.
        user_id: String,
    },
    /// `/sentinelx mute <finding_id> 24h`.
    Mute {
        /// Finding identifier to mute.
        finding_id: String,
        /// Mute duration as a parsed wall-clock number of seconds.
        /// We accept the same shorthand Slack power-users expect:
        /// `1h`, `24h`, `7d`. See [`parse_duration`] for the grammar.
        duration_secs: u64,
        /// Slack user id of the requester.
        user_id: String,
    },
}

impl SlackCommand {
    /// Stable verb string used in audit events and metrics.
    #[must_use]
    pub const fn verb(&self) -> &'static str {
        match self {
            Self::Ack { .. } => "ack",
            Self::Assign { .. } => "assign",
            Self::Mute { .. } => "mute",
        }
    }

    /// Finding id this command operates on.
    #[must_use]
    pub fn finding_id(&self) -> &str {
        match self {
            Self::Ack { finding_id, .. }
            | Self::Assign { finding_id, .. }
            | Self::Mute { finding_id, .. } => finding_id,
        }
    }

    /// Slack user id of the requester.
    #[must_use]
    pub fn user_id(&self) -> &str {
        match self {
            Self::Ack { user_id, .. }
            | Self::Assign { user_id, .. }
            | Self::Mute { user_id, .. } => user_id,
        }
    }
}

/// Verify a Slack slash-command request signature.
///
/// `now_unix` is the verifier's wall clock as epoch seconds — injected so
/// tests can pin a deterministic value. `signing_secret` MUST be the
/// per-tenant Slack signing secret materialised via
/// [`super::config::load_signing_secret`].
///
/// On success the function returns `Ok(())`; on any failure the request
/// MUST be rejected and an audit `rejected` row emitted. The function
/// never logs the secret, the signature, or the body.
pub fn verify_slack_signature(
    signing_secret: &SecretString,
    timestamp_header: Option<&str>,
    signature_header: Option<&str>,
    body: &[u8],
    now_unix: i64,
) -> Result<(), InboundError> {
    // 1. Parse timestamp and gate on the replay window.
    let ts_raw = parse_timestamp_header(timestamp_header, now_unix)?;
    // 2. Parse signature header and decode the hex MAC.
    let provided = parse_signature_header(signature_header)?;
    // 3. Compute expected MAC over `"v0:<ts>:" || body`.
    let base = format!("{SIGNATURE_VERSION}:{ts_raw}:");
    let expected = compute_hmac_sha256(signing_secret.expose_secret().as_bytes(), &base, body);
    // 4. Constant-time compare.
    constant_time_eq_hmac(&provided, &expected)
}

/// Decode the `X-Slack-Request-Timestamp` header and confirm it is
/// within the replay window.
fn parse_timestamp_header(
    timestamp_header: Option<&str>,
    now_unix: i64,
) -> Result<String, InboundError> {
    let Some(ts_raw) = timestamp_header else {
        warn!(
            target: "sx_integrations::chat::inbound",
            "slack request rejected: missing timestamp header"
        );
        return Err(InboundError::BadTimestamp);
    };
    let ts: i64 = ts_raw.trim().parse().map_err(|_| {
        warn!(
            target: "sx_integrations::chat::inbound",
            "slack request rejected: malformed timestamp header"
        );
        InboundError::BadTimestamp
    })?;
    let skew = now_unix.saturating_sub(ts).abs();
    if skew > SIGNATURE_REPLAY_WINDOW_SECS {
        warn!(
            target: "sx_integrations::chat::inbound",
            skew_secs = skew,
            "slack request rejected: stale timestamp"
        );
        return Err(InboundError::StaleTimestamp);
    }
    Ok(ts_raw.to_owned())
}

/// Decode the `X-Slack-Signature` header. Expected shape: `v0=<hex>`.
fn parse_signature_header(signature_header: Option<&str>) -> Result<Vec<u8>, InboundError> {
    let Some(sig_raw) = signature_header else {
        warn!(
            target: "sx_integrations::chat::inbound",
            "slack request rejected: missing signature header"
        );
        return Err(InboundError::BadSignature);
    };
    let sig_hex = sig_raw
        .strip_prefix(&format!("{SIGNATURE_VERSION}="))
        .ok_or(InboundError::BadSignature)?;
    hex::decode(sig_hex).map_err(|_| {
        warn!(
            target: "sx_integrations::chat::inbound",
            "slack request rejected: signature is not valid hex"
        );
        InboundError::BadSignature
    })
}

/// Constant-time HMAC comparison. Length mismatch is also reported in
/// constant time relative to the rest of the request handling — we
/// short-circuit before the `ct_eq` call to avoid panicking on a
/// length-mismatched slice, then surface the same `SignatureMismatch`
/// error variant. The branch above does not vary with secret bytes.
fn constant_time_eq_hmac(provided: &[u8], expected: &[u8]) -> Result<(), InboundError> {
    if provided.len() != expected.len() {
        warn!(
            target: "sx_integrations::chat::inbound",
            "slack request rejected: signature length mismatch"
        );
        return Err(InboundError::SignatureMismatch);
    }
    if provided.ct_eq(expected).unwrap_u8() != 1 {
        warn!(
            target: "sx_integrations::chat::inbound",
            "slack request rejected: signature mismatch"
        );
        return Err(InboundError::SignatureMismatch);
    }
    Ok(())
}

/// Compute `HMAC-SHA256(secret, base || body)` and return the raw bytes.
///
/// Public-in-crate so [`compute_slack_signature_hex`] can re-use it. The
/// HMAC crate's `Mac::new_from_slice` only fails on key length errors
/// that the underlying SHA-256 block size never enforces — we still
/// handle the `Result` cleanly and return an empty vec on the (unreachable)
/// failure path so the caller's constant-time compare cleanly rejects.
fn compute_hmac_sha256(secret: &[u8], base: &str, body: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;
    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        // SHA-256 accepts arbitrary key length so this branch is dead in
        // practice. Returning an empty vec causes the caller's
        // length-check to fail closed — which is the safe default.
        return Vec::new();
    };
    mac.update(base.as_bytes());
    mac.update(body);
    mac.finalize().into_bytes().to_vec()
}

/// Produce the Slack-style `v0=<hex>` signature for a given body and
/// timestamp. Test-helper for the signing-secret tamper test.
#[must_use]
pub fn compute_slack_signature_hex(secret: &[u8], timestamp: &str, body: &[u8]) -> String {
    let base = format!("{SIGNATURE_VERSION}:{timestamp}:");
    let mac = compute_hmac_sha256(secret, &base, body);
    format!("{SIGNATURE_VERSION}={}", hex::encode(mac))
}

/// Parse a Slack `application/x-www-form-urlencoded` slash-command body
/// into a [`SlackCommand`].
///
/// Slack documents the relevant fields as:
///
/// * `command` — `/sentinelx`
/// * `text` — the bit after the slash command (e.g. `ack f-42`)
/// * `user_id` — Slack id of the invoker (e.g. `U123ABC`)
///
/// The function only accepts `command == "/sentinelx"`; any other verb
/// returns [`InboundError::MalformedCommand`].
pub fn parse_slash_command(body: &str) -> Result<SlackCommand, InboundError> {
    let mut command: Option<String> = None;
    let mut text: Option<String> = None;
    let mut user_id: Option<String> = None;

    for pair in body.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k_raw, v_raw) = pair.split_once('=').unwrap_or((pair, ""));
        let k = url_decode_form(k_raw);
        let v = url_decode_form(v_raw);
        match k.as_str() {
            "command" => command = Some(v),
            "text" => text = Some(v),
            "user_id" => user_id = Some(v),
            _ => {}
        }
    }

    let cmd = command.ok_or_else(|| InboundError::MalformedCommand("missing `command`".into()))?;
    if cmd != "/sentinelx" {
        return Err(InboundError::MalformedCommand(format!(
            "unknown command `{cmd}`"
        )));
    }
    let text = text.ok_or_else(|| InboundError::MalformedCommand("missing `text`".into()))?;
    let user_id =
        user_id.ok_or_else(|| InboundError::MalformedCommand("missing `user_id`".into()))?;

    let mut parts = text.split_whitespace();
    let verb = parts
        .next()
        .ok_or_else(|| InboundError::MalformedCommand("empty text".into()))?;

    match verb {
        "ack" => {
            let finding_id = parts
                .next()
                .ok_or_else(|| InboundError::MalformedCommand("ack missing finding_id".into()))?;
            if parts.next().is_some() {
                return Err(InboundError::MalformedCommand(
                    "ack takes one argument".into(),
                ));
            }
            Ok(SlackCommand::Ack {
                finding_id: finding_id.to_owned(),
                user_id,
            })
        }
        "assign" => {
            let finding_id = parts.next().ok_or_else(|| {
                InboundError::MalformedCommand("assign missing finding_id".into())
            })?;
            let assignee = parts
                .next()
                .ok_or_else(|| InboundError::MalformedCommand("assign missing assignee".into()))?;
            if parts.next().is_some() {
                return Err(InboundError::MalformedCommand(
                    "assign takes two arguments".into(),
                ));
            }
            Ok(SlackCommand::Assign {
                finding_id: finding_id.to_owned(),
                assignee: assignee.to_owned(),
                user_id,
            })
        }
        "mute" => {
            let finding_id = parts
                .next()
                .ok_or_else(|| InboundError::MalformedCommand("mute missing finding_id".into()))?;
            let duration = parts
                .next()
                .ok_or_else(|| InboundError::MalformedCommand("mute missing duration".into()))?;
            if parts.next().is_some() {
                return Err(InboundError::MalformedCommand(
                    "mute takes two arguments".into(),
                ));
            }
            let duration_secs = parse_duration(duration)?;
            Ok(SlackCommand::Mute {
                finding_id: finding_id.to_owned(),
                duration_secs,
                user_id,
            })
        }
        other => Err(InboundError::MalformedCommand(format!(
            "unknown verb `{other}`"
        ))),
    }
}

/// Parse a duration shorthand: `Ns` (seconds), `Nm` (minutes), `Nh`
/// (hours), `Nd` (days). Rejects unsuffixed numbers — the contract is
/// "unit is always explicit" so the user cannot accidentally mute a
/// finding for thousands of seconds when they meant hours.
fn parse_duration(s: &str) -> Result<u64, InboundError> {
    if s.len() < 2 {
        return Err(InboundError::MalformedCommand(format!(
            "duration `{s}` too short"
        )));
    }
    let (digits, unit) = s.split_at(s.len() - 1);
    let n: u64 = digits.parse().map_err(|_| {
        InboundError::MalformedCommand(format!("duration `{s}` has non-numeric prefix"))
    })?;
    let secs = match unit {
        "s" => n,
        "m" => n
            .checked_mul(60)
            .ok_or_else(|| InboundError::MalformedCommand("duration overflow".into()))?,
        "h" => n
            .checked_mul(3600)
            .ok_or_else(|| InboundError::MalformedCommand("duration overflow".into()))?,
        "d" => n
            .checked_mul(86_400)
            .ok_or_else(|| InboundError::MalformedCommand("duration overflow".into()))?,
        other => {
            return Err(InboundError::MalformedCommand(format!(
                "duration unit `{other}` not in {{s,m,h,d}}"
            )))
        }
    };
    Ok(secs)
}

/// Minimal form-encoded percent-decoder. Slack uses
/// `application/x-www-form-urlencoded` for slash-command bodies. We avoid
/// pulling in a heavyweight crate for this single use site.
fn url_decode_form(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let Some(&b) = bytes.get(i) else { break };
        match b {
            b'+' => {
                out.push(' ');
                i += 1;
            }
            b'%' => {
                if let Some(hex_chunk) = bytes.get(i + 1..i + 3) {
                    if let Ok(s) = std::str::from_utf8(hex_chunk) {
                        if let Ok(decoded) = u8::from_str_radix(s, 16) {
                            out.push(decoded as char);
                            i += 3;
                            continue;
                        }
                    }
                }
                out.push(b as char);
                i += 1;
            }
            _ => {
                out.push(b as char);
                i += 1;
            }
        }
    }
    out
}

/// Format the verb verb of a `SlackCommand` for `Display`. Useful for
/// tracing.
impl fmt::Display for SlackCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SlackCommand{{verb={verb}, finding={fid}, user={uid}}}",
            verb = self.verb(),
            fid = self.finding_id(),
            uid = self.user_id(),
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const SECRET: &str = "8f742231b10e8888abcd99yyyzzz85ed";
    const TS: &str = "1700000000";
    const BODY: &str = "command=%2Fsentinelx&text=ack+f-42&user_id=U0CONST";

    fn signed_request() -> (String, String, String) {
        let sig = compute_slack_signature_hex(SECRET.as_bytes(), TS, BODY.as_bytes());
        (TS.to_owned(), sig, BODY.to_owned())
    }

    fn now() -> i64 {
        TS.parse::<i64>().unwrap()
    }

    #[test]
    fn happy_path_signature_verifies() {
        let (ts, sig, body) = signed_request();
        let secret = SecretString::from(SECRET.to_owned());
        verify_slack_signature(&secret, Some(&ts), Some(&sig), body.as_bytes(), now()).unwrap();
    }

    #[test]
    fn tampered_body_fails_signature_check() {
        let (ts, sig, _) = signed_request();
        let tampered = "command=%2Fsentinelx&text=mute+f-99+9999d&user_id=U0EVIL";
        let secret = SecretString::from(SECRET.to_owned());
        let err =
            verify_slack_signature(&secret, Some(&ts), Some(&sig), tampered.as_bytes(), now())
                .unwrap_err();
        assert_eq!(err, InboundError::SignatureMismatch);
    }

    #[test]
    fn wrong_signing_secret_fails_check() {
        let (ts, sig, body) = signed_request();
        // Same body+ts, different secret: the recomputed MAC differs.
        let other = SecretString::from("attacker-guessed-secret".to_owned());
        let err = verify_slack_signature(&other, Some(&ts), Some(&sig), body.as_bytes(), now())
            .unwrap_err();
        assert_eq!(err, InboundError::SignatureMismatch);
    }

    #[test]
    fn stale_timestamp_rejected() {
        let (ts, sig, body) = signed_request();
        let secret = SecretString::from(SECRET.to_owned());
        // Pretend our wall clock is one hour ahead.
        let future = now() + 3600;
        let err = verify_slack_signature(&secret, Some(&ts), Some(&sig), body.as_bytes(), future)
            .unwrap_err();
        assert_eq!(err, InboundError::StaleTimestamp);

        // Or one hour behind.
        let past = now() - 3600;
        let err = verify_slack_signature(&secret, Some(&ts), Some(&sig), body.as_bytes(), past)
            .unwrap_err();
        assert_eq!(err, InboundError::StaleTimestamp);
    }

    #[test]
    fn missing_or_malformed_headers_rejected() {
        let (ts, sig, body) = signed_request();
        let secret = SecretString::from(SECRET.to_owned());

        let err =
            verify_slack_signature(&secret, None, Some(&sig), body.as_bytes(), now()).unwrap_err();
        assert_eq!(err, InboundError::BadTimestamp);

        let err = verify_slack_signature(
            &secret,
            Some("not-a-number"),
            Some(&sig),
            body.as_bytes(),
            now(),
        )
        .unwrap_err();
        assert_eq!(err, InboundError::BadTimestamp);

        let err =
            verify_slack_signature(&secret, Some(&ts), None, body.as_bytes(), now()).unwrap_err();
        assert_eq!(err, InboundError::BadSignature);

        let err = verify_slack_signature(
            &secret,
            Some(&ts),
            Some("v1=deadbeef"),
            body.as_bytes(),
            now(),
        )
        .unwrap_err();
        assert_eq!(err, InboundError::BadSignature);

        let err =
            verify_slack_signature(&secret, Some(&ts), Some("v0=zzzz"), body.as_bytes(), now())
                .unwrap_err();
        assert_eq!(err, InboundError::BadSignature);
    }

    #[test]
    fn parse_ack_command() {
        let body = "command=%2Fsentinelx&text=ack+f-42&user_id=U0ABC";
        let cmd = parse_slash_command(body).unwrap();
        assert_eq!(
            cmd,
            SlackCommand::Ack {
                finding_id: "f-42".into(),
                user_id: "U0ABC".into(),
            }
        );
        assert_eq!(cmd.verb(), "ack");
        assert_eq!(cmd.finding_id(), "f-42");
        assert_eq!(cmd.user_id(), "U0ABC");
    }

    #[test]
    fn parse_assign_command() {
        let body = "command=%2Fsentinelx&text=assign+f-42+%40rick&user_id=U0ABC";
        let cmd = parse_slash_command(body).unwrap();
        assert_eq!(
            cmd,
            SlackCommand::Assign {
                finding_id: "f-42".into(),
                assignee: "@rick".into(),
                user_id: "U0ABC".into(),
            }
        );
    }

    #[test]
    fn parse_mute_command_with_24h() {
        let body = "command=%2Fsentinelx&text=mute+f-42+24h&user_id=U0ABC";
        let cmd = parse_slash_command(body).unwrap();
        assert_eq!(
            cmd,
            SlackCommand::Mute {
                finding_id: "f-42".into(),
                duration_secs: 24 * 3600,
                user_id: "U0ABC".into(),
            }
        );
    }

    #[test]
    fn parse_mute_command_units() {
        for (input, expected) in [
            ("mute f-1 30s", 30),
            ("mute f-1 5m", 300),
            ("mute f-1 2h", 7200),
            ("mute f-1 7d", 7 * 86400),
        ] {
            let body = format!(
                "command=%2Fsentinelx&text={}&user_id=U0ABC",
                input.replace(' ', "+")
            );
            let cmd = parse_slash_command(&body).unwrap();
            if let SlackCommand::Mute { duration_secs, .. } = cmd {
                assert_eq!(duration_secs, expected, "input={input}");
            } else {
                panic!("expected Mute for {input}");
            }
        }
    }

    #[test]
    fn parse_rejects_unknown_command_root() {
        let body = "command=%2Felsewhere&text=ack+f-1&user_id=U0ABC";
        let err = parse_slash_command(body).unwrap_err();
        assert!(matches!(err, InboundError::MalformedCommand(_)));
    }

    #[test]
    fn parse_rejects_unknown_verb() {
        let body = "command=%2Fsentinelx&text=delete+f-1&user_id=U0ABC";
        let err = parse_slash_command(body).unwrap_err();
        assert!(matches!(err, InboundError::MalformedCommand(_)));
    }

    #[test]
    fn parse_rejects_missing_argument() {
        let body = "command=%2Fsentinelx&text=ack&user_id=U0ABC";
        let err = parse_slash_command(body).unwrap_err();
        assert!(matches!(err, InboundError::MalformedCommand(_)));
    }

    #[test]
    fn parse_rejects_extra_argument() {
        let body = "command=%2Fsentinelx&text=ack+f-1+extra&user_id=U0ABC";
        let err = parse_slash_command(body).unwrap_err();
        assert!(matches!(err, InboundError::MalformedCommand(_)));
    }

    #[test]
    fn parse_rejects_unsuffixed_duration() {
        let body = "command=%2Fsentinelx&text=mute+f-1+24&user_id=U0ABC";
        let err = parse_slash_command(body).unwrap_err();
        assert!(matches!(err, InboundError::MalformedCommand(_)));
    }

    #[test]
    fn display_is_redaction_free() {
        let cmd = SlackCommand::Ack {
            finding_id: "f-42".into(),
            user_id: "U0ABC".into(),
        };
        let s = cmd.to_string();
        assert!(s.contains("verb=ack"));
        assert!(s.contains("finding=f-42"));
        assert!(s.contains("user=U0ABC"));
    }

    #[test]
    fn signature_at_exact_boundary_accepted() {
        let (ts, sig, body) = signed_request();
        let secret = SecretString::from(SECRET.to_owned());
        // Exactly at the boundary is accepted.
        let edge = now() + SIGNATURE_REPLAY_WINDOW_SECS;
        verify_slack_signature(&secret, Some(&ts), Some(&sig), body.as_bytes(), edge).unwrap();
    }
}
