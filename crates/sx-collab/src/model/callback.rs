//! Recorded out-of-band callback events.
//!
//! A [`Callback`] is the persisted artefact of a DNS / HTTP / SMTP
//! interaction that landed on the collaborator and matched (or, in the
//! `unknown` case, plausibly should have matched) a minted [`Token`].

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::model::token::Token;

/// Snapshot of a single out-of-band callback.
///
/// Variant fields capture only the minimum needed for verification: source
/// IP, the token it targeted, the message excerpt (already capped by the
/// receiver), and a high-resolution reception timestamp.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Callback {
    /// A DNS query was observed for `<token>.oob.<base_domain>`.
    Dns {
        /// Token decoded from the leftmost label.
        token: Token,
        /// Resource-record type of the query (e.g. `A`, `AAAA`).
        query_type: String,
        /// Source IP if the transport exposed one.
        source_ip: Option<IpAddr>,
        /// Server-side reception timestamp.
        received_at: OffsetDateTime,
    },
    /// An HTTP request was observed for `<token>.oob.<base_domain>/...`.
    Http {
        /// Token decoded from the host header's leftmost label.
        token: Token,
        /// HTTP method (uppercase).
        method: String,
        /// Request path including the query string.
        path: String,
        /// Sanitised request headers — sensitive entries are replaced with
        /// `<REDACTED>`.
        headers: BTreeMap<String, String>,
        /// First N bytes of the body where N == `http_body_capture_bytes`.
        body_excerpt: Vec<u8>,
        /// Source IP of the peer.
        source_ip: Option<IpAddr>,
        /// Server-side reception timestamp.
        received_at: OffsetDateTime,
    },
    /// An SMTP session was observed.
    Smtp {
        /// Token decoded from the `RCPT TO:` address (or EHLO fallback).
        token: Token,
        /// `MAIL FROM:` envelope sender.
        mail_from: String,
        /// All `RCPT TO:` envelope recipients.
        rcpt_to: Vec<String>,
        /// Captured DATA payload, capped at `smtp_max_message_bytes`.
        message_excerpt: Vec<u8>,
        /// Source IP of the peer.
        source_ip: Option<IpAddr>,
        /// Server-side reception timestamp.
        received_at: OffsetDateTime,
    },
}

impl Callback {
    /// Reference to the token bound to this callback.
    #[must_use]
    pub const fn token(&self) -> &Token {
        match self {
            Self::Dns { token, .. } | Self::Http { token, .. } | Self::Smtp { token, .. } => token,
        }
    }

    /// Reception timestamp.
    #[must_use]
    pub const fn received_at(&self) -> OffsetDateTime {
        match self {
            Self::Dns { received_at, .. }
            | Self::Http { received_at, .. }
            | Self::Smtp { received_at, .. } => *received_at,
        }
    }

    /// Short human-readable variant name suitable for log tags.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Dns { .. } => "dns",
            Self::Http { .. } => "http",
            Self::Smtp { .. } => "smtp",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{Callback, Token};
    use std::collections::BTreeMap;
    use time::OffsetDateTime;

    #[test]
    fn token_helper_returns_inner_token() {
        let tk = Token::new();
        let cb = Callback::Dns {
            token: tk.clone(),
            query_type: "A".into(),
            source_ip: None,
            received_at: OffsetDateTime::UNIX_EPOCH,
        };
        assert_eq!(cb.token(), &tk);
        assert_eq!(cb.kind(), "dns");
    }

    #[test]
    fn callback_round_trips_json() {
        let tk = Token::new();
        let cb = Callback::Http {
            token: tk,
            method: "GET".into(),
            path: "/probe".into(),
            headers: BTreeMap::new(),
            body_excerpt: b"hi".to_vec(),
            source_ip: None,
            received_at: OffsetDateTime::UNIX_EPOCH,
        };
        let json = serde_json::to_string(&cb).unwrap();
        let back: Callback = serde_json::from_str(&json).unwrap();
        assert_eq!(cb, back);
    }
}
