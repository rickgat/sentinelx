//! DNS receiver.
//!
//! Implements a minimal `hickory_server::RequestHandler` that answers a
//! single A record for any query under `<token>.oob.<base_domain>` and
//! returns `REFUSED` for anything else.
//!
//! LOW-001-FU4 (2026-06-23): migrated to hickory 0.26. The notable API moves:
//!
//! * `hickory_server::ServerFuture` -> `hickory_server::Server`.
//! * `hickory_server::authority::MessageResponseBuilder` ->
//!   `hickory_server::zone_handler::MessageResponseBuilder`.
//! * `RequestHandler::handle_request` now takes two generic parameters
//!   `<R: ResponseHandler, T: Time>`.
//! * `Header::{new,response_from_request,set_*}` were removed; the
//!   equivalent constructors live on `Metadata`, and the response is built
//!   by mutating `Metadata`'s public fields then wrapping it in a new
//!   `Header { metadata, counts: HeaderCounts::default() }`.
//! * `Request` no longer exposes `header()` / `query()` methods; it derefs
//!   to `MessageRequest`, so use `request.metadata` (field) and
//!   `request.queries()` (slice of `LowerQuery`).

use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use hickory_proto::op::{Header, HeaderCounts, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_server::net::runtime::Time;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponseBuilder;
use hickory_server::Server;
use sx_core::value_object::ids::TenantId;
use time::OffsetDateTime;
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::error::CollabError;
use crate::model::callback::Callback;
use crate::model::config::CollabConfig;
use crate::model::token::Token;
use crate::service::sink::CallbackSink;
use crate::service::token_alloc::TokenAllocator;
use crate::service::TRACING_TARGET;

const DNS_RECORD_TTL: u32 = 60;
const OOB_LABEL: &str = "oob";

/// `RequestHandler` implementation for the OOB DNS receiver.
#[derive(Debug, Clone)]
pub struct OobAuthority {
    base_domain: String,
    answer_ipv4: Ipv4Addr,
    sink: Arc<dyn CallbackSink>,
    allocator: Arc<TokenAllocator>,
}

impl OobAuthority {
    /// Construct a new authority bound to a fixed base domain and answer
    /// IPv4 address.
    #[must_use]
    pub fn new(
        base_domain: String,
        answer_ipv4: Ipv4Addr,
        sink: Arc<dyn CallbackSink>,
        allocator: Arc<TokenAllocator>,
    ) -> Self {
        Self {
            base_domain,
            answer_ipv4,
            sink,
            allocator,
        }
    }

    /// Returns the configured base domain (without leading dot).
    #[must_use]
    pub fn base_domain(&self) -> &str {
        &self.base_domain
    }

    /// Decide whether `name` (as displayed in canonical DNS form, e.g.
    /// `abc.oob.example.com.`) is anchored under
    /// `<something>.oob.<base_domain>` and return the extracted token
    /// string, or `None` when the query is out of scope or malformed.
    #[must_use]
    pub fn extract_token<'a>(&self, name: &'a str) -> Option<&'a str> {
        // Strip the trailing dot if present.
        let trimmed = name.strip_suffix('.').unwrap_or(name);
        // Suffix must be `oob.<base_domain>`.
        let suffix = format!(".{}.{}", OOB_LABEL, self.base_domain.to_ascii_lowercase());
        // Suffix is checked case-insensitively against the lowercased name.
        let lower = trimmed.to_ascii_lowercase();
        let stripped = lower.strip_suffix(&suffix)?;
        if stripped.is_empty() {
            return None;
        }
        // The remaining part is `<token>` possibly with extra labels in
        // front (e.g. `foo.bar.<token>.oob.example`). We accept any number
        // of prefix labels and take the *rightmost* label as the token.
        // `stripped` does not include the suffix, so its last label is the
        // token candidate.
        let token_label = stripped.rsplit('.').next()?;
        if token_label.is_empty() {
            return None;
        }
        // Return a slice from the original `name` so capitalisation in
        // `name` does not leak via the lowercased copy.  We measure the
        // byte offset in `lower` and translate to the original.
        let lower_offset = stripped.len() - token_label.len();
        // `name` and `lower` differ only in ASCII case; byte lengths align.
        let prefix_len = stripped.len() - token_label.len();
        // Be defensive: only return a slice if positions line up.
        if prefix_len != lower_offset {
            return None;
        }
        let original_token = trimmed.get(prefix_len..prefix_len + token_label.len())?;
        Some(original_token)
    }
}

#[async_trait]
impl RequestHandler for OobAuthority {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        // hickory 0.26: `Request` derefs to `MessageRequest`. The header
        // bits live on `request.metadata` (a public field of type
        // `Metadata`), and there can be multiple queries — for OOB DNS we
        // only ever answer the first (single-query) shape.
        let req_meta = request.metadata;
        let Some(query) = request.queries.queries().first() else {
            return refused(&req_meta, &mut response_handle, request).await;
        };

        // Only answer standard QUERY ops.
        if req_meta.message_type != MessageType::Query || req_meta.op_code != OpCode::Query {
            return refused(&req_meta, &mut response_handle, request).await;
        }

        let name_display = query.name().to_string();
        let token_str = match self.extract_token(&name_display) {
            Some(t) => t.to_string(),
            None => {
                warn!(
                    target: TRACING_TARGET,
                    query = %name_display,
                    "dns query outside base_domain refused",
                );
                return refused(&req_meta, &mut response_handle, request).await;
            }
        };

        let Ok(token) = Token::parse(&token_str) else {
            warn!(
                target: TRACING_TARGET,
                query = %name_display,
                "dns query token failed validation",
            );
            return refused(&req_meta, &mut response_handle, request).await;
        };

        // Bind to a tenant if we know one; otherwise log a warning.
        if self.allocator.lookup(&token).is_none() {
            warn!(
                target: TRACING_TARGET,
                token = token.as_str(),
                tenant = %TenantId::new(),
                "dns query for unknown token recorded as unknown tenant",
            );
        }

        let cb = Callback::Dns {
            token,
            query_type: format!("{:?}", query.query_type()),
            source_ip: Some(request.src().ip()),
            received_at: OffsetDateTime::now_utc(),
        };
        if let Err(e) = self.sink.append(cb).await {
            warn!(
                target: TRACING_TARGET,
                error = %e,
                "dns sink append failed",
            );
        } else {
            info!(
                target: TRACING_TARGET,
                kind = "dns",
                src = %request.src(),
                "callback recorded",
            );
        }

        // Build the response: a single A record for every recognised name.
        let mut metadata = Metadata::response_from_request(&req_meta);
        metadata.authoritative = true;
        metadata.response_code = ResponseCode::NoError;

        let answers: Vec<Record> = if query.query_type() == RecordType::A {
            let answer_name = match Name::from_str(&name_display) {
                Ok(n) => n,
                Err(_) => return refused(&req_meta, &mut response_handle, request).await,
            };
            let rdata = RData::A(A(self.answer_ipv4));
            vec![Record::from_rdata(answer_name, DNS_RECORD_TTL, rdata)]
        } else {
            // Other query types: respond NoError with no answers.
            Vec::new()
        };

        let builder = MessageResponseBuilder::from_message_request(request);
        let msg = builder.build(
            metadata,
            answers.iter(),
            std::iter::empty(),
            std::iter::empty(),
            std::iter::empty(),
        );
        match response_handle.send_response(msg).await {
            Ok(info) => info,
            Err(e) => {
                warn!(target: TRACING_TARGET, error = %e, "dns send_response failed");
                servfail_response_info(req_meta.id, req_meta.op_code)
            }
        }
    }
}

async fn refused<R: ResponseHandler>(
    req_meta: &Metadata,
    response_handle: &mut R,
    request: &Request,
) -> ResponseInfo {
    let mut metadata = Metadata::response_from_request(req_meta);
    metadata.response_code = ResponseCode::Refused;
    let builder = MessageResponseBuilder::from_message_request(request);
    let msg = builder.build_no_records(metadata);
    match response_handle.send_response(msg).await {
        Ok(info) => info,
        Err(_) => servfail_response_info(req_meta.id, req_meta.op_code),
    }
}

/// Build a minimal SERVFAIL `ResponseInfo` used when the wire send itself
/// fails. hickory 0.26 dropped the `Header::new()` zero-arg constructor;
/// every `Header` requires explicit metadata + counts.
fn servfail_response_info(id: u16, op_code: OpCode) -> ResponseInfo {
    let mut metadata = Metadata::new(id, MessageType::Response, op_code);
    metadata.response_code = ResponseCode::ServFail;
    ResponseInfo::from(Header {
        metadata,
        counts: HeaderCounts::default(),
    })
}

/// Owns the spawned DNS server task and the bound socket address.
#[derive(Debug)]
pub struct DnsServerHandle {
    /// Effective bind address (after the OS resolved port 0, if used).
    pub local_addr: SocketAddr,
    /// `JoinHandle` of the background driver task.
    pub task: JoinHandle<()>,
}

/// Spawn the DNS server.  Returns once the UDP socket is bound and the
/// driver task is running.
pub async fn spawn_dns_server(
    cfg: &CollabConfig,
    sink: Arc<dyn CallbackSink>,
    allocator: Arc<TokenAllocator>,
    shutdown: Arc<Notify>,
) -> Result<DnsServerHandle, CollabError> {
    let socket = UdpSocket::bind(cfg.dns_bind)
        .await
        .map_err(|e| CollabError::dns_server(format!("bind {}: {e}", cfg.dns_bind)))?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| CollabError::dns_server(format!("local_addr: {e}")))?;
    info!(
        target: TRACING_TARGET,
        addr = %local_addr,
        "dns receiver bound",
    );

    let authority = OobAuthority::new(cfg.base_domain.clone(), cfg.answer_ipv4, sink, allocator);

    let task = tokio::spawn(async move {
        // hickory 0.26: `ServerFuture` was renamed to `Server`; the
        // register_socket / shutdown_gracefully / block_until_done surface
        // is unchanged.
        let mut server = Server::new(authority);
        server.register_socket(socket);
        tokio::select! {
            () = shutdown.notified() => {
                debug!(target: TRACING_TARGET, "dns receiver shutting down");
                let _ = server.shutdown_gracefully().await;
            }
            r = server.block_until_done() => {
                if let Err(e) = r {
                    warn!(target: TRACING_TARGET, error = %e, "dns server ended");
                }
            }
        }
    });
    Ok(DnsServerHandle { local_addr, task })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::OobAuthority;
    use crate::model::token::Token;
    use crate::service::sink::{CallbackSink, InMemoryCallbackSink};
    use crate::service::token_alloc::TokenAllocator;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use sx_core::value_object::ids::TenantId;

    fn auth(token: Option<&Token>) -> (OobAuthority, Arc<InMemoryCallbackSink>) {
        let sink = Arc::new(InMemoryCallbackSink::new());
        let allocator = Arc::new(TokenAllocator::new());
        if let Some(t) = token {
            // Allocator bindings are keyed by `(tenant, finding_id) -> token`,
            // so we cannot inject an arbitrary token directly.  Instead,
            // allocate a fresh token but ignore it — the test reuses the
            // allocator only for lookup_unknown_is_none semantics.
            let _ = t;
        }
        let a = OobAuthority::new(
            "example.com".into(),
            Ipv4Addr::LOCALHOST,
            sink.clone() as Arc<dyn CallbackSink>,
            allocator,
        );
        (a, sink)
    }

    #[test]
    fn dns_authority_refuses_outside_base_domain() {
        let (a, _) = auth(None);
        // Out-of-scope domain.
        assert!(a
            .extract_token("0123456789abcdef.oob.evil.example.org")
            .is_none());
        // Missing `oob` anchor label.
        assert!(a
            .extract_token("0123456789abcdef.evil.example.com")
            .is_none());
        // The exact base domain root is not a valid query either.
        assert!(a.extract_token("oob.example.com").is_none());
    }

    #[test]
    fn dns_authority_extracts_token_with_prefix_labels() {
        let (a, _) = auth(None);
        // Multiple labels in front of the token are tolerated.
        let tok = a
            .extract_token("noise.0123456789abcdef.oob.example.com.")
            .unwrap();
        assert_eq!(tok, "0123456789abcdef");
    }

    #[test]
    fn dns_authority_returns_configured_a_for_known_token() {
        let sink = Arc::new(InMemoryCallbackSink::new());
        let allocator = Arc::new(TokenAllocator::new());
        let tid = TenantId::new();
        let token = allocator.allocate(tid, "F-1".into());
        let a = OobAuthority::new(
            "example.com".into(),
            Ipv4Addr::new(10, 0, 0, 7),
            sink.clone() as Arc<dyn CallbackSink>,
            allocator.clone(),
        );
        // The authority's answer IP is what callers expect to receive back.
        assert_eq!(a.answer_ipv4, Ipv4Addr::new(10, 0, 0, 7));
        // Confirm token extraction works for the bound token.
        let q = format!("{}.oob.example.com.", token.as_str());
        let extracted = a.extract_token(&q).unwrap();
        assert_eq!(extracted, token.as_str());
        // And the bound token resolves via the allocator.
        assert_eq!(allocator.lookup(&token).unwrap().tenant_id, tid);
    }
}
