//! gRPC server-reflection probe.
//!
//! Connects to a gRPC server that exposes the standard
//! `grpc.reflection.v1.ServerReflection` (or `.v1alpha`) service, lists the
//! services it advertises, and (where available) the methods of each
//! service. The response is normalised to [`GrpcServiceList`] for
//! consumers.
//!
//! Transport: a `tonic` `Channel` built from the configured [`Url`] (TLS
//! enabled either by `grpcs` / `https` scheme or explicitly via the `tls`
//! flag), wrapping the generated `ServerReflectionClient`. The client
//! issues a single `ListServices("")` request on the bidirectional
//! streaming `ServerReflectionInfo` RPC and consumes the first response.
//!
//! The hand-rolled protobuf decoder ([`parse_list_service_response_bytes`])
//! is **retained** for fixture-driven unit tests and as a fallback for
//! consumers that have raw `ListServiceResponse` bytes (for example, from
//! a packet capture) without a live channel.
//!
//! Dangerous-flag rules emitted by this probe:
//!
//! | Rule id                | Severity | Trigger                                       |
//! |------------------------|----------|-----------------------------------------------|
//! | `grpc-destructive-method` | high   | Method name begins with `Delete` / `Drop` etc. |
//! | `grpc-admin-service`     | medium | Service name contains `admin`                  |

use std::time::Duration;

use futures::StreamExt as _;
use serde::{Deserialize, Serialize};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic_reflection::pb::v1::{
    server_reflection_client::ServerReflectionClient, server_reflection_request::MessageRequest,
    server_reflection_response::MessageResponse, ServerReflectionRequest,
};
use url::Url;

use crate::error::DiscoveryError;

/// Default connect timeout applied to the gRPC channel when the caller has
/// not set one explicitly.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default per-request timeout applied to the streaming reflection RPC.
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Substrings (case-insensitive prefixes) that flag a method name as
/// destructive.
const DESTRUCTIVE_METHOD_PREFIXES: &[&str] = &["delete", "drop", "purge", "wipe", "destroy"];

/// Substrings (case-insensitive) that flag a service name as administrative.
const ADMIN_SERVICE_MARKERS: &[&str] = &["admin", "superuser", "root"];

/// Reserved well-known service names skipped from result lists.
const RESERVED_REFLECTION_SERVICES: &[&str] = &[
    "grpc.reflection.v1.ServerReflection",
    "grpc.reflection.v1alpha.ServerReflection",
];

/// Severity tag for a [`GrpcFinding`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GrpcSeverity {
    /// Highest-severity classification.
    High,
    /// Mid-severity classification.
    Medium,
    /// Informational finding (no immediate action).
    Info,
}

impl GrpcSeverity {
    /// Stable string tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Info => "info",
        }
    }
}

/// Dangerous-flag observation for a gRPC service / method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrpcFinding {
    /// Stable rule identifier (e.g. `grpc-destructive-method`).
    pub rule_id: String,
    /// Severity classification.
    pub severity: GrpcSeverity,
    /// Qualified element: `service` or `service.method`.
    pub element: String,
    /// Human-readable rationale.
    pub message: String,
}

/// Method discovered on a gRPC service.
///
/// The reflection protocol's `ListService` arm only carries service names;
/// method names are populated when the caller also asks for
/// `FileContainingSymbol` and parses the resulting `FileDescriptorProto`.
/// Until that branch lands, `methods` is empty by default and the
/// dangerous-flag classifier is exercised through fixture-driven tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodSpec {
    /// Method name as advertised by the service descriptor.
    pub name: String,
}

/// A single service from the reflection response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSpec {
    /// Fully qualified service name (e.g. `pkg.UserService`).
    pub name: String,
    /// Methods discovered for the service.
    pub methods: Vec<MethodSpec>,
}

/// List of services reported by a gRPC server's reflection endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GrpcServiceList {
    /// Services discovered (reserved reflection services filtered out).
    pub services: Vec<ServiceSpec>,
    /// Dangerous-flag findings derived from service / method names.
    pub findings: Vec<GrpcFinding>,
}

/// gRPC reflection probe configuration.
#[derive(Debug, Clone)]
pub struct GrpcReflect {
    /// Endpoint URL. The scheme MUST be `http`, `https`, `grpc`, or
    /// `grpcs`. Host + port are honored; path is ignored.
    pub endpoint: Url,
    /// Whether to negotiate TLS. Set independently of the URL scheme so
    /// callers can override (e.g. `grpc://` with manual TLS).
    pub tls: bool,
}

impl GrpcReflect {
    /// Construct a new probe, validating the endpoint scheme.
    ///
    /// # Errors
    /// - [`DiscoveryError::Config`] if the URL scheme is not one of the
    ///   gRPC-compatible schemes.
    /// - [`DiscoveryError::Config`] if the URL has no host.
    pub fn new(endpoint: Url, tls: bool) -> Result<Self, DiscoveryError> {
        match endpoint.scheme() {
            "http" | "https" | "grpc" | "grpcs" => {}
            other => {
                return Err(DiscoveryError::config(format!(
                    "grpc reflect rejects scheme '{other}'; expected http(s) or grpc(s)"
                )));
            }
        }
        if endpoint.host_str().is_none() {
            return Err(DiscoveryError::config(
                "grpc reflect endpoint must have a host",
            ));
        }
        Ok(Self { endpoint, tls })
    }

    /// Open a `tonic` channel to the configured endpoint, send a single
    /// `ListServices("")` request on the bidirectional reflection RPC, and
    /// decode the first response into a [`GrpcServiceList`].
    ///
    /// Behaviour:
    /// - The URL scheme is translated to the transport-level scheme
    ///   (`grpc` → `http`, `grpcs` → `https`); `http(s)` is forwarded
    ///   verbatim.
    /// - If [`Self::tls`] is set, a webpki-root-backed
    ///   [`ClientTlsConfig`] is applied even when the scheme is plain
    ///   `http` / `grpc`. The `https` / `grpcs` schemes also auto-enable
    ///   TLS.
    /// - The reserved-reflection filter and the dangerous-flag classifier
    ///   are applied via [`finalize_service_list`], so the public surface
    ///   matches the previous hand-rolled decoder path.
    ///
    /// Method names are **not** populated by this round-trip: the v1
    /// reflection RPC only returns service names in response to
    /// `ListServices`. Method discovery requires a follow-up
    /// `FileContainingSymbol` lookup against each service, which is
    /// deferred to a separate scanner pass.
    ///
    /// # Errors
    /// - [`DiscoveryError::Config`] if the endpoint URL cannot be
    ///   converted into a `tonic` `Endpoint` or the TLS configuration is
    ///   rejected.
    /// - [`DiscoveryError::Internal`] for transport failures, gRPC status
    ///   errors, an empty response stream, an `ErrorResponse` arm from the
    ///   server, or an unexpected `MessageResponse` variant.
    pub async fn probe(&self) -> Result<GrpcServiceList, DiscoveryError> {
        let services = {
            let channel = self
                .build_endpoint()?
                .connect()
                .await
                .map_err(|e| DiscoveryError::internal(format!("grpc reflect connect: {e}")))?;
            list_services(channel).await?
        };
        Ok(finalize_service_list(services))
    }

    /// Build a `tonic::transport::Endpoint` from the probe configuration,
    /// translating gRPC-flavoured schemes into the HTTP schemes that
    /// `tonic` actually parses and honouring [`Self::tls`].
    fn build_endpoint(&self) -> Result<Endpoint, DiscoveryError> {
        let transport_scheme = match self.endpoint.scheme() {
            "grpcs" | "https" => "https",
            "grpc" | "http" => "http",
            other => {
                // Constructor rejected anything else, but keep the arm
                // explicit so future scheme additions stay safe.
                return Err(DiscoveryError::config(format!(
                    "grpc reflect: unsupported transport scheme '{other}'"
                )));
            }
        };
        let host = self
            .endpoint
            .host_str()
            .ok_or_else(|| DiscoveryError::config("grpc reflect: endpoint has no host"))?;
        let port = self.endpoint.port_or_known_default().unwrap_or(
            if matches!(transport_scheme, "https") {
                443
            } else {
                80
            },
        );
        // Authority-only URI: tonic ignores the URL path on the client.
        let dst = format!("{transport_scheme}://{host}:{port}");

        let mut endpoint = Endpoint::from_shared(dst.clone()).map_err(|e| {
            DiscoveryError::config(format!("grpc reflect: invalid endpoint '{dst}': {e}"))
        })?;
        endpoint = endpoint
            .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
            .timeout(DEFAULT_REQUEST_TIMEOUT);

        // Force TLS when either the scheme demands it or the caller flipped
        // the flag. `Endpoint::tls_config` is idempotent — passing a fresh
        // `ClientTlsConfig` here only overrides domain/cert state.
        let scheme_is_tls = matches!(transport_scheme, "https");
        if scheme_is_tls || self.tls {
            let tls = ClientTlsConfig::new().with_enabled_roots();
            endpoint = endpoint.tls_config(tls).map_err(|e| {
                DiscoveryError::config(format!("grpc reflect: tls config rejected: {e}"))
            })?;
        }

        Ok(endpoint)
    }

    /// Read-only accessor used by tests + downstream consumers.
    #[must_use]
    pub const fn tls(&self) -> bool {
        self.tls
    }

    /// Read-only accessor.
    #[must_use]
    pub const fn endpoint(&self) -> &Url {
        &self.endpoint
    }
}

/// Send a `ListServices("")` request on the bidirectional reflection RPC,
/// consume the first response frame, and return the decoded service names.
///
/// Method specs are left empty: only service names round-trip through the
/// `ListServices` arm; populating methods requires
/// `FileContainingSymbol` follow-ups that are out of scope here.
async fn list_services(channel: Channel) -> Result<Vec<ServiceSpec>, DiscoveryError> {
    let request = ServerReflectionRequest {
        host: String::new(),
        message_request: Some(MessageRequest::ListServices(String::new())),
    };
    let request_stream = futures::stream::iter(std::iter::once(request));
    let mut stream = ServerReflectionClient::new(channel)
        .server_reflection_info(request_stream)
        .await
        .map_err(|status| {
            DiscoveryError::internal(format!(
                "grpc reflect: server_reflection_info status={}: {}",
                status.code(),
                status.message()
            ))
        })?
        .into_inner();
    let first = stream
        .next()
        .await
        .ok_or_else(|| DiscoveryError::internal("grpc reflect: empty response stream"))?
        .map_err(|status| {
            DiscoveryError::internal(format!(
                "grpc reflect: response status={}: {}",
                status.code(),
                status.message()
            ))
        })?;

    match first.message_response {
        Some(MessageResponse::ListServicesResponse(list)) => Ok(list
            .service
            .into_iter()
            .map(|s| ServiceSpec {
                name: s.name,
                methods: Vec::new(),
            })
            .collect()),
        Some(MessageResponse::ErrorResponse(err)) => Err(DiscoveryError::internal(format!(
            "grpc reflect: server error code={} message='{}'",
            err.error_code, err.error_message
        ))),
        Some(_) => Err(DiscoveryError::internal(
            "grpc reflect: unexpected response arm (expected list_services_response)",
        )),
        None => Err(DiscoveryError::internal(
            "grpc reflect: response carried no message_response oneof",
        )),
    }
}

/// Hand-rolled decoder for the reflection
/// `ListServiceResponse { repeated ServiceResponse service = 1; }`
/// payload, where each `ServiceResponse` is `{ string name = 1; }`.
///
/// Wire format primer used here:
/// - Each field is encoded as a varint `tag = (field_no << 3) | wire_type`.
/// - For length-delimited fields (`wire_type` `2`), the next varint is the
///   length followed by raw bytes.
///
/// This is sufficient to decode both the bare `ListServiceResponse` and the
/// `ServerReflectionResponse` envelope when its `list_services_response`
/// oneof arm is active (tag 6).
///
/// # Errors
/// - [`DiscoveryError::Internal`] on truncated input or invalid varints.
pub fn parse_list_service_response_bytes(bytes: &[u8]) -> Result<Vec<ServiceSpec>, DiscoveryError> {
    let mut out = Vec::new();
    let mut cur = bytes;
    while !cur.is_empty() {
        let (tag, rest) = read_varint(cur)?;
        cur = rest;
        let field_no = tag >> 3;
        let wire_type = tag & 0x07;
        match (field_no, wire_type) {
            // ServerReflectionResponse.list_services_response (oneof tag 26).
            (26, 2) => {
                let (payload, rest) = read_length_delimited(cur)?;
                cur = rest;
                let inner = parse_list_service_response_bytes(payload)?;
                out.extend(inner);
            }
            // ListServiceResponse.service (repeated, tag 1) → ServiceResponse.
            (1, 2) => {
                let (payload, rest) = read_length_delimited(cur)?;
                cur = rest;
                if let Some(name) = parse_service_response_name(payload)? {
                    out.push(ServiceSpec {
                        name,
                        methods: Vec::new(),
                    });
                }
            }
            // Unknown but valid → skip.
            (_, 2) => {
                let (_payload, rest) = read_length_delimited(cur)?;
                cur = rest;
            }
            (_, 0) => {
                let (_v, rest) = read_varint(cur)?;
                cur = rest;
            }
            (_, 1) => {
                if cur.len() < 8 {
                    return Err(DiscoveryError::internal("grpc reflect: truncated 64-bit"));
                }
                cur = cur.get(8..).unwrap_or(&[]);
            }
            (_, 5) => {
                if cur.len() < 4 {
                    return Err(DiscoveryError::internal("grpc reflect: truncated 32-bit"));
                }
                cur = cur.get(4..).unwrap_or(&[]);
            }
            (_, wt) => {
                return Err(DiscoveryError::internal(format!(
                    "grpc reflect: unsupported wire type {wt}"
                )));
            }
        }
    }
    Ok(out)
}

fn parse_service_response_name(bytes: &[u8]) -> Result<Option<String>, DiscoveryError> {
    let mut cur = bytes;
    let mut name: Option<String> = None;
    while !cur.is_empty() {
        let (tag, rest) = read_varint(cur)?;
        cur = rest;
        let field_no = tag >> 3;
        let wire_type = tag & 0x07;
        match (field_no, wire_type) {
            (1, 2) => {
                let (payload, rest) = read_length_delimited(cur)?;
                cur = rest;
                let s = std::str::from_utf8(payload)
                    .map_err(|e| DiscoveryError::internal(format!("invalid utf8: {e}")))?;
                name = Some(s.to_owned());
            }
            (_, 2) => {
                let (_p, rest) = read_length_delimited(cur)?;
                cur = rest;
            }
            (_, 0) => {
                let (_v, rest) = read_varint(cur)?;
                cur = rest;
            }
            (_, wt) => {
                return Err(DiscoveryError::internal(format!(
                    "grpc reflect: service name unsupported wire type {wt}"
                )));
            }
        }
    }
    Ok(name)
}

fn read_varint(bytes: &[u8]) -> Result<(u64, &[u8]), DiscoveryError> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    let mut idx = 0usize;
    loop {
        let &byte = bytes
            .get(idx)
            .ok_or_else(|| DiscoveryError::internal("grpc reflect: truncated varint"))?;
        idx = idx.saturating_add(1);
        let part = u64::from(byte & 0x7F);
        value = value
            .checked_add(part << shift)
            .ok_or_else(|| DiscoveryError::internal("grpc reflect: varint overflow"))?;
        if byte & 0x80 == 0 {
            break;
        }
        shift = shift
            .checked_add(7)
            .ok_or_else(|| DiscoveryError::internal("grpc reflect: varint shift overflow"))?;
        if shift > 63 {
            return Err(DiscoveryError::internal("grpc reflect: varint too long"));
        }
    }
    let rest = bytes.get(idx..).unwrap_or(&[]);
    Ok((value, rest))
}

fn read_length_delimited(bytes: &[u8]) -> Result<(&[u8], &[u8]), DiscoveryError> {
    let (len, rest) = read_varint(bytes)?;
    let len_us = usize::try_from(len)
        .map_err(|_| DiscoveryError::internal("grpc reflect: length-prefix too large"))?;
    if rest.len() < len_us {
        return Err(DiscoveryError::internal(
            "grpc reflect: truncated length-delimited field",
        ));
    }
    let payload = rest.get(..len_us).unwrap_or(&[]);
    let tail = rest.get(len_us..).unwrap_or(&[]);
    Ok((payload, tail))
}

/// Build a [`GrpcServiceList`] from a decoded service list, filtering out
/// reserved reflection services and classifying findings.
#[must_use]
pub fn finalize_service_list(mut services: Vec<ServiceSpec>) -> GrpcServiceList {
    services.retain(|s| !RESERVED_REFLECTION_SERVICES.contains(&s.name.as_str()));
    let findings = classify_services(&services);
    GrpcServiceList { services, findings }
}

fn classify_services(services: &[ServiceSpec]) -> Vec<GrpcFinding> {
    let mut out = Vec::new();
    for s in services {
        let svc_lower = s.name.to_ascii_lowercase();
        if ADMIN_SERVICE_MARKERS.iter().any(|m| svc_lower.contains(m)) {
            out.push(GrpcFinding {
                rule_id: "grpc-admin-service".to_owned(),
                severity: GrpcSeverity::Medium,
                element: s.name.clone(),
                message: format!("Service '{}' looks administrative.", s.name),
            });
        }
        for m in &s.methods {
            if is_destructive_method(&m.name) {
                out.push(GrpcFinding {
                    rule_id: "grpc-destructive-method".to_owned(),
                    severity: GrpcSeverity::High,
                    element: format!("{}.{}", s.name, m.name),
                    message: format!(
                        "Method '{}.{}' matches destructive name pattern.",
                        s.name, m.name
                    ),
                });
            }
        }
    }
    out
}

fn is_destructive_method(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    DESTRUCTIVE_METHOD_PREFIXES
        .iter()
        .any(|p| lower.starts_with(p))
}

/// Hand-encode a `ListServiceResponse` for unit-test fixtures.
///
/// Public so the test module of this crate (and downstream consumers
/// building fixtures) can construct realistic captures without taking a
/// `prost` dependency.
#[must_use]
pub fn encode_list_service_response_fixture(names: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for name in names {
        let mut service_resp = Vec::new();
        // field 1, wire type 2 → tag = (1 << 3) | 2 = 10
        write_varint(&mut service_resp, 10);
        write_varint(&mut service_resp, name.len() as u64);
        service_resp.extend_from_slice(name.as_bytes());

        // Outer ListServiceResponse: field 1, wire type 2 → tag = 10
        write_varint(&mut out, 10);
        write_varint(&mut out, service_resp.len() as u64);
        out.extend_from_slice(&service_resp);
    }
    out
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        // Safe: masking with 0x7F keeps the value within `u8` range.
        #[allow(clippy::cast_possible_truncation)]
        let byte = (value & 0x7F) as u8;
        out.push(byte | 0x80);
        value >>= 7;
    }
    // Safe: loop exited because `value < 0x80` fits in `u8`.
    #[allow(clippy::cast_possible_truncation)]
    let last = (value & 0x7F) as u8;
    out.push(last);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use std::sync::Once;

    /// Install the ring `CryptoProvider` exactly once per process. Required
    /// before any test constructs a `ClientTlsConfig`, because rustls 0.23
    /// panics on TLS-config build when there's no process-level default.
    fn install_rustls_provider_once() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            // `install_default` returns Err if a provider is already installed,
            // which we tolerate — concurrent test binaries may race us.
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    // 1
    #[test]
    fn parses_reflection_response_into_service_specs() {
        let bytes = encode_list_service_response_fixture(&[
            "pkg.UserService",
            "pkg.OrderService",
            "grpc.reflection.v1alpha.ServerReflection",
        ]);
        let services = parse_list_service_response_bytes(&bytes).unwrap();
        let final_list = finalize_service_list(services);
        let names: Vec<_> = final_list
            .services
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        // Reflection service is filtered out by finalize_service_list.
        assert_eq!(names, vec!["pkg.UserService", "pkg.OrderService"]);
    }

    // 2
    #[test]
    fn rejects_unknown_scheme() {
        let err = GrpcReflect::new(Url::parse("ftp://example.com/x").unwrap(), false).unwrap_err();
        assert!(matches!(err, DiscoveryError::Config(_)));
    }

    // 3
    #[test]
    fn accepts_grpc_scheme_and_records_tls_flag() {
        let p = GrpcReflect::new(
            Url::parse("grpc://reflect.example.com:50051").unwrap(),
            false,
        )
        .unwrap();
        assert!(!p.tls());
        assert_eq!(p.endpoint().host_str(), Some("reflect.example.com"));
    }

    // 4
    #[test]
    fn accepts_grpcs_scheme_with_tls_enabled() {
        let p =
            GrpcReflect::new(Url::parse("grpcs://reflect.example.com:443").unwrap(), true).unwrap();
        assert!(p.tls());
    }

    // 5
    #[test]
    fn accepts_https_scheme_for_grpc_web_targets() {
        let p = GrpcReflect::new(Url::parse("https://grpc.example.com/").unwrap(), true).unwrap();
        assert!(p.tls());
    }

    // 6
    #[test]
    fn rejects_url_without_host() {
        // `unix:/tmp/foo` parses with no host segment.
        let err = GrpcReflect::new(
            Url::parse("grpc://")
                .unwrap_or_else(|_| Url::parse("file:///tmp/x").expect("static url")),
            false,
        )
        .unwrap_err();
        assert!(matches!(err, DiscoveryError::Config(_)));
    }

    // 7
    #[test]
    fn methods_carrying_delete_prefix_are_highlighted_as_high() {
        let services = vec![ServiceSpec {
            name: "pkg.UserService".to_owned(),
            methods: vec![
                MethodSpec {
                    name: "GetUser".to_owned(),
                },
                MethodSpec {
                    name: "DeleteUser".to_owned(),
                },
                MethodSpec {
                    name: "DropTenant".to_owned(),
                },
            ],
        }];
        let final_list = finalize_service_list(services);
        let destructive: Vec<_> = final_list
            .findings
            .iter()
            .filter(|f| f.rule_id == "grpc-destructive-method")
            .collect();
        assert_eq!(destructive.len(), 2);
        assert!(destructive.iter().all(|f| f.severity == GrpcSeverity::High));
        let elements: Vec<&str> = destructive.iter().map(|f| f.element.as_str()).collect();
        assert!(elements.contains(&"pkg.UserService.DeleteUser"));
        assert!(elements.contains(&"pkg.UserService.DropTenant"));
    }

    // 8
    #[test]
    fn admin_service_name_is_flagged_medium() {
        let services = vec![ServiceSpec {
            name: "pkg.AdminConsole".to_owned(),
            methods: Vec::new(),
        }];
        let final_list = finalize_service_list(services);
        let f = final_list
            .findings
            .iter()
            .find(|f| f.rule_id == "grpc-admin-service")
            .expect("expected admin-service finding");
        assert_eq!(f.severity, GrpcSeverity::Medium);
    }

    // 9
    #[test]
    fn parser_rejects_truncated_varint() {
        // A length-delimited tag (1<<3|2 = 10) followed by an incomplete
        // length varint.
        let bad = [0x0A, 0xFF];
        let err = parse_list_service_response_bytes(&bad).unwrap_err();
        assert!(matches!(err, DiscoveryError::Internal(_)));
    }

    // 10
    #[test]
    fn parser_rejects_length_overrun() {
        // Tag 10 (length-delimited), length 99, no payload bytes.
        let bad = [0x0A, 0x63];
        let err = parse_list_service_response_bytes(&bad).unwrap_err();
        assert!(matches!(err, DiscoveryError::Internal(_)));
    }

    // 11
    #[test]
    fn empty_payload_yields_empty_service_list() {
        let final_list = finalize_service_list(parse_list_service_response_bytes(&[]).unwrap());
        assert!(final_list.services.is_empty());
        assert!(final_list.findings.is_empty());
    }

    // 12 — endpoint translation invariant. `build_endpoint` rewrites
    // `grpc(s)://` URLs into the `http(s)://` form `tonic` parses, so the
    // probe never hands tonic a scheme it would reject up-front. We can't
    // verify the resulting `Endpoint` directly (it is opaque), but
    // exercising `build_endpoint` for every accepted scheme guards
    // against regressions in the scheme translation table.
    #[test]
    fn build_endpoint_accepts_all_supported_schemes() {
        install_rustls_provider_once();
        for raw in [
            "grpc://reflect.example.com:50051",
            "grpcs://reflect.example.com:443",
            "http://reflect.example.com:50051",
            "https://reflect.example.com/",
        ] {
            let url = Url::parse(raw).unwrap();
            let probe = GrpcReflect::new(url, false).unwrap();
            probe
                .build_endpoint()
                .unwrap_or_else(|e| panic!("build_endpoint({raw}) failed: {e}"));
        }
    }

    // 13 — TLS override path. With the `tls` flag set, `build_endpoint`
    // must succeed even when the URL scheme is plain `grpc` / `http`.
    #[test]
    fn build_endpoint_honors_tls_override_on_plaintext_scheme() {
        install_rustls_provider_once();
        let url = Url::parse("grpc://reflect.example.com:50051").unwrap();
        let probe = GrpcReflect::new(url, true).unwrap();
        probe.build_endpoint().expect("tls override must apply");
    }

    // 14 — live reflection integration smoke. Requires a real
    // reflection-capable server. Skipped in CI by default.
    #[tokio::test]
    #[ignore = "Requires live gRPC server with reflection on localhost:50051"]
    async fn live_reflection_integration_test() {
        let probe = GrpcReflect::new(Url::parse("grpc://127.0.0.1:50051").unwrap(), false).unwrap();
        let list = probe.probe().await.expect("live reflection probe");
        assert!(
            !list.services.is_empty(),
            "expected at least one user-defined service from local reflection server",
        );
    }
}
