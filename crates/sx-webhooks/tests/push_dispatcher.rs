//! Integration tests for the mobile-push dispatcher (P3-008).
//!
//! These tests drive `PushDispatcher` end-to-end against [`wiremock`]
//! stand-ins for APNs and FCM. They cover the four behaviours the
//! product bar requires:
//!
//! 1. APNs delivery — `POST /3/device/{token}` is invoked with the right
//!    headers (`apns-topic`, `apns-priority: 10`, `apns-push-type: alert`)
//!    and a `bearer …` `Authorization` carrying an ES256-signed JWT.
//! 2. FCM delivery — `POST /v1/projects/{p}/messages:send` is invoked
//!    after a successful `OAuth2` token exchange against the mocked Google
//!    token endpoint.
//! 3. 60-second dedupe window — two `dispatch_finding` calls for the
//!    same `(device, finding_id)` inside the window result in a single
//!    upstream POST and a `Deduped` audit event.
//! 4. Rate limit — once five sends land in a 60-second window, the
//!    sixth dispatch for the same device is dropped with a
//!    `RateLimited` audit event and no extra wiremock hit.
//!
//! The dispatcher relies on a pluggable [`MonotonicClock`] so the
//! tests pin time deterministically without `tokio::time::pause`.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};

use secrecy::SecretString;
use sx_webhooks::push::dispatcher::{MonotonicClock, PushDispatcherConfig};
use sx_webhooks::{
    push::apns::ApnsClient, push::fcm::FcmClient, ApnsCredentials, DeviceRecord, DeviceRegistry,
    FcmCredentials, FindingSeverity, InMemoryAuditSink, InMemoryDeviceRegistry,
    InMemoryTenantPushCredentials, MobilePlatform, NewDeviceRegistration, PushAuditEvent,
    PushDispatcher, PushFinding,
};
use wiremock::matchers::{header, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// PKCS#8 EC P-256 test key (matches the one used by the inline
/// `apns::tests`). Never signs production traffic.
const TEST_PKCS8_EC: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2\n\
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r\n\
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G\n\
-----END PRIVATE KEY-----\n";

/// PKCS#8 RSA test key (matches the one used by the inline
/// `fcm::tests`). Never signs production traffic.
const TEST_RSA_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCqmMzkx3mbAlye
aLOygtaQ983yFOVkwDs9DubEt3rdCi/FxQ7kP9QjBBIvsZM2NgEhEOdVxW+pRvJ8
RjDF0J4EO8abSCxo7BBGMppgcyxLxrKhTCaVi+HvjtMNViBsJdSz61+nnatJXVfq
eRxxl3hysSFJCGAuejeK3Z2ZzmGnwGN+YaoVVIRIv4NLPnXBJli1cJzAACFRbJKc
GNAUrW5CDB0f2fLJSMeymC9vsLFiz6gbFGidcQdDSMoWHzZ9DKrqyudIt4nPio9f
5ELefC88rzbszp2Lgqcz5uQ8mJyWHO13TTPEiMjOL+/RvgWTgdRhDMJFhMg8YNCo
m9h1TOSZAgMBAAECggEABID7oiZu3D6qAmUeKbjzpaNjLfsAVOJQgLkgCCLAxRfn
y7il1F+9L85OVXEX2Lsrg7Ysvf++xfkZaFpD30nAYuPPR3TL9lpVcihTxCGE8nxc
utkrXhtHBAebubsJE1iFgW6rVB37omMrBxB65aKo+NyFYKZuf/T0+oRat4TX4MFj
5rStmRyBdaIQA+dfs25DAm340lasbcCj8sSB8ni9SeSxRPGsaDoJnHw+6sHxCJ5u
eyDNUE/Lk6azIdaQTbmicPDa2S3qHyS1UmdHI6pd8/bs7UrulBHAiIacLiFoQJ7M
uV9Apx9MZZTtZST7fO5G6UmLTTSsswnMzyHgD+Cv0QKBgQDl4D4u5r0UxPS8Oorq
Dlq5jeCkOHSrHHejS0P0focaAaxRhslKzoBCEcYa+4uSZKqivaH4EHzJZ+9Nlphb
wEc4tBLBZ70kUp2ZdzLxKHQMMGWmGJbLHhlWmIC8IDnuU3VCOUkO5ti/5TOsHQbN
g7ZcPUZNiPJPNA5wuWj8MS4lKQKBgQC9+/UjKkkOXxnlL6D9/rEMF4eyf7dKxGSS
MGqdtKnQWdnB38LO/nKB/MxfjgP/LcSWEPpndX4bTdKinEnFAApHKj2k9uSD/vhF
sqXureleWVlPARU2ZFyU1J0DSfWJP384Dixim6sJ0l4WW7F8BlXlYrtzYvF9Jmgo
3dqhKxjB8QKBgQDSXQHK3fEOvqbQUiqpwnUX9VQsNFXf+O8rCkenyNpN3FYbTWOM
B6mrzKQkMSoqz+CviSZd4oivr2N492V6IV2L8I5xW0Plp4z90e1Wb5SzSt7avwnP
2z2I14qHnl4lUU6vScknz+1uvoso6G8/R1ds1c4uSjKkdJj6Y1JF56O48QKBgEB+
kDFn4XUng7rx+E1BcQkR09cc1DRlh165YPg4pI0+c1YFiDSM3IKUNy0ZIPI3r0zi
Zp9Im47ZVHAvbjuaT+LozBR8XAcTP2UpyHrGPzrwSgkv7OuSFnvP0Z2UNe5px95X
sWmoPuAOsjIU3qOj4vUEF26MYD6EE0gMSHP+FWGBAoGAc4gvSYJHq1pQw7P/JHPk
rU0/9i8URf0eRPwHQTtBa3AjFIRXRIHKCOmj+3TFeYg2+1nSxFDbFMZuvbcdHZB5
XxubfFDM/zI1lx60G8M0/nCm3D+50moXiTJMfjFth97v7rOzYPv3rkmoOacPJzAY
j5zu3nHyNHrJ7Aoe+QnmfIo=
-----END PRIVATE KEY-----
";

/// Manually advanced clock used by the dispatcher's rate-limit /
/// dedupe state. We start from a frozen `Instant::now()` and offset by
/// a tunable `Duration`.
#[derive(Debug)]
struct FakeClock {
    base: Instant,
    offset: StdMutex<Duration>,
}

impl FakeClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            base: Instant::now(),
            offset: StdMutex::new(Duration::ZERO),
        })
    }

    fn advance(&self, by: Duration) {
        let mut g = self.offset.lock().expect("offset");
        *g += by;
    }
}

impl MonotonicClock for FakeClock {
    fn now(&self) -> Instant {
        let g = self.offset.lock().expect("offset");
        self.base + *g
    }
}

fn apns_creds() -> ApnsCredentials {
    ApnsCredentials {
        team_id: "TEAM123456".into(),
        key_id: "KEY0987654".into(),
        bundle_id: "com.example.app".into(),
        private_key_pem: SecretString::from(TEST_PKCS8_EC.to_owned()),
    }
}

fn fcm_creds(token_uri: String, fcm_base_url: String) -> FcmCredentials {
    FcmCredentials {
        project_id: "demo-proj".into(),
        client_email: "svc@demo-proj.iam.gserviceaccount.com".into(),
        private_key_pem: SecretString::from(TEST_RSA_PEM.to_owned()),
        token_uri: Some(token_uri),
        fcm_base_url: Some(fcm_base_url),
    }
}

async fn seed_registry(
    reg: &InMemoryDeviceRegistry,
    tenant: &str,
    user: &str,
    platform: MobilePlatform,
    token: &str,
) -> DeviceRecord {
    let id = reg
        .register(NewDeviceRegistration {
            tenant_id: tenant.into(),
            user_id: user.into(),
            platform,
            device_token: SecretString::from(token.to_owned()),
        })
        .await
        .expect("register");
    reg.devices_for_user(tenant, user)
        .await
        .expect("lookup")
        .into_iter()
        .find(|d| d.id == id)
        .expect("found")
}

// ---------------------------------------------------------------------
// APNs wiremock round-trip
// ---------------------------------------------------------------------

#[tokio::test]
async fn dispatcher_sends_critical_apns_push_with_es256_jwt() {
    let mock = MockServer::start().await;
    // Wiremock intercepts the POST and asserts on the headers Apple
    // requires (bearer JWT, apns-topic, apns-priority: 10, push type).
    Mock::given(method("POST"))
        .and(path_regex(r"^/3/device/.+$"))
        .and(header("apns-topic", "com.example.app"))
        .and(header("apns-priority", "10"))
        .and(header("apns-push-type", "alert"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock)
        .await;

    let registry = Arc::new(InMemoryDeviceRegistry::new());
    let creds_store = Arc::new(InMemoryTenantPushCredentials::new());
    creds_store.set_apns("tenant-a", apns_creds()).await;
    creds_store
        .set_contacts("tenant-a", vec!["alice".to_owned()])
        .await;
    let _device = seed_registry(
        registry.as_ref(),
        "tenant-a",
        "alice",
        MobilePlatform::Ios,
        "apns-device-token-hex",
    )
    .await;
    let audit = Arc::new(InMemoryAuditSink::new());

    let dispatcher = PushDispatcher::new(
        registry.clone() as Arc<dyn DeviceRegistry>,
        creds_store.clone(),
        audit.clone(),
        ApnsClient::new(mock.uri()),
        FcmClient::new(),
    );

    let delivered = dispatcher
        .dispatch_finding(&PushFinding {
            finding_id: "f-1".into(),
            tenant_id: "tenant-a".into(),
            severity: FindingSeverity::Critical,
            title: "Critical alert".into(),
            body: "Investigate the production breach now.".into(),
        })
        .await
        .expect("dispatch");
    assert_eq!(delivered, 1);

    // Audit emitted exactly one Delivered event for APNs.
    let events = audit.snapshot().await;
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0],
        PushAuditEvent::Delivered {
            provider: "apns",
            ..
        }
    ));

    // Inspect the captured request — it must carry a 3-segment JWT in
    // the `authorization: bearer …` header. We do not log or assert on
    // the token itself, only its structural shape.
    let requests = mock.received_requests().await.expect("received");
    assert_eq!(requests.len(), 1);
    let auth = requests[0]
        .headers
        .get("authorization")
        .expect("authorization header")
        .to_str()
        .expect("utf8");
    assert!(auth.starts_with("bearer "), "scheme must be bearer");
    let jwt = &auth["bearer ".len()..];
    assert_eq!(
        jwt.split('.').count(),
        3,
        "JWT must be 3-segment ES256 token"
    );
}

// ---------------------------------------------------------------------
// FCM wiremock round-trip (OAuth2 token exchange + messages:send)
// ---------------------------------------------------------------------

#[tokio::test]
async fn dispatcher_sends_critical_fcm_push_after_oauth_exchange() {
    let mock = MockServer::start().await;
    // 1) OAuth2 token endpoint returns an access token.
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "fake-google-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        })))
        .expect(1)
        .mount(&mock)
        .await;
    // 2) FCM messages:send accepts the push.
    Mock::given(method("POST"))
        .and(path("/v1/projects/demo-proj/messages:send"))
        .and(header("authorization", "Bearer fake-google-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "projects/demo-proj/messages/m-1",
        })))
        .expect(1)
        .mount(&mock)
        .await;

    let registry = Arc::new(InMemoryDeviceRegistry::new());
    let creds_store = Arc::new(InMemoryTenantPushCredentials::new());
    creds_store
        .set_fcm(
            "tenant-a",
            fcm_creds(format!("{}/token", mock.uri()), mock.uri()),
        )
        .await;
    creds_store
        .set_contacts("tenant-a", vec!["bob".to_owned()])
        .await;
    let _device = seed_registry(
        registry.as_ref(),
        "tenant-a",
        "bob",
        MobilePlatform::Android,
        "fcm-registration-id",
    )
    .await;
    let audit = Arc::new(InMemoryAuditSink::new());

    let dispatcher = PushDispatcher::new(
        registry.clone() as Arc<dyn DeviceRegistry>,
        creds_store.clone(),
        audit.clone(),
        ApnsClient::default(),
        FcmClient::new(),
    );

    let delivered = dispatcher
        .dispatch_finding(&PushFinding {
            finding_id: "f-2".into(),
            tenant_id: "tenant-a".into(),
            severity: FindingSeverity::Critical,
            title: "Crit".into(),
            body: "body".into(),
        })
        .await
        .expect("dispatch");
    assert_eq!(delivered, 1);

    let events = audit.snapshot().await;
    assert_eq!(events.len(), 1);
    assert!(matches!(
        events[0],
        PushAuditEvent::Delivered {
            provider: "fcm",
            ..
        }
    ));
}

// ---------------------------------------------------------------------
// Severity gate
// ---------------------------------------------------------------------

#[tokio::test]
async fn dispatcher_skips_non_critical_findings() {
    let mock = MockServer::start().await;
    // The wiremock server is configured with *no* mounts; if the
    // dispatcher tries to POST anything the test fails because the
    // mock returns 404 and the audit gains a Failed event.
    let registry = Arc::new(InMemoryDeviceRegistry::new());
    let creds_store = Arc::new(InMemoryTenantPushCredentials::new());
    creds_store.set_apns("tenant-a", apns_creds()).await;
    creds_store
        .set_contacts("tenant-a", vec!["alice".to_owned()])
        .await;
    let _device = seed_registry(
        registry.as_ref(),
        "tenant-a",
        "alice",
        MobilePlatform::Ios,
        "apns-tok",
    )
    .await;
    let audit = Arc::new(InMemoryAuditSink::new());

    let dispatcher = PushDispatcher::new(
        registry.clone() as Arc<dyn DeviceRegistry>,
        creds_store.clone(),
        audit.clone(),
        ApnsClient::new(mock.uri()),
        FcmClient::new(),
    );

    for sev in [
        FindingSeverity::Info,
        FindingSeverity::Low,
        FindingSeverity::Medium,
        FindingSeverity::High,
    ] {
        let delivered = dispatcher
            .dispatch_finding(&PushFinding {
                finding_id: "f".into(),
                tenant_id: "tenant-a".into(),
                severity: sev,
                title: "t".into(),
                body: "b".into(),
            })
            .await
            .expect("dispatch");
        assert_eq!(delivered, 0, "severity {sev:?} should not push");
    }
    assert!(audit.snapshot().await.is_empty());
    assert!(mock.received_requests().await.unwrap().is_empty());
}

// ---------------------------------------------------------------------
// 60-second dedupe window
// ---------------------------------------------------------------------

#[tokio::test]
async fn dispatcher_dedupes_identical_finding_within_60s_window() {
    let mock = MockServer::start().await;
    // Single mount that accepts any number of pushes; we verify the
    // *exact* count via `mock.received_requests()` after the run so we
    // can decouple from wiremock's per-mount expect-counter (which is
    // cumulative across the lifetime of the mock).
    Mock::given(method("POST"))
        .and(path_regex(r"^/3/device/.+$"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock)
        .await;

    let registry = Arc::new(InMemoryDeviceRegistry::new());
    let creds_store = Arc::new(InMemoryTenantPushCredentials::new());
    creds_store.set_apns("tenant-a", apns_creds()).await;
    creds_store
        .set_contacts("tenant-a", vec!["alice".to_owned()])
        .await;
    let _device = seed_registry(
        registry.as_ref(),
        "tenant-a",
        "alice",
        MobilePlatform::Ios,
        "apns-tok",
    )
    .await;
    let audit = Arc::new(InMemoryAuditSink::new());

    let clock = FakeClock::new();
    let dispatcher = PushDispatcher::with_config(
        registry.clone() as Arc<dyn DeviceRegistry>,
        creds_store.clone(),
        audit.clone(),
        ApnsClient::new(mock.uri()),
        FcmClient::new(),
        PushDispatcherConfig::default(),
        Box::new(FakeClockHandle(clock.clone())),
    );

    let finding = PushFinding {
        finding_id: "f-dedupe".into(),
        tenant_id: "tenant-a".into(),
        severity: FindingSeverity::Critical,
        title: "t".into(),
        body: "b".into(),
    };

    // First dispatch — delivered.
    assert_eq!(dispatcher.dispatch_finding(&finding).await.unwrap(), 1);
    // 30s later — still inside the 60s window: suppressed.
    clock.advance(Duration::from_secs(30));
    assert_eq!(dispatcher.dispatch_finding(&finding).await.unwrap(), 0);
    // 31s further — now 61s after the first delivery: pushes again.
    clock.advance(Duration::from_secs(31));
    assert_eq!(dispatcher.dispatch_finding(&finding).await.unwrap(), 1);

    let events = audit.snapshot().await;
    assert_eq!(events.len(), 3, "delivered + deduped + delivered");
    assert!(matches!(events[0], PushAuditEvent::Delivered { .. }));
    assert!(matches!(events[1], PushAuditEvent::Deduped { .. }));
    assert!(matches!(events[2], PushAuditEvent::Delivered { .. }));

    // Only the two real deliveries hit APNs; the dedupe in the middle
    // did not.
    let upstream_hits = mock.received_requests().await.unwrap().len();
    assert_eq!(upstream_hits, 2, "dedupe must suppress upstream POST");
}

// ---------------------------------------------------------------------
// 5 / minute / device rate limit
// ---------------------------------------------------------------------

#[tokio::test]
async fn dispatcher_drops_sixth_send_in_one_minute_window() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"^/3/device/.+$"))
        .respond_with(ResponseTemplate::new(200))
        // 5 successful deliveries allowed; the 6th must NOT hit APNs.
        .expect(5)
        .mount(&mock)
        .await;

    let registry = Arc::new(InMemoryDeviceRegistry::new());
    let creds_store = Arc::new(InMemoryTenantPushCredentials::new());
    creds_store.set_apns("tenant-a", apns_creds()).await;
    creds_store
        .set_contacts("tenant-a", vec!["alice".to_owned()])
        .await;
    let _device = seed_registry(
        registry.as_ref(),
        "tenant-a",
        "alice",
        MobilePlatform::Ios,
        "apns-tok",
    )
    .await;
    let audit = Arc::new(InMemoryAuditSink::new());

    let clock = FakeClock::new();
    let dispatcher = PushDispatcher::with_config(
        registry.clone() as Arc<dyn DeviceRegistry>,
        creds_store.clone(),
        audit.clone(),
        ApnsClient::new(mock.uri()),
        FcmClient::new(),
        PushDispatcherConfig::default(),
        Box::new(FakeClockHandle(clock.clone())),
    );

    // Six dispatches with distinct finding ids (so dedupe doesn't kick
    // in) and 1-second spacing (well inside the 60s rate window).
    for i in 0..6 {
        let f = PushFinding {
            finding_id: format!("f-{i}"),
            tenant_id: "tenant-a".into(),
            severity: FindingSeverity::Critical,
            title: "t".into(),
            body: "b".into(),
        };
        let _ = dispatcher.dispatch_finding(&f).await.unwrap();
        clock.advance(Duration::from_secs(1));
    }

    let events = audit.snapshot().await;
    let delivered = events
        .iter()
        .filter(|e| matches!(e, PushAuditEvent::Delivered { .. }))
        .count();
    let rate_limited = events
        .iter()
        .filter(|e| matches!(e, PushAuditEvent::RateLimited { .. }))
        .count();
    assert_eq!(delivered, 5, "5/min/device cap");
    assert_eq!(rate_limited, 1, "the 6th is dropped");
}

// ---------------------------------------------------------------------
// Helper that lets a single FakeClock instance be passed to two
// dispatchers (or, in our case, satisfies the trait-object lifetime).
// ---------------------------------------------------------------------

#[derive(Debug)]
struct FakeClockHandle(Arc<FakeClock>);

impl MonotonicClock for FakeClockHandle {
    fn now(&self) -> Instant {
        self.0.now()
    }
}
