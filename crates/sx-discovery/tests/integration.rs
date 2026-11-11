//! Integration tests for the sx-discovery crate.
//!
//! Covers the cases the crate spec calls out:
//!
//! - `safety_gate_denies_when_scope_violated`
//! - `safety_gate_denies_when_killswitch_tripped`
//! - `tcp_port_probe_emits_open_port_for_listening_socket`
//! - `tcp_port_probe_emits_nothing_for_closed_port`
//! - `http_fingerprint_captures_server_header` (uses `wiremock`)
//! - `http_fingerprint_strips_set_cookie_value`
//! - `dns_resolver_requires_explicit_resolvers`
//! - `rate_limiter_blocks_above_budget`
//! - `kill_switch_aborts_in_flight_scan`
//! - `scanner_registry_lookup_by_id`

#![allow(clippy::unwrap_used, clippy::missing_panics_doc, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sx_discovery::prelude::*;
use time::OffsetDateTime;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn rate_limiter() -> Arc<RateLimiter> {
    Arc::new(
        RateLimiter::new(RateLimiterConfig {
            max_concurrent_probes: 4,
            per_target_rps_limit: 100,
            per_target_burst: 100,
        })
        .unwrap(),
    )
}

fn engagement(scope: Vec<ScopeTarget>) -> Engagement {
    Engagement {
        id: EngagementId::new(),
        tenant_id: TenantId::new(),
        allowed_scope: scope,
        denylist: vec![],
        max_intensity: ScanIntensity::Standard,
    }
}

fn ctx_for(eng: &Engagement, rl: Arc<RateLimiter>) -> ScanContext {
    let scopes = vec![
        KillSwitchScope::Global,
        KillSwitchScope::Tenant(eng.tenant_id),
        KillSwitchScope::Engagement(eng.id),
    ];
    ScanContext {
        tenant_id: eng.tenant_id,
        engagement_id: eng.id,
        intensity: ScanIntensity::Light,
        rate_limiter: rl,
        kill_signal: Arc::new(Notify::new()),
        kill_scopes: scopes,
        deadline: OffsetDateTime::now_utc() + time::Duration::seconds(30),
    }
}

#[tokio::test]
async fn safety_gate_denies_when_scope_violated() {
    let eng = engagement(vec![ScopeTarget::Domain(Fqdn::new("example.com").unwrap())]);
    let req = ScanRequest {
        tenant_id: eng.tenant_id,
        engagement_id: eng.id,
        targets: vec![ScopeTarget::Domain(Fqdn::new("evil.com").unwrap())],
        intensity: ScanIntensity::Light,
    };
    let gate = SafetyGate::new(
        Arc::new(InMemoryScopeValidator),
        Arc::new(InMemoryKillSwitch::new()),
    );
    let r = gate.check(&eng, &req).await;
    assert!(matches!(r, Err(DiscoveryError::SafetyGate(_))));
}

#[tokio::test]
async fn safety_gate_denies_when_killswitch_tripped() {
    let eng = engagement(vec![ScopeTarget::Domain(Fqdn::new("example.com").unwrap())]);
    let req = ScanRequest {
        tenant_id: eng.tenant_id,
        engagement_id: eng.id,
        targets: vec![ScopeTarget::Domain(Fqdn::new("example.com").unwrap())],
        intensity: ScanIntensity::Light,
    };
    let switch = InMemoryKillSwitch::new();
    switch.trip(&KillSwitchScope::Engagement(eng.id));
    let gate = SafetyGate::new(Arc::new(InMemoryScopeValidator), Arc::new(switch));
    assert!(matches!(
        gate.check(&eng, &req).await,
        Err(DiscoveryError::KillSwitchTripped),
    ));
}

#[tokio::test]
async fn tcp_port_probe_emits_open_port_for_listening_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // Spawn an accept loop so connect succeeds — we never write anything,
    // which still lets the probe observe "open" without a banner.
    tokio::spawn(async move {
        while let Ok((_sock, _)) = listener.accept().await {
            // Drop the socket; the probe will observe an open port with no
            // banner (since we don't speak first).
        }
    });

    let scanner = TcpPortProbeScanner::new(TcpPortProbeConfig {
        ports: vec![port],
        connect_timeout: Duration::from_secs(2),
        banner_read_timeout: Duration::from_millis(200),
        max_banner_bytes: 256,
    })
    .unwrap();
    let eng = engagement(vec![ScopeTarget::Ip("127.0.0.1".parse().unwrap())]);
    let target = ScopeTarget::Ip("127.0.0.1".parse().unwrap());
    let result = scanner
        .scan(ctx_for(&eng, rate_limiter()), target)
        .await
        .unwrap();
    assert!(
        result
            .observations
            .iter()
            .any(|o| matches!(o, Observation::OpenPort { port: p, .. } if *p == port)),
        "expected open port {port} observation, got {:?}",
        result.observations,
    );
}

#[tokio::test]
async fn tcp_port_probe_emits_nothing_for_closed_port() {
    // Bind then drop to find a guaranteed-closed port.
    let port = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let scanner = TcpPortProbeScanner::new(TcpPortProbeConfig {
        ports: vec![port],
        connect_timeout: Duration::from_millis(200),
        banner_read_timeout: Duration::from_millis(100),
        max_banner_bytes: 256,
    })
    .unwrap();
    let eng = engagement(vec![ScopeTarget::Ip("127.0.0.1".parse().unwrap())]);
    let target = ScopeTarget::Ip("127.0.0.1".parse().unwrap());
    let result = scanner
        .scan(ctx_for(&eng, rate_limiter()), target)
        .await
        .unwrap();
    assert!(
        result.observations.is_empty(),
        "closed port should produce no observations, got {:?}",
        result.observations,
    );
}

#[tokio::test]
async fn http_fingerprint_captures_server_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("server", "nginx/1.27")
                .insert_header("x-powered-by", "PHP/8.3"),
        )
        .mount(&server)
        .await;

    let scanner = HttpFingerprintScanner::new(HttpFingerprintConfig {
        user_agent: "sentinelx-test/1.0".into(),
        request_timeout: Duration::from_secs(5),
        max_redirects: 0,
        default_scheme: "http".into(),
    })
    .unwrap();
    let target = ScopeTarget::Url(url::Url::parse(&server.uri()).unwrap());
    let eng = engagement(vec![target.clone()]);
    let result = scanner
        .scan(ctx_for(&eng, rate_limiter()), target)
        .await
        .unwrap();
    let mut saw_server = false;
    let mut saw_framework = false;
    for obs in &result.observations {
        if let Observation::HttpResponse {
            server, framework, ..
        } = obs
        {
            if server.as_deref() == Some("nginx/1.27") {
                saw_server = true;
            }
            if framework.as_deref() == Some("PHP/8.3") {
                saw_framework = true;
            }
        }
    }
    assert!(saw_server, "expected nginx server header");
    assert!(saw_framework, "expected PHP framework header");
}

#[tokio::test]
async fn http_fingerprint_strips_set_cookie_value() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "session=topsecretvalue; HttpOnly")
                .insert_header("set-cookie", "tracking=anothersecret"),
        )
        .mount(&server)
        .await;

    let scanner = HttpFingerprintScanner::new(HttpFingerprintConfig {
        user_agent: "sentinelx-test/1.0".into(),
        request_timeout: Duration::from_secs(5),
        max_redirects: 0,
        default_scheme: "http".into(),
    })
    .unwrap();
    let target = ScopeTarget::Url(url::Url::parse(&server.uri()).unwrap());
    let eng = engagement(vec![target.clone()]);
    let result = scanner
        .scan(ctx_for(&eng, rate_limiter()), target)
        .await
        .unwrap();
    // Find HttpResponse observations. The main response should not contain
    // an exact `set-cookie` header with the raw value; the redacted
    // synthetic observation should mention the count.
    let mut found_redacted = false;
    let mut found_raw = false;
    for obs in &result.observations {
        if let Observation::HttpResponse { headers, .. } = obs {
            for (k, v) in headers {
                if k == "set-cookie" {
                    if v.starts_with("<redacted") {
                        found_redacted = true;
                    } else if v.contains("topsecretvalue") || v.contains("anothersecret") {
                        found_raw = true;
                    }
                }
            }
        }
    }
    assert!(!found_raw, "raw set-cookie value leaked into storage");
    assert!(
        found_redacted,
        "expected a redacted set-cookie placeholder observation",
    );
}

#[tokio::test]
async fn dns_resolver_requires_explicit_resolvers() {
    let r = DnsResolverScanner::new(DnsScannerConfig {
        resolvers: vec![],
        query_timeout: Duration::from_secs(1),
    });
    assert!(matches!(r, Err(DiscoveryError::Config(_))));
}

#[tokio::test]
async fn rate_limiter_blocks_above_budget() {
    let lim = Arc::new(
        RateLimiter::new(RateLimiterConfig {
            max_concurrent_probes: 4,
            per_target_rps_limit: 1,
            per_target_burst: 1,
        })
        .unwrap(),
    );
    let _p = lim.acquire("target").await.unwrap();
    assert!(matches!(
        lim.acquire("target").await,
        Err(DiscoveryError::RateLimited),
    ));
}

#[tokio::test]
async fn scanner_registry_lookup_by_id() {
    let cfg = DnsScannerConfig {
        resolvers: vec!["1.1.1.1:53".parse().unwrap()],
        query_timeout: Duration::from_secs(1),
    };
    let scanner = Arc::new(DnsResolverScanner::new(cfg).unwrap());
    let mut registry = ScannerRegistry::new();
    let id = scanner.id();
    RegisterScannerUseCase::new(&mut registry)
        .execute(scanner)
        .unwrap();
    let got = registry.lookup(&id).unwrap();
    assert_eq!(got.id(), id);
}

#[tokio::test]
async fn kill_switch_aborts_in_flight_scan() {
    // Build a "slow scanner" that blocks on the kill signal directly,
    // emulating a scanner that yields cleanly on cancellation.
    #[derive(Debug)]
    struct SlowScanner;

    #[async_trait]
    impl Scanner for SlowScanner {
        fn id(&self) -> ScannerId {
            ScannerId::new("slow_scanner_v1")
        }
        fn capabilities(&self) -> ScannerCapabilities {
            ScannerCapabilities {
                max_intensity: ScanIntensity::Standard,
                target_kinds: std::iter::once(TargetKind::Domain).collect(),
                max_throughput_obs_per_sec: 1,
            }
        }
        async fn scan(
            &self,
            ctx: ScanContext,
            target: ScopeTarget,
        ) -> Result<ScanResult, DiscoveryError> {
            // Block until the kill signal fires or 5s elapses.
            tokio::select! {
                () = ctx.kill_signal.notified() => Err(DiscoveryError::KillSwitchTripped),
                () = tokio::time::sleep(Duration::from_secs(5)) => Ok(ScanResult {
                    scanner_id: self.id(),
                    target,
                    observations: vec![],
                    started_at: OffsetDateTime::now_utc(),
                    ended_at: OffsetDateTime::now_utc(),
                }),
            }
        }
    }

    let eng = engagement(vec![ScopeTarget::Domain(Fqdn::new("example.com").unwrap())]);
    let req = ScanRequest {
        tenant_id: eng.tenant_id,
        engagement_id: eng.id,
        targets: vec![ScopeTarget::Domain(Fqdn::new("example.com").unwrap())],
        intensity: ScanIntensity::Light,
    };
    let switch = Arc::new(InMemoryKillSwitch::new());
    let gate = SafetyGate::new(
        Arc::new(InMemoryScopeValidator),
        Arc::<InMemoryKillSwitch>::clone(&switch),
    );
    let mut registry = ScannerRegistry::new();
    registry.register(Arc::new(SlowScanner)).unwrap();
    let uc = RunDiscoveryUseCase::new(
        Arc::new(registry),
        gate,
        rate_limiter(),
        Duration::from_secs(5),
        1,
    )
    .unwrap();

    let switch_for_trip = Arc::clone(&switch);
    let eng_id = eng.id;
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        switch_for_trip.trip(&KillSwitchScope::Engagement(eng_id));
    });

    let result = tokio::time::timeout(Duration::from_secs(3), uc.execute(&eng, &req, None))
        .await
        .unwrap_or_else(|_| panic!("orchestrator should return within timeout"))
        .unwrap();
    assert!(result.killed || !result.errors.is_empty());
}
