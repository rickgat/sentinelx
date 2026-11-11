# Telemetry Readiness Checklist (TOP5-#4)

> **Single-page gate.** The production-deployment reviewer ticks every
> box on this page before sign-off. If any box is empty, the
> deployment HOLDS at staging until remediated.
>
> Pairs with `../slos.md`, `../slos-production.md`,
> `./multi-region-deployment.md` §11, and
> `./failover-drill-template.md` §5.

---

## 0. Header

| Field | Value |
| --- | --- |
| Deployment ID | DEP-{YYYY}-{seq} |
| Reviewer | ______ |
| Date (UTC) | ______ |
| Target region(s) | ______ |

---

## 1. Prometheus scrape

- [ ] **Scrape configured** — every `sx-monolith` pod exposes
      `/metrics` on its Prometheus bind address
      (`telemetry.prometheus_bind` per
      `crates/sx-config/src/schema/telemetry.rs:59`). Default port for
      the workspace pattern is **9090**; verify the deployed value
      matches the Prometheus scrape config target list.

      ```bash
      kubectl get pods -n sentinelx -l app=sx-monolith -o name | xargs -I{} \
        kubectl exec -n sentinelx {} -- curl -sS http://127.0.0.1:9090/metrics \
        | head -5
      # expect: "# HELP sx_http_requests_total ..." or similar header
      ```

- [ ] **Scrape interval ≤ 30 s** — burn-rate alerts in `../slos.md`
      §5.2 assume sub-minute samples.

- [ ] **`up{job="sx-monolith"}` = 1** for every pod for ≥ 5 min.

- [ ] **Cardinality guard active** — per-tenant labels are bounded by
      `crates/sx-telemetry/src/cardinality.rs` (DEFAULT_TENANT_LABEL_CAP).
      Verify cap matches deployed tenant count + 25% headroom.

---

## 2. Critical alerts wired

All alert names below MUST be present in the deployed Prometheus
ruleset. The metric strings are the **canonical names from the
codebase** — grep `crates/` and `services/` before renaming any of
these in an alert rule.

- [ ] **`xmldsig_shadow_mismatch_total` rate** — SAML verifier
      regression signal (ADR-0022).

      | Property | Value |
      | --- | --- |
      | Metric | `xmldsig_shadow_mismatch_total` |
      | Source | `crates/sx-xmlsec/src/dual.rs:70` |
      | Threshold | rate > 0.01 / min for 5 min |
      | Page | SecEng on-call |

- [ ] **`sx_findings_ingested_total{status="failed"}`** —
      FOUND-001 insert path health.

      | Property | Value |
      | --- | --- |
      | Metric | `sx_findings_ingested_total` |
      | Source | `crates/sx-telemetry/src/metrics.rs:107` |
      | Threshold | failed-rate > 0.01 / min for 5 min |
      | Page | Backend on-call |

- [ ] **Audit chain break detected** — observer at
      `services/sx-monolith/src/adapters/audit_break_observer.rs`
      emits a finding via FOUND-001 when a chain head reveals a
      gap. The finding is the page-able signal; the metric is its
      counterpart.

      | Property | Value |
      | --- | --- |
      | Signal | `audit_chain.break_detected` event (logged) + finding `rule_id=audit:chain-break` |
      | Source | `services/sx-monolith/src/adapters/audit_break_observer.rs:189` |
      | Threshold | any occurrence in 5-min window |
      | Page | SecEng + IC (P1) |

- [ ] **`log_ingest.rate_limited_total` per tenant** — P2-008 burst
      indicator.

      | Property | Value |
      | --- | --- |
      | Metric | `log_ingest.rate_limited_total` |
      | Source | `crates/sx-log-ingest/src/rate_limit.rs:47` |
      | Threshold | rate > 100 / 5 min per tenant |
      | Page | SOC (informational, feeds detection pipeline) |

- [ ] **`rba_decision_total{action="block"}` per tenant** — RBA
      blocking signal.

      | Property | Value |
      | --- | --- |
      | Metric | `rba_decision_total` |
      | Source | `crates/sx-rba/src/metrics.rs:74` |
      | Threshold | rate > 50 / 5 min per tenant |
      | Page | SOC |

- [ ] **`sx_anchor_last_success_age_seconds`** — audit anchor RPO.

      | Property | Value |
      | --- | --- |
      | Metric | `sx_anchor_last_success_age_seconds` |
      | Source | `docs/slos.md:46` (gauge defined in `crates/sx-audit`) |
      | Threshold | > 86400 (24h) |
      | Page | SecEng (audit chain RPO budget) |

- [ ] **`sx_feed_last_pull_age_seconds`** — threat-intel freshness.

      | Property | Value |
      | --- | --- |
      | Metric | `sx_feed_last_pull_age_seconds` |
      | Source | `docs/slos.md:46`, §3.4 (per-feed freshness SLOs) |
      | Threshold | per-feed (KEV ≤ 30 min, NVD ≤ 4 h, EPSS ≤ 24 h) |
      | Page | Intel on-call |

- [ ] **`sx_killswitch_triggered_total`** — kill-switch fire alarm.

      | Property | Value |
      | --- | --- |
      | Metric | `sx_killswitch_triggered_total` |
      | Source | `crates/sx-telemetry/src/metrics.rs:117` |
      | Threshold | any occurrence |
      | Page | IC + Exec (P0) |

---

## 3. Grafana dashboards present

Every SLO row in `../slos-production.md` §2 must have a Grafana panel
that the reviewer can show during sign-off.

- [ ] Dashboard: **SentinelX — Production SLO Suite**
- [ ] Panel: Login p99 latency (route=`/v1/auth/login`)
- [ ] Panel: Findings list p95 latency (route=`/v1/findings`)
- [ ] Panel: Scan completion p95 (route=`/v1/scans/http-headers`)
- [ ] Panel: SARIF p95 latency (route=`/v1/scans/:id.sarif`)
- [ ] Panel: Audit anchor age (`sx_anchor_last_success_age_seconds`)
- [ ] Panel: XMLDSig shadow mismatch counter
- [ ] Panel: Findings ingested rate (success vs. failed split)
- [ ] Panel: Per-tenant rate-limit rejects
- [ ] Panel: Per-tenant RBA decision mix (allow / step_up_mfa / block)

Dashboard URLs (one per panel) recorded in the deployment-record
ticket. Reviewer initials beside each: ______

---

## 4. Log shipping

- [ ] **OTLP endpoint set** — `telemetry.otlp_endpoint`
      (`crates/sx-config/src/schema/telemetry.rs:55`) configured to
      the deployed collector. Default scheme: `grpc://` (per the
      schema doc-string).
- [ ] **Sample ratio set** — `telemetry.sample_ratio` (§63 of same
      schema file) at the per-environment value. Production
      recommendation: 0.1 for traces, 1.0 for warn/error.
- [ ] **Log format = `json`** — `telemetry.log_format` per
      `crates/sx-config/src/schema/telemetry.rs:51`. Pretty/text is
      dev-only.
- [ ] **Log retention** — 30 days hot, 90 days warm per workspace
      policy.
- [ ] **PII/secret scrubbing** — `crates/sx-secrets::redactor` wired
      into the log pipeline (verify via `RUST_LOG=trace` smoke that
      no PHC / no token bytes appear in shipped logs).

---

## 5. On-call

- [ ] **Rotation defined** for every page tier in §2 above
      (SecEng, Backend, SOC, IC, Intel).
- [ ] **PagerDuty schedule** named consistently with the team
      (`sentinelx-secops`, `sentinelx-backend`, etc.) — visible in
      `incident-response.md`.
- [ ] **Escalation policy** — primary on-call → backup on-call → IC.
- [ ] **Pre-deployment handshake** — current on-call paged once with
      a test alert; ack recorded.

---

## 6. Runbook URLs in alert payloads

Every alert defined in §2 carries a `runbook_url` annotation
pointing at the corresponding markdown anchor. The deployment
reviewer manually opens at least one alert's runbook link and
verifies it lands on the correct anchor.

- [ ] `xmldsig_shadow_mismatch_total` → runbook: ADR-0022 + SAML
      attack detail in `incident-response.md`.
- [ ] `findings_insert_failed` → `incident-response.md` §FOUND-001.
- [ ] `audit_chain_break_detected` → `audit-chain-compromise.md`.
- [ ] `rate_limited_total burst` → `incident-response.md` §rate-limit.
- [ ] `rba_block burst` → `rba-decision-investigation.md`.
- [ ] `anchor_last_success_age_seconds` → `audit-chain-compromise.md`.
- [ ] `killswitch_triggered_total` → `incident-response.md` §kill-switch.

---

## 7. Sign-off

The reviewer ticks every box above, signs, and attaches this filled
checklist to the deployment-record ticket. Any unticked box = HOLD.

| Reviewer | Sign-off (UTC) |
| --- | --- |
| ______ | __:__ |

---

## 8. Change Log

| Date | Change | Author |
| --- | --- | --- |
| 2026-06-25 | Initial telemetry-readiness checklist (TOP5-#4) — references canonical metric strings from the codebase | Platform Engineering / TOP5-#4 |
