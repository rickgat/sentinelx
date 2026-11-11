# SentinelX Runbooks

> **Last reviewed:** 2026-06-13
> **Maintainer:** Platform Engineering (`sre-lead@sentinelx.example`)
> **Review cadence:** Each runbook carries its own cadence in its header.
> **Classification:** Internal — Restricted

This directory holds the operational runbooks for SentinelX — the documents
that the on-call rotation, the IC, and the platform team reach for when
something is on fire or about to be.

A runbook here is **executable knowledge**, not a marketing artifact. If a
runbook contains a command, that command must work today. If it contains an
RTO, that RTO must match what the customer SLA says. Drift between a runbook
and reality is a P1 documentation bug.

---

## Index

| Runbook | When to open it | Owner | Review cadence |
| --- | --- | --- | --- |
| [`breach-notification.md`](./breach-notification.md) | Confirmed customer-data exposure; regulator notification clock has started (GDPR 72 h, UU PDP 3×24 h, PDPA SG 72 h) | CCO + Legal + Security | Bimonthly |
| [`disaster-recovery.md`](./disaster-recovery.md) | Loss (or credible threat of loss) of an entire AZ, region, or data tier | SRE Lead | Quarterly |
| [`disaster-recovery-drill-template.md`](./disaster-recovery-drill-template.md) | Template for the quarterly DR drill required by SOC 2 CC7.5 / ISO 27001 A.5.30 / PCI DSS 12.10.1 | SRE Lead | Per drill |
| [`finops.md`](./finops.md) | Cost anomaly, budget review, capacity planning; ClickHouse + Neo4j + KMS + WORM cost modelling | FinOps | Quarterly |
| [`incident-response.md`](./incident-response.md) | Customer-impacting incident below the DR threshold; dispatches a **P3-004 IR playbook** (ransomware / data-exfil / credential-compromise / insider) | IC + SRE | Quarterly |
| [`multi-region-deployment.md`](./multi-region-deployment.md) | Steady-state multi-region operation, planned region cutover, tenant topology change (P2-010) | Platform Eng | Quarterly |
| [`supply-chain.md`](./supply-chain.md) | Triage a RUSTSEC advisory, ignore-with-justification flow, SBOM signature verification (LOW-001) | Security Eng | Quarterly |

---

## Conventions

Every runbook in this directory follows the same skeleton:

1. **Header block** — last-reviewed date, maintainer, next review, classification.
2. **Purpose & scope** — what triggers the runbook, what is *not* covered.
3. **Targets / objectives** — measurable, mapped to customer SLA where applicable.
4. **Architecture / topology context** — only what is needed to make the
   procedures comprehensible.
5. **Procedures** — numbered, with exact commands, expected outputs, and
   failure branches.
6. **Risk register / change log** — what we are watching for and what changed.

If you are writing a new runbook, copy the skeleton from
[`disaster-recovery.md`](./disaster-recovery.md) — it is the most mature.

---

## Relationship to the rest of the docs

- **Architecture** is captured by the top-level `docs/ARCHITECTURE.md` and the ADR set in [`../adr/`](../adr/).
- **Security controls and policies** live in [`../security/`](../security/) — STRIDE threat model, supply chain, bug bounty bridge (P3-010), internal red team.
- **Per-component operations playbooks** (smaller-scope, single-service)
  live in [`../operations/`](../operations/):
  - [`compliance-evidence.md`](../operations/compliance-evidence.md) — P1-004 evidence collector flow
  - [`gitops.md`](../operations/gitops.md) — ArgoCD + Argo Rollouts
  - [`runbook.md`](../operations/runbook.md) — boot, kill-switch, KEK rotation, TSA fallback, RLS verification
  - [`runtime-security.md`](../operations/runtime-security.md) — P2-016 Falco + OCSF
- **Compliance** maps live in [`../compliance/`](../compliance/):
  - [`pci-dss-v4-mapping.md`](../compliance/pci-dss-v4-mapping.md) — every requirement → SentinelX capability
  - [`gdpr-pdp-dpia.md`](../compliance/gdpr-pdp-dpia.md) — DPIA + RoPA + DSR workflow
  - [`engagement-roe-template.md`](../compliance/engagement-roe-template.md) — engagement RoE template w/ safety pipeline
- **Task / gap register** is [`../SECURITY_GAP_REMEDIATION_TASKS.md`](../SECURITY_GAP_REMEDIATION_TASKS.md); each runbook is owned by one or more task IDs.

---

## Drill calendar

Runbooks must be exercised, not just maintained. The standing drill calendar:

| Quarter | Drill | Runbook exercised |
| --- | --- | --- |
| Q1 | Region drain + promote | `multi-region-deployment.md`, `disaster-recovery.md` |
| Q2 | Backup restore (Postgres PITR, ClickHouse snapshot) | `disaster-recovery.md` |
| Q3 | Tabletop: customer breach with regulator notification | `breach-notification.md`, `incident-response.md` |
| Q4 | Full DR — destroy primary region in staging, run on DR only for 24 h | `disaster-recovery.md`, `multi-region-deployment.md` |

Drill outcomes are filed under `docs/drills/{yyyy-qN}/` and feed back into
the runbook change logs.

