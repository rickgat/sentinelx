import type { HelpCategory } from "./help-types";

/**
 * The 8 category landing pages (plus the implicit `getting-started`
 * quick-start). Each category is mirrored 1:1 against the sidebar
 * grouping so an operator coming from a menu can predict where to find
 * the tutorial.
 */
export const HELP_CATEGORIES: ReadonlyArray<HelpCategory> = [
  {
    slug: "getting-started",
    title: "Getting started",
    summary:
      "Five-minute quick start: log in, kick off your first scan, triage findings, export SARIF.",
    icon: "Rocket",
  },
  {
    slug: "posture",
    title: "Posture: engagements, findings, remediation, reports",
    summary:
      "Plan engagements, triage findings, track remediation MTTR, and ship customer-ready reports.",
    icon: "ClipboardList",
  },
  {
    slug: "discovery",
    title: "Discovery and inventory",
    summary:
      "Scans, vuln ingest, cloud inventory, OCSF logs, compliance frameworks, digital twin, and blast radius.",
    icon: "Compass",
  },
  {
    slug: "identity",
    title: "Identity and access",
    summary:
      "IAM users + roles, MFA enrolment, adaptive RBA, known devices, SCIM provisioning, and tenant switching.",
    icon: "Fingerprint",
  },
  {
    slug: "soc-detection",
    title: "SOC and detection",
    summary:
      "SOC alert queue, OCSF log ingest, UEBA anomalies, two-person approvals, and the platform kill switch.",
    icon: "Siren",
  },
  {
    slug: "offensive",
    title: "Offensive simulation and AI",
    summary:
      "Breach & attack simulation, ATT&CK techniques, red-team workflows, AI Copilot, and HITL approvals.",
    icon: "Sword",
  },
  {
    slug: "governance",
    title: "Governance, analytics, and developer",
    summary:
      "Risk analytics, attack graph, OpenAPI docs, the request playground, and Vault-backed secrets.",
    icon: "Gavel",
  },
  {
    slug: "integrations",
    title: "Integrations and finding fan-out",
    summary:
      "How findings flow into Jira, PagerDuty, Linear, Opsgenie, and ServiceNow via the webhook sinks.",
    icon: "Send",
  },
];
