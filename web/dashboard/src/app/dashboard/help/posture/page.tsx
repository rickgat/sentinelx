import { redirect } from "next/navigation";

import { getAccessToken } from "@/lib/server-fetch";

import { HelpCategoryLayout } from "../help-layout";
import type { MenuTutorial } from "../help-types";

/**
 * Posture category — covers the four operational menus that own the
 * security finding lifecycle plus the two detail sub-routes that fall
 * out of them.
 *
 * Routes covered:
 *   - /dashboard/engagements
 *   - /dashboard/engagements/[id]
 *   - /dashboard/findings
 *   - /dashboard/findings/[id]
 *   - /dashboard/remediation
 *   - /dashboard/reports
 */
const TUTORIALS: ReadonlyArray<MenuTutorial> = [
  {
    id: "engagements",
    title: "Engagements",
    route: "/dashboard/engagements",
    purpose:
      "Engagements are time-boxed scopes of work — a single pentest, a quarterly internal review, a customer-facing assessment. Every finding is owned by exactly one engagement so audit trails stay clean.",
    whenToUse: [
      "When you start a new pentest or assessment cycle and need a container for its scope, dates, and reports.",
      "When you need to filter the platform's other menus (BAS, Reports, Red Team) by a single engagement.",
      "When a customer asks for the canonical list of work performed during a period.",
    ],
    workflow: [
      "Click 'New engagement' and fill the form: name, scope description, start / end dates.",
      "Submit — the row appears in the table with status 'draft'.",
      "Open the engagement detail page to schedule it (`scheduled` → `active`) once approvals land.",
      "When work wraps, transition to `completed`; the engagement becomes read-only and is locked for the auditor.",
      "Export the final report from the Reports menu, scoped to the engagement id.",
    ],
    inputs: [
      "`GET /v1/engagements?limit=200` — list source (SSR-rendered).",
      "`POST /v1/engagements` — create flow.",
      "Engagement state machine: draft → scheduled → active → completed / aborted / cancelled.",
    ],
    outputs: [
      "Engagement rows referenceable from Findings, Reports, BAS, Red Team.",
      "Audit log of every status transition (read via the activity panel on the detail page).",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "Why can't I delete an engagement?",
        a: "Engagements are append-only by design (audit requirement). Use the `cancelled` or `aborted` terminal status instead — both preserve the audit history.",
      },
      {
        q: "Can a finding belong to two engagements?",
        a: "No. The data model enforces a single owning engagement. If you need to attribute the same finding to a second cycle, clone the finding into the new engagement and link them via the `parent_finding_id` cross-reference.",
      },
    ],
    references: [
      { label: "Engagement detail", href: "/dashboard/help/posture#engagement-detail" },
      { label: "/dashboard/reports", href: "/dashboard/reports" },
      { label: "Help: Discovery", href: "/dashboard/help/discovery" },
    ],
  },
  {
    id: "engagement-detail",
    title: "Engagement detail",
    route: "/dashboard/engagements/[id]",
    purpose:
      "The engagement detail view shows the scope, current status, owner, and the action buttons (schedule, activate, abort) needed to advance the engagement through its lifecycle.",
    whenToUse: [
      "When you need to advance an engagement's status (draft → scheduled → active → completed).",
      "When you need to attach scope notes or read the audit trail of transitions.",
      "When you're preparing a customer hand-off and need a single page summarising the engagement.",
    ],
    workflow: [
      "Click any engagement row from the list to open the detail page.",
      "Confirm scope, dates, and assigned operator on the header card.",
      "Use the action panel to advance status — buttons gate themselves to legal transitions.",
      "Read the activity log at the bottom to confirm the transition was recorded.",
    ],
    inputs: [
      "`GET /v1/engagements/{id}` — single record load (notFound on 404).",
      "Status transition API: `POST /v1/engagements/{id}/transition`.",
    ],
    outputs: [
      "Status update + audit row.",
      "Side-effect refresh of any list view filtered by this engagement.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "Why is the 'Activate' button disabled?",
        a: "Activation requires two-person approval (PRD §6A.4). Submit the approval request from the **Approvals** menu first; the button re-enables once the second operator signs off.",
      },
    ],
    references: [
      { label: "/dashboard/approvals", href: "/dashboard/approvals" },
      { label: "Help: SOC + Detection", href: "/dashboard/help/soc-detection" },
    ],
  },
  {
    id: "findings",
    title: "Findings",
    route: "/dashboard/findings",
    purpose:
      "The Findings menu is the day-to-day triage surface: every security issue raised by any scanner, ingest, or simulation lands in this table for prioritisation.",
    whenToUse: [
      "After a scan completes — to triage the new rows and assign severity.",
      "When responding to an ingest from an external scanner (Vuln Import).",
      "When preparing a report — to filter and confirm the inventory for the engagement.",
    ],
    workflow: [
      "Open Findings. The table shows columns Severity, Title, Asset, Status, First seen.",
      "Use the status tab strip (all / open / triaged / in_progress / resolved / false_positive / accepted / closed) to narrow the queue.",
      "Click a row's 'View →' link to open the detail page and read the full description + suggested fix.",
      "Update status (triage, mark in-progress, resolve) — every change appends to the finding's audit history.",
      "Once resolved, the Remediation menu picks the row up automatically to compute MTTR.",
    ],
    inputs: [
      "`GET /v1/findings?limit=200` — SSR snapshot for the table.",
      "Vuln Import + Scans + BAS pipelines deposit rows into this collection.",
      "Predictive Panel (right-rail) reads from `/v1/findings/predict`.",
    ],
    outputs: [
      "Status mutations feed Remediation and the SARIF export.",
      "Triage decisions become part of the engagement's audit chain.",
      "Cross-fanout to ticketing sinks (Jira / PagerDuty / Linear / Opsgenie / ServiceNow) is triggered on `open → triaged` if the integration is enabled.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "What is the 'accepted' status for?",
        a: "Use `accepted` when leadership has signed off on living with the risk (e.g. a low-severity finding the business explicitly tolerates). Closed findings reopen on regression; accepted findings do not — see Remediation for regression handling.",
      },
      {
        q: "Why doesn't my finding show up in Jira?",
        a: "Fan-out only fires on the `open → triaged` transition and only if the Jira sink is enabled for the tenant. Check **Integrations** in this Help section + confirm the sink in `crates/sx-webhooks/src/jira.rs` has credentials provisioned.",
      },
    ],
    references: [
      { label: "Finding detail", href: "/dashboard/help/posture#finding-detail" },
      { label: "/dashboard/remediation", href: "/dashboard/remediation" },
      { label: "Help: Integrations", href: "/dashboard/help/integrations" },
    ],
  },
  {
    id: "finding-detail",
    title: "Finding detail",
    route: "/dashboard/findings/[id]",
    purpose:
      "The finding detail surface is the canonical source-of-truth for a single issue: severity badge, status badge, description, recommended fix, source artefact, and the full audit trail of every status transition.",
    whenToUse: [
      "When you need to triage, comment on, or resolve a specific finding.",
      "When the engagement report references a finding and you need to verify its current state.",
      "When you're disputing severity and need to read the full original description.",
    ],
    workflow: [
      "Click 'View →' on any finding row.",
      "Confirm severity (badge in `critical | high | medium | low | info`) and status (`open | triaged | in_progress | resolved | false_positive | accepted | closed`).",
      "Read the description, source artefact link, and recommended fix.",
      "Use the action buttons to advance status; the page refetches after each transition.",
    ],
    inputs: [
      "`GET /v1/findings/{id}` — single-row load.",
      "Audit trail: `GET /v1/findings/{id}/history`.",
    ],
    outputs: [
      "Status transition events, surfaced both here and in Remediation analytics.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "Can I edit a finding's title or description?",
        a: "Only `analyst` and above can adjust the title; the description is immutable once the finding was ingested (preserves source provenance). To clarify, add a comment instead.",
      },
    ],
    references: [
      { label: "/dashboard/findings", href: "/dashboard/findings" },
      { label: "/dashboard/remediation", href: "/dashboard/remediation" },
    ],
  },
  {
    id: "remediation",
    title: "Remediation outcomes",
    route: "/dashboard/remediation",
    purpose:
      "The Remediation page summarises remediation effectiveness across the tenant: MTTR per severity bucket, headline regression rate, and the top regressing `check_id`s. It's the answer to 'are we actually fixing things?'.",
    whenToUse: [
      "Weekly, as a leadership-facing posture review.",
      "When a regression alert fires and you need to know which check is misbehaving.",
      "When you're sizing remediation engineering capacity for next sprint.",
    ],
    workflow: [
      "Open Remediation. Three panels render: MTTR by severity, headline regression rate, top regressing checks.",
      "Confirm the window selector (default 30 days) reflects the period you care about.",
      "Inspect MTTR: critical / high should be in hours; medium / low can be days.",
      "Check the regression list — any check_id with regression_count > 0 across the window deserves a follow-up.",
      "Click into the offending check to open the underlying findings in the Findings menu.",
    ],
    inputs: [
      "`GET /v1/remediation/outcomes/metrics?window_days={n}` — MTTR + regression aggregate.",
      "`GET /v1/remediation/outcomes/regressions?limit=25` — top regressing checks.",
    ],
    outputs: [
      "Read-only — no mutations. Drives ops planning + leadership comms.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "MTTR is stored as seconds — why does the UI say 'days / hours'?",
        a: "The page converts seconds to the most human-readable unit. The underlying value is exact; the rendering is rounded for readability.",
      },
      {
        q: "What counts as a 'regression'?",
        a: "A finding that was previously `resolved` or `closed` and re-opened due to a re-scan detecting the same issue. The `accepted` status is excluded from regression accounting.",
      },
    ],
    references: [
      { label: "/dashboard/findings", href: "/dashboard/findings" },
      { label: "/dashboard/analytics", href: "/dashboard/analytics" },
      { label: "Help: Governance", href: "/dashboard/help/governance" },
    ],
  },
  {
    id: "reports",
    title: "Reports",
    route: "/dashboard/reports",
    purpose:
      "Generate customer-ready report bundles scoped to an engagement. Supports plaintext executive summary, technical PDF, and SARIF for ingest into customer tooling.",
    whenToUse: [
      "At the end of an engagement, when you owe the customer a final deliverable.",
      "Mid-engagement, for an interim status report.",
      "Whenever you need to hand SARIF off to a third-party scanner or aggregator.",
    ],
    workflow: [
      "Open Reports. The form shows the engagement dropdown.",
      "Pick the engagement to scope the report to.",
      "Choose format: executive summary, technical PDF, SARIF.",
      "Click 'Generate' — the bundle is materialised server-side and returned as a download link.",
      "Forward the link to the customer or attach to the engagement record.",
    ],
    inputs: [
      "`GET /v1/engagements?limit=200` — dropdown source.",
      "`POST /v1/reports/render` — generation endpoint (returns a manifest + signed URL).",
    ],
    outputs: [
      "Executive summary PDF, technical PDF, or SARIF (per FSD §4.9).",
      "An audit-trail entry against the engagement.",
    ],
    roles: ["analyst", "admin"],
    faqs: [
      {
        q: "Why is the SARIF export missing some findings?",
        a: "SARIF only includes findings tied to source artefacts (file path + line). Findings without a source location (e.g. infra misconfig) are emitted into the PDF but skipped by SARIF — see `docs/finding-enrichment.md`.",
      },
      {
        q: "Can I customise the PDF template?",
        a: "Templates are versioned under `crates/sx-reports/templates/`. Ask an admin to enable a custom template for your tenant; the dropdown will show it once provisioned.",
      },
    ],
    references: [
      { label: "/dashboard/engagements", href: "/dashboard/engagements" },
      { label: "/dashboard/findings", href: "/dashboard/findings" },
      { label: "Help: Integrations", href: "/dashboard/help/integrations" },
    ],
  },
];

export default async function PostureHelpPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }
  return (
    <HelpCategoryLayout
      category="posture"
      title="Posture: engagements, findings, remediation, reports"
      intro="The four menus that own the security finding lifecycle, from creating an engagement scope through to handing the customer a SARIF bundle. Read top-to-bottom for the canonical 'first pentest' walkthrough."
      tutorials={TUTORIALS}
    />
  );
}
