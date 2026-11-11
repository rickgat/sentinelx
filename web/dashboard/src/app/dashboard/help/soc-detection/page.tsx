import { redirect } from "next/navigation";

import { getAccessToken } from "@/lib/server-fetch";

import { HelpCategoryLayout } from "../help-layout";
import type { MenuTutorial } from "../help-types";

/**
 * SOC + Detection category — the live operational layer.
 *
 * Routes covered (5):
 *   - /dashboard/soc
 *   - /dashboard/logs
 *   - /dashboard/ueba
 *   - /dashboard/approvals
 *   - /dashboard/safety
 */
const TUTORIALS: ReadonlyArray<MenuTutorial> = [
  {
    id: "soc",
    title: "SOC alerts",
    route: "/dashboard/soc",
    purpose:
      "The live SOC alert feed: the correlator's output, ranked by severity, with 30-second polling so the queue stays current without a manual refresh.",
    whenToUse: [
      "As your day-job home page when you're the on-call analyst.",
      "When a downstream sink (Slack, PagerDuty) pings you about an incident — to confirm the corresponding alert.",
      "Auditing the correlation logic — are we generating too many or too few alerts?",
    ],
    workflow: [
      "Open SOC. The page SSRs the initial buffer and polls `/api/soc/alerts` every 30s.",
      "Triage alerts top-down (highest severity first).",
      "Click an alert to expand its evidence (raw events that triggered the correlation).",
      "Acknowledge, escalate, or close — each transition is recorded.",
      "Cross-reference the corresponding Finding (if the alert points at a known check) for context.",
    ],
    inputs: [
      "`GET /v1/soc/alerts` — initial SSR snapshot.",
      "`GET /api/soc/alerts` (dashboard proxy) — client polling every 30s.",
      "Upstream correlator reads OCSF events from the log ring.",
    ],
    outputs: [
      "Alert state changes (acknowledged, escalated, closed).",
      "Downstream fan-out to PagerDuty / Slack via configured webhook sinks.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "Why are there so many low-severity alerts?",
        a: "The correlator runs in a permissive mode by default to catch tuning regressions early. Raise the threshold or mute specific rules via the admin endpoint — there is no UI toggle yet.",
      },
      {
        q: "How is severity determined?",
        a: "Each correlation rule has a baseline severity; the runtime can promote it based on context (e.g. blast radius of the target asset). Read the alert evidence for the per-rule trace.",
      },
    ],
    references: [
      { label: "/dashboard/logs", href: "/dashboard/logs" },
      { label: "/dashboard/ueba", href: "/dashboard/ueba" },
      { label: "Help: Integrations", href: "/dashboard/help/integrations" },
    ],
  },
  {
    id: "logs",
    title: "OCSF log ingest",
    route: "/dashboard/logs",
    purpose:
      "Browse the per-tenant ring buffer of OCSF-normalised events, and submit ad-hoc events manually via the ingest form for testing or backfill.",
    whenToUse: [
      "When a SOC alert needs raw event context to triage.",
      "When validating a new ingest pipeline (cloud connector, agent) is shipping events correctly.",
      "When testing a correlation rule — you can hand-craft events here.",
    ],
    workflow: [
      "Open Logs. The most recent 50 events render SSR.",
      "Click 'Refresh' to poll for new events.",
      "Click 'Ingest event' to open the manual form; paste an OCSF JSON document and submit.",
      "Successfully ingested events appear in the ring within seconds and are visible to the correlator + UEBA scorers.",
    ],
    inputs: [
      "`GET /v1/logs?limit=50` — read.",
      "`POST /api/logs/ingest` — manual write.",
      "Upstream connectors (Auditd, CloudTrail, syslog) write directly to the ring via the sx-api ingest endpoint.",
    ],
    outputs: [
      "Events visible to SOC correlation + UEBA baseline.",
      "Audit log entry for every manual ingest.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "Why is the ring empty?",
        a: "Either no connectors are configured or the ring's retention window has elapsed. Default retention is the last N seconds (configurable). Tail `logs`-prefixed events via the API for offline inspection.",
      },
      {
        q: "Can I export the ring?",
        a: "Not from the UI yet. Use `GET /v1/logs?limit=N` directly to pull pages, or ask an admin to enable archival shipping to S3.",
      },
    ],
    references: [
      { label: "/dashboard/soc", href: "/dashboard/soc" },
      { label: "/dashboard/ueba", href: "/dashboard/ueba" },
    ],
  },
  {
    id: "ueba",
    title: "UEBA anomalies",
    route: "/dashboard/ueba",
    purpose:
      "User + Entity Behavioural Analytics: sort the highest-signal anomalies first, drill into a row to inspect the user's baseline, and decide whether to escalate.",
    whenToUse: [
      "Every morning, as a behavioural-anomaly review pass.",
      "When the SOC raises an alert that the analyst suspects is behavioural — to cross-check the baseline.",
      "When tuning the baseline scorer — to see whether the score distribution looks reasonable.",
    ],
    workflow: [
      "Open UEBA. Anomalies render sorted by score descending, tie-broken by detected_at descending.",
      "Inspect the top row — score, user, anomaly kind.",
      "Click the row to fetch the per-user baseline (the client fetches on demand).",
      "Compare current behaviour against the baseline window — large delta means investigate.",
      "Escalate via SOC if warranted; mark as expected if the user has legitimate cause (travel, role change).",
    ],
    inputs: [
      "`GET /v1/ueba/anomalies?limit=200` — anomaly list (sorted server-side).",
      "`GET /v1/ueba/baseline/{user_id}` — per-user baseline on demand.",
    ],
    outputs: [
      "Anomaly status (open / acknowledged / dismissed) feeds the next baseline iteration.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "Why does a brand new user show a high score?",
        a: "With no baseline history, every action is novel and scores high. The scorer's cold-start handling assigns a damped score for the first N actions — see UEBA docs.",
      },
      {
        q: "What does 'detected_at' mean?",
        a: "The wall-clock time the anomaly was emitted, not the time of the underlying event. Latency between event and anomaly is typically sub-minute.",
      },
    ],
    references: [
      { label: "/dashboard/soc", href: "/dashboard/soc" },
      { label: "/dashboard/logs", href: "/dashboard/logs" },
      { label: "/dashboard/rba", href: "/dashboard/rba" },
    ],
  },
  {
    id: "approvals",
    title: "Two-person approvals",
    route: "/dashboard/approvals",
    purpose:
      "Request and grant two-person approval for high-risk operations (engagement activation, destructive admin actions). The platform's HITL gate for sensitive workflows.",
    whenToUse: [
      "When transitioning an engagement to `active` — the second-person sign-off lives here.",
      "When an admin action triggers a four-eyes policy.",
      "When you're the second approver and got a notification.",
    ],
    workflow: [
      "Open Approvals. The page lists engagement-scoped approval requests.",
      "If you're the requester: pick the engagement, fill the form, submit. The page captures your email automatically.",
      "If you're the approver: review the pending row and click Approve or Reject.",
      "The underlying operation completes once the second approval lands.",
    ],
    inputs: [
      "`GET /v1/engagements?limit=200` — engagement source for the form.",
      "`POST /v1/approvals` — request.",
      "`POST /v1/approvals/{id}/decide` — approve/reject.",
    ],
    outputs: [
      "Approval decisions become preconditions for the gated operation.",
      "Every decision is audit-logged.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "Can I approve my own request?",
        a: "No. The approver email must differ from the requester email — the API rejects same-email approvals with a 422.",
      },
      {
        q: "What if the approver is on holiday?",
        a: "Any operator with the same role can approve. There's no hard-coded approver assignment — the policy is 'any qualified second operator'.",
      },
    ],
    references: [
      { label: "/dashboard/engagements", href: "/dashboard/engagements" },
      { label: "/dashboard/copilot-approvals", href: "/dashboard/copilot-approvals" },
      { label: "/dashboard/safety", href: "/dashboard/safety" },
    ],
  },
  {
    id: "safety",
    title: "Safety and kill switch",
    route: "/dashboard/safety",
    purpose:
      "The platform's emergency stop. Tripping safety halts every active scan, BAS run, copilot action, and ingest pipeline. Use only when something has gone catastrophically wrong.",
    whenToUse: [
      "When a runaway BAS run is hammering production.",
      "When a misconfigured ingest is shipping sensitive data.",
      "When customer impact is imminent and you need to buy time.",
    ],
    workflow: [
      "Open Safety. The big red 'Trip kill switch' button is the only affordance.",
      "Click it. The confirmation dialog opens.",
      "Enter a reason (minimum 4 characters — the API rejects shorter).",
      "Submit. The platform broadcasts a halt signal to every worker.",
      "Once the situation is contained, an admin issues `POST /v1/safety/reset` (no UI button — it's CLI-only).",
    ],
    inputs: [
      "`POST /api/safety/trip` — body `{ reason: string }`.",
      "Reset is admin-only via the CLI (`sx safety reset`).",
    ],
    outputs: [
      "Every active worker stops at the next safe point.",
      "Audit log entry capturing who tripped and why.",
      "PagerDuty / Slack notification to the operations team.",
    ],
    roles: ["ops", "admin"],
    faqs: [
      {
        q: "Will tripping safety lose in-flight data?",
        a: "Workers halt at the next safe point — partial state is persisted but not necessarily complete. Plan to re-run any halted scan / BAS run after the reset.",
      },
      {
        q: "Why is there no reset button?",
        a: "Reset is deliberately CLI-only so an operator can't double-tap by mistake. Run `sx safety reset --reason '<text>'` from a trusted shell.",
      },
    ],
    references: [
      { label: "/dashboard/approvals", href: "/dashboard/approvals" },
      { label: "/dashboard/copilot-approvals", href: "/dashboard/copilot-approvals" },
    ],
  },
];

export default async function SocDetectionHelpPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }
  return (
    <HelpCategoryLayout
      category="soc-detection"
      title="SOC and detection"
      intro="The live operational layer: incoming alerts, raw OCSF events, behavioural anomalies, and the two HITL gates (approvals + the kill switch). Read SOC first; the other menus are drills into the same data."
      tutorials={TUTORIALS}
    />
  );
}
