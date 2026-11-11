import { redirect } from "next/navigation";

import { getAccessToken } from "@/lib/server-fetch";

import { HelpCategoryLayout } from "../help-layout";
import type { MenuTutorial } from "../help-types";

/**
 * Integrations category — finding fan-out and ticketing webhook sinks.
 *
 * Integrations are configured server-side (no dedicated dashboard menu
 * yet) so each tutorial describes the user-visible behaviour and points
 * at the relevant findings / reports menus + the backing crate.
 */
const TUTORIALS: ReadonlyArray<MenuTutorial> = [
  {
    id: "fanout-overview",
    title: "Finding fan-out (overview)",
    route: "/dashboard/findings",
    purpose:
      "When a finding transitions from `open` to `triaged`, the platform fans the event out to every configured webhook sink — Jira, PagerDuty, Linear, Opsgenie, ServiceNow. This tutorial explains the lifecycle so you can predict where a finding will end up.",
    whenToUse: [
      "Configuring a new tenant and deciding which sinks to enable.",
      "Debugging why a finding didn't show up in your team's ticketing system.",
      "Auditing the fan-out chain for SOC 2 evidence.",
    ],
    workflow: [
      "Open a finding in `/dashboard/findings` and confirm its current status.",
      "Transition to `triaged` (or another status the tenant has wired for fan-out).",
      "The sx-api emits a webhook event consumed by `crates/sx-webhooks` and `crates/sx-integrations`.",
      "Each enabled sink renders the event into a ticket / incident / alert.",
      "Verify in the downstream system. If it's missing, check the per-sink troubleshooting below.",
    ],
    inputs: [
      "Finding status transition events (emitted by `POST /v1/findings/{id}/status`).",
      "Webhook sink configs persisted under the tenant's `sx-config`.",
    ],
    outputs: [
      "One ticket / incident / alert per enabled sink.",
      "Audit log entry capturing the fan-out outcome (success / failed / disabled).",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "Where do I configure sinks?",
        a: "Sink credentials live in tenant config (`sx-config`) and are mounted via Vault. No dashboard form yet — admins do this via the CLI. See the per-sink tutorials below for credential shapes.",
      },
      {
        q: "Will the same finding fan out multiple times?",
        a: "No. The fan-out fires once per status transition. Re-firing requires a transition back-and-forth, which is itself audit-logged.",
      },
    ],
    references: [
      { label: "/dashboard/findings", href: "/dashboard/findings" },
      { label: "/dashboard/reports", href: "/dashboard/reports" },
      { label: "Help: Posture", href: "/dashboard/help/posture" },
    ],
  },
  {
    id: "jira",
    title: "Jira",
    route: "/dashboard/findings",
    purpose:
      "Materialise findings as Jira issues so engineering can pick them up in their existing sprint queue. The Jira sink lives in `crates/sx-webhooks/src/jira.rs` and `crates/sx-integrations/src/jira_incident.rs`.",
    whenToUse: [
      "Your remediation team uses Jira as the source of truth.",
      "You need findings to show up in a specific project / issue type.",
      "You're auditing finding-to-issue traceability.",
    ],
    workflow: [
      "An admin provisions Jira credentials (base URL + API token + target project key) in `sx-config`.",
      "Transition a finding to `triaged` in `/dashboard/findings`.",
      "The Jira sink renders the finding into an issue: title = finding title, description = finding description + asset + link back to the dashboard.",
      "The Jira issue key is recorded against the finding for cross-reference.",
      "Subsequent status changes (resolved → closed) sync back as Jira transitions if configured.",
    ],
    inputs: [
      "Tenant config: Jira base URL, API token, project key, issue type.",
      "Finding transition events.",
    ],
    outputs: [
      "Jira issue with finding metadata + link.",
      "Issue key persisted against the finding record.",
    ],
    roles: ["admin"],
    faqs: [
      {
        q: "Why isn't my finding showing up in Jira?",
        a: "Check three things: the sink is enabled, the credentials are valid (look for `webhook.jira.unauthorized` in Logs), and the finding actually transitioned to a fan-out-eligible status. The `open` status alone does not fire.",
      },
      {
        q: "Can I customise the issue body?",
        a: "Template lives in the crate. Customisation requires a backend change today; a tenant-level template override is on the integrations roadmap.",
      },
    ],
    references: [
      { label: "/dashboard/findings", href: "/dashboard/findings" },
      { label: "/dashboard/api-docs", href: "/dashboard/api-docs" },
    ],
  },
  {
    id: "pagerduty",
    title: "PagerDuty",
    route: "/dashboard/soc",
    purpose:
      "Page on-call humans when a SOC alert or high-severity finding lands. The PagerDuty sink lives in `crates/sx-webhooks/src/pagerduty.rs`.",
    whenToUse: [
      "You have an on-call rotation that needs to wake up for criticals.",
      "You want a paging trail for compliance evidence (SOC 2 incident response).",
      "You're integrating with an existing PagerDuty service for unified incident management.",
    ],
    workflow: [
      "Admin provisions PagerDuty integration key in `sx-config`.",
      "A SOC alert or finding triage event fires.",
      "The PagerDuty sink posts a `trigger` event with severity + summary.",
      "Resolve or acknowledge from PagerDuty; the back-sync closes the loop in `/dashboard/soc`.",
    ],
    inputs: [
      "Tenant config: PagerDuty integration key (Events API v2).",
      "Alert + finding transition events.",
    ],
    outputs: [
      "PagerDuty incident with dedup key + summary.",
      "Back-sync to platform on acknowledge / resolve (if webhook is mutual).",
    ],
    roles: ["admin"],
    faqs: [
      {
        q: "Why is every alert paging me?",
        a: "Default severity filter is `critical`. If you're getting lower severities, the per-tenant override is set too broadly. Tighten via the sink config.",
      },
    ],
    references: [
      { label: "/dashboard/soc", href: "/dashboard/soc" },
      { label: "/dashboard/safety", href: "/dashboard/safety" },
    ],
  },
  {
    id: "linear",
    title: "Linear",
    route: "/dashboard/findings",
    purpose:
      "Materialise findings as Linear issues — the modern-stack alternative to Jira. The sink lives in `crates/sx-webhooks/src/linear.rs`.",
    whenToUse: [
      "Your engineering org uses Linear instead of Jira.",
      "You want findings to land directly in a Linear team's triage column.",
      "You need bidirectional sync (close finding → close Linear issue).",
    ],
    workflow: [
      "Admin provisions Linear API token + target team id in `sx-config`.",
      "Transition a finding to `triaged`.",
      "The Linear sink creates an issue in the configured team with finding metadata.",
      "Linear issue id is persisted on the finding for cross-reference.",
    ],
    inputs: [
      "Tenant config: Linear API token, team id, optional template id.",
      "Finding transition events.",
    ],
    outputs: [
      "Linear issue with finding context.",
      "Issue id stored against the finding.",
    ],
    roles: ["admin"],
    faqs: [
      {
        q: "Can I route different severities to different teams?",
        a: "Not yet — the sink ships to a single team. Route via Linear's own automation rules in the meantime.",
      },
    ],
    references: [
      { label: "/dashboard/findings", href: "/dashboard/findings" },
    ],
  },
  {
    id: "opsgenie",
    title: "Opsgenie",
    route: "/dashboard/soc",
    purpose:
      "Alternative paging sink for tenants on Atlassian Opsgenie. Behaviour mirrors PagerDuty. Sink lives in `crates/sx-webhooks/src/opsgenie.rs`.",
    whenToUse: [
      "You use Opsgenie for on-call (often paired with Jira).",
      "You want the same per-severity paging policy as PagerDuty.",
      "You need a non-PagerDuty paging trail for regional compliance.",
    ],
    workflow: [
      "Admin provisions Opsgenie API key + target team in `sx-config`.",
      "Alerts and finding transitions emit Opsgenie alert events.",
      "Operators acknowledge / close from Opsgenie; back-sync closes the platform-side state.",
    ],
    inputs: [
      "Tenant config: Opsgenie API key, team, priority mapping.",
      "Alert + finding transition events.",
    ],
    outputs: [
      "Opsgenie alert with dedup key + priority.",
    ],
    roles: ["admin"],
    faqs: [
      {
        q: "How does priority map from severity?",
        a: "`critical → P1`, `high → P2`, `medium → P3`, `low → P4`, `info → P5`. Override the mapping in the sink config if you need different semantics.",
      },
    ],
    references: [
      { label: "/dashboard/soc", href: "/dashboard/soc" },
    ],
  },
  {
    id: "servicenow",
    title: "ServiceNow",
    route: "/dashboard/findings",
    purpose:
      "Materialise findings as ServiceNow incidents — typical for enterprise tenants that run ITSM through ServiceNow. Sink lives in `crates/sx-webhooks/src/servicenow.rs`.",
    whenToUse: [
      "Your enterprise mandates ServiceNow as the ITSM source of truth.",
      "You need formal change-management linkage between findings and incident records.",
      "You're audited against ServiceNow ticket SLAs.",
    ],
    workflow: [
      "Admin provisions ServiceNow instance URL + credentials + target table in `sx-config`.",
      "Transition a finding to `triaged`.",
      "The ServiceNow sink posts a new incident record with finding metadata + the dashboard cross-link.",
      "Incident number is recorded against the finding.",
    ],
    inputs: [
      "Tenant config: ServiceNow instance URL, OAuth credentials, target table (e.g. `incident`).",
      "Finding transition events.",
    ],
    outputs: [
      "ServiceNow incident record.",
      "Incident number stored on the finding.",
    ],
    roles: ["admin"],
    faqs: [
      {
        q: "ServiceNow OAuth tokens expire — does the sink refresh?",
        a: "Yes. The sink uses a refresh-token flow and silently re-issues on 401. If you see persistent 401s in Logs, the client_secret is stale.",
      },
    ],
    references: [
      { label: "/dashboard/findings", href: "/dashboard/findings" },
      { label: "/dashboard/admin/secrets", href: "/dashboard/admin/secrets" },
    ],
  },
];

export default async function IntegrationsHelpPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }
  return (
    <HelpCategoryLayout
      category="integrations"
      title="Integrations and finding fan-out"
      intro="How findings + alerts flow into your existing ticketing and paging tools. Read the fan-out overview first to understand the trigger, then jump to the per-sink tutorial for the integration you care about."
      tutorials={TUTORIALS}
    />
  );
}
