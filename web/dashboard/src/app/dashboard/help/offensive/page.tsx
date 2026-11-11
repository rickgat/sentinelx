import { redirect } from "next/navigation";

import { getAccessToken } from "@/lib/server-fetch";

import { HelpCategoryLayout } from "../help-layout";
import type { MenuTutorial } from "../help-types";

/**
 * Offensive simulation + AI category.
 *
 * Routes covered (5):
 *   - /dashboard/bas
 *   - /dashboard/bas/techniques
 *   - /dashboard/redteam
 *   - /dashboard/copilot
 *   - /dashboard/copilot-approvals
 */
const TUTORIALS: ReadonlyArray<MenuTutorial> = [
  {
    id: "bas",
    title: "Breach and attack simulation (BAS)",
    route: "/dashboard/bas",
    purpose:
      "Plan and run breach-and-attack simulations against engagement-scoped assets. The platform's safe, repeatable way to validate detection coverage against MITRE ATT&CK techniques.",
    whenToUse: [
      "Before signing off on a SOC detection capability — to confirm the rule actually fires.",
      "After a SIEM tuning change — to regression-test detection.",
      "Quarterly purple-team cadence.",
    ],
    workflow: [
      "Open BAS. Run history + engagement + asset dropdowns render SSR.",
      "Click 'New run'. Pick the engagement, then pick target assets.",
      "Pick the technique catalogue subset to exercise (see Techniques tutorial for the full list).",
      "Submit. The run appears with status `queued` → `running` → `completed`.",
      "Inspect the completed run: which techniques fired, which were detected, which slipped through.",
      "Open the SOC menu to confirm the corresponding alerts; gaps become findings.",
    ],
    inputs: [
      "`GET /v1/bas/runs?limit=200` — run history.",
      "`GET /v1/engagements?limit=200` + `GET /v1/assets?limit=200` — dropdown sources.",
      "`POST /v1/bas/runs` — kick a new run.",
    ],
    outputs: [
      "Run record with per-technique outcomes.",
      "Findings for any uncovered technique (detection gap).",
      "Cross-reference into Analytics for trending.",
    ],
    roles: ["ops", "admin"],
    faqs: [
      {
        q: "Will this hit production?",
        a: "BAS techniques run in `theoretical` intensity by default — they record what would happen, not actually exploit. Higher intensities exist but are gated by Safety + two-person approval.",
      },
      {
        q: "Why is my run stuck queued?",
        a: "BAS workers may be saturated or the Safety kill-switch is tripped. Check Safety; ask an admin to inspect worker health.",
      },
    ],
    references: [
      { label: "Techniques", href: "/dashboard/help/offensive#bas-techniques" },
      { label: "/dashboard/soc", href: "/dashboard/soc" },
      { label: "/dashboard/findings", href: "/dashboard/findings" },
    ],
  },
  {
    id: "bas-techniques",
    title: "BAS technique catalogue",
    route: "/dashboard/bas/techniques",
    purpose:
      "Read-only browser for the embedded MITRE ATT&CK technique catalogue shipped by the BAS planner. Grouped by tactic (reconnaissance → impact); every row deep-links to the upstream MITRE page.",
    whenToUse: [
      "When you need to know which techniques the platform can simulate.",
      "When designing a new BAS run and you want to pick a coherent kill-chain.",
      "When triaging a SOC alert — to look up the technique context.",
    ],
    workflow: [
      "Open BAS → Techniques.",
      "Browse the list grouped by ATT&CK tactic (reconnaissance, initial-access, execution, …, impact).",
      "Click any technique id (e.g. T1595) to open the upstream MITRE page in a new tab.",
      "Note the `required_intensity` and `platforms` columns — they tell you whether the platform can actually exercise the technique today.",
    ],
    inputs: [
      "Static catalogue inlined in `web/dashboard/src/app/dashboard/bas/techniques/page.tsx`.",
      "Once `GET /v1/bas/techniques` ships, this page swaps the inline constant for a fetch with zero client-side change.",
    ],
    outputs: [
      "Read-only. Drives BAS run planning.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "Why is the catalogue smaller than the full MITRE ATT&CK matrix?",
        a: "Only techniques the BAS planner can actually simulate are listed. Coverage grows each sprint — see the sprint hardening handoff for the latest additions.",
      },
    ],
    references: [
      { label: "/dashboard/bas", href: "/dashboard/bas" },
      { label: "/dashboard/redteam", href: "/dashboard/redteam" },
    ],
  },
  {
    id: "redteam",
    title: "Red Team",
    route: "/dashboard/redteam",
    purpose:
      "Plan and run multi-step red-team campaigns against an engagement. Stitches BAS techniques into a kill-chain narrative and tracks per-step outcomes.",
    whenToUse: [
      "When you need a longer-running, multi-phase exercise (vs a single BAS run).",
      "Customer-facing red-team engagements where the narrative matters.",
      "Validating detection across a kill-chain, not just point checks.",
    ],
    workflow: [
      "Open Red Team. Engagement dropdown renders SSR.",
      "Pick the target engagement.",
      "Plan the campaign: pick techniques in kill-chain order (recon → initial-access → execution → ...).",
      "Launch the campaign. Each step runs in sequence; outcomes accumulate into the campaign report.",
      "Review the per-step result — fired, detected, missed — and feed the gaps into Findings.",
    ],
    inputs: [
      "`GET /v1/engagements?limit=200` — engagement dropdown.",
      "`POST /v1/redteam/campaigns` — launch.",
    ],
    outputs: [
      "Campaign record + per-step audit trail.",
      "Findings for any detection gap.",
    ],
    roles: ["ops", "admin"],
    faqs: [
      {
        q: "How is Red Team different from BAS?",
        a: "BAS exercises one technique at a time. Red Team chains them into a campaign with a target objective. Use BAS for unit testing, Red Team for integration testing.",
      },
    ],
    references: [
      { label: "/dashboard/bas", href: "/dashboard/bas" },
      { label: "/dashboard/graph", href: "/dashboard/graph" },
    ],
  },
  {
    id: "copilot",
    title: "AI Copilot",
    route: "/dashboard/copilot",
    purpose:
      "Conversational AI assistant backed by `POST /v1/copilot/chat`. Ask about findings, controls, scans — the model reads tenant context and answers in plain language.",
    whenToUse: [
      "When triaging a finding and you want a one-paragraph summary.",
      "When drafting remediation steps for a customer.",
      "When you'd otherwise grep the Handbook to remember what a control means.",
    ],
    workflow: [
      "Open Copilot. The transcript starts empty.",
      "Type a question and press Enter. The request goes through the `/api/copilot/chat` proxy so the bearer never leaves the server.",
      "Read the response inline; transcript persists for the page lifetime.",
      "If the provider is disabled for the tenant, the page swaps in a 422 banner instead of crashing.",
    ],
    inputs: [
      "`POST /api/copilot/chat` (proxy → `POST /v1/copilot/chat`).",
      "Session bearer attached server-side.",
    ],
    outputs: [
      "Single-turn chat response.",
      "Any HITL-eligible action surfaces in Copilot Approvals (next tutorial).",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "Does the model see my findings?",
        a: "It receives a sanitised context bundle for the active tenant. Sensitive fields are redacted server-side before transmission.",
      },
      {
        q: "Why did I get a 'provider disabled' banner?",
        a: "The AI provider isn't configured for this tenant. Ask an admin to enable it via the tenant config; the page handles the 422 envelope gracefully.",
      },
    ],
    references: [
      { label: "/dashboard/copilot-approvals", href: "/dashboard/copilot-approvals" },
      { label: "/dashboard/findings", href: "/dashboard/findings" },
    ],
  },
  {
    id: "copilot-approvals",
    title: "Copilot HITL approvals",
    route: "/dashboard/copilot-approvals",
    purpose:
      "Queue of actions the AI Copilot has staged but cannot execute without a human sign-off. The HITL gate that keeps the model from autonomously mutating tenant state.",
    whenToUse: [
      "Daily, as part of the SOC analyst's queue review.",
      "When the Copilot proposed a remediation and you're deciding whether to apply it.",
      "When auditing the model's behaviour — every action it tried to take is here.",
    ],
    workflow: [
      "Open Copilot Approvals. The pending queue is SSR-loaded.",
      "Each card shows the proposed action, the rationale, and the affected entity.",
      "Click Approve to execute; Reject to deny + capture the reason.",
      "Approved actions complete asynchronously; results appear in the relevant menu (Findings, Engagements, etc.).",
    ],
    inputs: [
      "`GET /v1/copilot/approvals` — pending queue.",
      "`POST /api/copilot/approvals/{token}/decide` — approve/reject.",
    ],
    outputs: [
      "Action executed against the platform on approval.",
      "Audit-logged regardless of outcome.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "What happens if I don't approve in time?",
        a: "Pending approvals expire after a tenant-configurable window (default 24h) and require the Copilot to re-stage. No silent execution.",
      },
    ],
    references: [
      { label: "/dashboard/copilot", href: "/dashboard/copilot" },
      { label: "/dashboard/approvals", href: "/dashboard/approvals" },
    ],
  },
];

export default async function OffensiveHelpPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }
  return (
    <HelpCategoryLayout
      category="offensive"
      title="Offensive simulation and AI"
      intro="Validate detection by simulating attacks (BAS, Red Team) and accelerate triage with the AI Copilot — with mandatory HITL approval on every mutating action."
      tutorials={TUTORIALS}
    />
  );
}
