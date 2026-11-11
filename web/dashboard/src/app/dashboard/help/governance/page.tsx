import { redirect } from "next/navigation";

import { getAccessToken } from "@/lib/server-fetch";

import { HelpCategoryLayout } from "../help-layout";
import type { MenuTutorial } from "../help-types";

/**
 * Governance + Developer category.
 *
 * Routes covered (5):
 *   - /dashboard/analytics
 *   - /dashboard/graph
 *   - /dashboard/api-docs
 *   - /dashboard/api-playground
 *   - /dashboard/admin/secrets
 */
const TUTORIALS: ReadonlyArray<MenuTutorial> = [
  {
    id: "analytics",
    title: "Risk analytics",
    route: "/dashboard/analytics",
    purpose:
      "Comprehensive aggregate view across the tenant — engagement counts, finding distribution by severity, scan throughput, BAS run history, asset growth. The 'how are we doing this quarter?' surface.",
    whenToUse: [
      "Weekly leadership posture review.",
      "Quarterly board reporting.",
      "When sizing a new threat-coverage initiative.",
    ],
    workflow: [
      "Open Analytics. The page SSRs the static counters; charts render client-side via recharts.",
      "Read the headline counters first: engagements, findings by severity, scans run, BAS runs.",
      "Drill into the charts: severity over time, asset growth, finding velocity.",
      "Use the cross-links to jump back to the source menus when a number looks off.",
    ],
    inputs: [
      "Parallel SSR fan-out: `/v1/engagements`, `/v1/findings`, `/v1/assets`, `/v1/bas/runs`, `/v1/scans`.",
      "Charts: client-side recharts components.",
    ],
    outputs: [
      "Read-only. No mutations.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "Why does Analytics disagree with Remediation MTTR?",
        a: "Analytics computes inventory counts; Remediation computes time-to-fix. Both are correct — they answer different questions. Use Analytics for volume, Remediation for velocity.",
      },
    ],
    references: [
      { label: "/dashboard/remediation", href: "/dashboard/remediation" },
      { label: "/dashboard/findings", href: "/dashboard/findings" },
    ],
  },
  {
    id: "graph",
    title: "Attack graph",
    route: "/dashboard/graph",
    purpose:
      "Graph view of attack paths across the engagement's asset inventory, backed by Neo4j. Helps you reason about what's actually reachable, not just what's vulnerable.",
    whenToUse: [
      "When planning a Red Team campaign — to pick a realistic kill-chain.",
      "When debugging blast-radius — to see the underlying graph.",
      "When explaining attack paths to a customer with a visual.",
    ],
    workflow: [
      "Open Graph. The engagement dropdown is SSR-loaded.",
      "Pick the target engagement.",
      "The page fetches the projection and renders it in a force-directed layout.",
      "Pan + zoom; click nodes for attributes; click edges for relationship type.",
      "Use the legend to read node/edge colour conventions.",
    ],
    inputs: [
      "`GET /v1/engagements?limit=200` — engagement source.",
      "`GET /v1/graph/projection?engagement_id={id}` — projection payload.",
    ],
    outputs: [
      "Read-only.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "Why is the graph empty?",
        a: "The engagement might not have any assets in scope, or the Neo4j projection job hasn't run yet. Check **Logs** for `graph.projection.failed` events.",
      },
    ],
    references: [
      { label: "/dashboard/blast-radius", href: "/dashboard/blast-radius" },
      { label: "/dashboard/redteam", href: "/dashboard/redteam" },
      { label: "/dashboard/twin", href: "/dashboard/twin" },
    ],
  },
  {
    id: "api-docs",
    title: "API documentation",
    route: "/dashboard/api-docs",
    purpose:
      "Browse the platform's OpenAPI 3.1 schema via Swagger UI. The same schema that powers the playground + every SDK; the canonical reference for sx-api consumers.",
    whenToUse: [
      "When you're integrating an external system against sx-api.",
      "When the dashboard doesn't expose a feature and you want to know if the API does.",
      "When writing a custom report or export pipeline.",
    ],
    workflow: [
      "Open API Docs. The Swagger UI loads the schema via the `/api/openapi` same-origin proxy.",
      "Browse endpoints by tag.",
      "Use the inline 'Try it out' to run a request against your tenant.",
      "Copy curl + request body samples directly into your client.",
    ],
    inputs: [
      "`GET /api/openapi` (proxy → `GET /openapi.json` on sx-api).",
    ],
    outputs: [
      "Read-only schema browser. Live requests do mutate when you 'Try it out'.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "Why does the page say 'no schema'?",
        a: "Either sx-api is unreachable from the dashboard origin or the proxy isn't configured. Check the dashboard's `NEXT_PUBLIC_SX_API_URL` env.",
      },
    ],
    references: [
      { label: "/dashboard/api-playground", href: "/dashboard/api-playground" },
    ],
  },
  {
    id: "api-playground",
    title: "API playground",
    route: "/dashboard/api-playground",
    purpose:
      "Free-form HTTP playground with multi-tab support, environment variables, and a 50-entry history. Requests are proxied server-side so you can hit any HTTPS endpoint without CORS pain.",
    whenToUse: [
      "When you're prototyping a new sx-api consumer.",
      "When you need to confirm an endpoint's payload format before writing client code.",
      "When repro-ing a customer-reported bug against a specific request.",
    ],
    workflow: [
      "Open API Playground.",
      "Pick or create a tab; set method + URL + headers + body.",
      "Use environment variables (`{{var}}`) to template values across tabs.",
      "Send. The response renders inline; the request is captured in history.",
      "Hit the saved-history panel to re-run any earlier request.",
    ],
    inputs: [
      "Server-side proxy with the dashboard's session bearer attached.",
      "`NEXT_PUBLIC_SX_API_URL` for the default sx-api base.",
    ],
    outputs: [
      "Response rendered inline. Mutating requests do mutate.",
      "50-entry rolling history (in-browser).",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "Why is my request blocked by SSRF protection?",
        a: "The proxy enforces an SSRF guard against private CIDR + metadata endpoints. Override is admin-only. Use a public test target instead.",
      },
      {
        q: "Are my saved requests synced?",
        a: "No — history is in-browser only. Export the history JSON if you need to share with a teammate.",
      },
    ],
    references: [
      { label: "/dashboard/api-docs", href: "/dashboard/api-docs" },
    ],
  },
  {
    id: "admin-secrets",
    title: "Secrets and KMS",
    route: "/dashboard/admin/secrets",
    purpose:
      "Vault secret browser. Inspect which paths the platform proxies through Vault. Gated by the `admin:secrets` permission; non-admins see a clear 403 card.",
    whenToUse: [
      "When debugging a Vault-related failure (provider down, path missing).",
      "When auditing what sensitive material the platform touches.",
      "When rotating a secret and you want to confirm the path's metadata.",
    ],
    workflow: [
      "Open Admin → Secrets. Requires `admin:secrets`.",
      "Browse paths the platform proxies (key names are visible; cleartext values are reveal-gated).",
      "Click 'Reveal' on a specific path; the request hits Vault server-side with the bearer attached.",
      "Confirm or rotate the secret using your own Vault tooling.",
    ],
    inputs: [
      "`GET /v1/admin/secrets` — list visible paths.",
      "`GET /v1/admin/secrets/reveal?path=...` — reveal cleartext (audited).",
      "Backend mirrors the `admin:secrets` check on every reveal.",
    ],
    outputs: [
      "Audit log entry for every reveal.",
    ],
    roles: ["admin"],
    faqs: [
      {
        q: "Why does the page show a 403 card even though I'm admin?",
        a: "You need the specific `admin:secrets` permission, not just any admin role. Check `/dashboard/iam` for your role's grants.",
      },
      {
        q: "Can I write secrets here?",
        a: "No. The page is read-only; writes happen via your existing Vault workflow. The platform consumes secrets, it doesn't manage them.",
      },
    ],
    references: [
      { label: "/dashboard/iam", href: "/dashboard/iam" },
      { label: "Help: Identity", href: "/dashboard/help/identity" },
    ],
  },
];

export default async function GovernanceHelpPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }
  return (
    <HelpCategoryLayout
      category="governance"
      title="Governance, analytics, and developer"
      intro="Aggregate dashboards (Analytics), graph + secrets administration, and the developer surfaces (OpenAPI docs + the request playground)."
      tutorials={TUTORIALS}
    />
  );
}
