import { redirect } from "next/navigation";

import { getAccessToken } from "@/lib/server-fetch";

import { HelpCategoryLayout } from "../help-layout";
import type { MenuTutorial } from "../help-types";

/**
 * Discovery category — every menu that brings external state into the
 * platform's inventory or evaluates that inventory against a framework.
 *
 * Routes covered (8):
 *   - /dashboard/scans
 *   - /dashboard/vuln-import
 *   - /dashboard/cloud
 *   - /dashboard/compliance
 *   - /dashboard/compliance/[framework]
 *   - /dashboard/compliance/evidence
 *   - /dashboard/twin
 *   - /dashboard/blast-radius
 */
const TUTORIALS: ReadonlyArray<MenuTutorial> = [
  {
    id: "scans",
    title: "Scans",
    route: "/dashboard/scans",
    purpose:
      "Run and inspect first-party scans — currently HTTP header scans against engagement-scoped assets. Results become findings automatically and feed downstream reporting + remediation.",
    whenToUse: [
      "At the start of an engagement, to seed the finding queue.",
      "After a target asset's configuration changed and you want a fresh baseline.",
      "When you're sanity-checking that a remediation actually fixed the underlying check.",
    ],
    workflow: [
      "Open Scans. The page SSR-loads recent runs + engagement + asset dropdowns.",
      "Click 'New scan', pick the engagement, then pick a target asset (URL).",
      "Submit. The row appears in the table with status `queued` → `running`.",
      "Once `completed`, every detected issue is materialised as a Finding row and the scan record stays linked.",
      "Use the row's 'View →' link to inspect the raw HTTP headers if you need to debug a finding's source.",
    ],
    inputs: [
      "`GET /v1/scans?limit=200` — scan history.",
      "`GET /v1/engagements?limit=200` + `GET /v1/assets?limit=200` — dropdown sources.",
      "`POST /v1/scans` — kick off a run.",
    ],
    outputs: [
      "Findings rows (severity tagged per check).",
      "Scan record linked to engagement + asset for audit.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "My scan is stuck in `queued` — what's wrong?",
        a: "Scans run on the platform's worker pool. If the pool is offline, the scan stays queued until the worker reconnects. Check **Logs** for any `scan.worker.unreachable` events; ask an admin to inspect `crates/sx-monolith` health.",
      },
      {
        q: "Can I run a scan without an engagement?",
        a: "No. Every scan must be tied to an engagement so the finding chain stays auditable. Create a `recon` engagement if you need a non-customer-facing scope.",
      },
    ],
    references: [
      { label: "/dashboard/findings", href: "/dashboard/findings" },
      { label: "/dashboard/engagements", href: "/dashboard/engagements" },
      { label: "Help: Posture", href: "/dashboard/help/posture" },
    ],
  },
  {
    id: "vuln-import",
    title: "Vulnerability import",
    route: "/dashboard/vuln-import",
    purpose:
      "Ingest external vulnerability reports (Trivy, Snyk, Nuclei, OWASP ZAP, generic SARIF) and have them materialise as platform findings under an engagement.",
    whenToUse: [
      "After a CI pipeline produced a SARIF and you want it in the platform's audit chain.",
      "When integrating a third-party scanner that isn't first-class yet.",
      "For a one-off bulk import of legacy reports during an onboarding.",
    ],
    workflow: [
      "Open Vulnerability import. The page shows the import history table.",
      "Click 'New import' and pick the source kind (SARIF, Trivy JSON, etc.).",
      "Upload the report file; the form validates schema client-side before transmission.",
      "Submit — the import is queued and the row appears with status `pending`.",
      "Once `processed`, every parsed issue is created as a Finding tied to the engagement.",
    ],
    inputs: [
      "`GET /v1/vuln/imports?limit=200` — import history.",
      "`POST /v1/vuln/imports` — submit a new import.",
    ],
    outputs: [
      "Finding rows (severity-mapped from the source format).",
      "Import audit record showing source format, parse warnings, finding count.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "Why did my import succeed but produce zero findings?",
        a: "The source file parsed OK but the format-specific normaliser couldn't extract any rows. Check the import's parse-warning list — typically the file was an empty result set, not a malformed report.",
      },
      {
        q: "Are duplicates dropped?",
        a: "Yes. The ingester deduplicates by `(check_id, asset, location)` against the last 90 days. Set the `force_duplicate` flag if you actually want to re-create the row.",
      },
    ],
    references: [
      { label: "/dashboard/findings", href: "/dashboard/findings" },
      { label: "/dashboard/scans", href: "/dashboard/scans" },
    ],
  },
  {
    id: "cloud",
    title: "Cloud inventory",
    route: "/dashboard/cloud",
    purpose:
      "Browse the platform's cloud asset inventory — accounts, regions, resource types, and their relationships. Backs the Blast Radius and Digital Twin views.",
    whenToUse: [
      "When you need to know which resources exist in a customer's cloud footprint.",
      "Before computing blast radius for a seed asset — to confirm the asset is even in the inventory.",
      "For a quick spot-check that the inventory ingest is current.",
    ],
    workflow: [
      "Open Cloud inventory. The table fetches client-side via `/api/cloud/inventory` (the dashboard's same-origin proxy).",
      "Filter by account, region, or resource type using the column controls.",
      "Click a row to expand the resource's tags + relationships.",
      "If the inventory looks stale, ask an admin to trigger a fresh ingest via the cloud connector.",
    ],
    inputs: [
      "`GET /api/cloud/inventory` (proxied to sx-api with the session bearer attached server-side).",
    ],
    outputs: [
      "Read-only. Feeds Blast Radius and Digital Twin views.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "Why is the inventory empty?",
        a: "Either the cloud connector hasn't been provisioned for this tenant or the ingest job has failed. Check **Logs** for `cloud.ingest.failed` events.",
      },
    ],
    references: [
      { label: "/dashboard/blast-radius", href: "/dashboard/blast-radius" },
      { label: "/dashboard/twin", href: "/dashboard/twin" },
    ],
  },
  {
    id: "compliance",
    title: "Compliance frameworks",
    route: "/dashboard/compliance",
    purpose:
      "Index of every compliance framework the platform recognises: ISO 27001, SOC 2, PCI DSS, HIPAA, NIST 800-53, CIS AWS. Click into a framework to see its controls.",
    whenToUse: [
      "When you're preparing an audit and need the canonical control list.",
      "When mapping a finding to a control for evidence-bundle accounting.",
      "When you're explaining to a customer which frameworks the platform attests against.",
    ],
    workflow: [
      "Open Compliance. Six framework cards render (ISO 27001, SOC 2, PCI DSS, HIPAA, NIST 800-53, CIS AWS).",
      "Click any card to load the framework detail page.",
      "Use the framework detail page to read the canonical control list.",
      "Use the Evidence sub-page to ship evidence bundles to S3 for the auditor.",
    ],
    inputs: [
      "Static list — sourced from `COMPLIANCE_FRAMEWORKS` in `web/dashboard/src/lib/types.ts`.",
    ],
    outputs: [
      "Click-through to framework detail and evidence pages.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "Where do I add a new framework?",
        a: "Framework slugs live in the type union — adding one is a code change in `sx-api` + a dashboard type bump. Not a runtime customisation.",
      },
    ],
    references: [
      { label: "Framework detail", href: "/dashboard/help/discovery#compliance-framework" },
      { label: "Evidence bundles", href: "/dashboard/help/discovery#compliance-evidence" },
    ],
  },
  {
    id: "compliance-framework",
    title: "Compliance framework detail",
    route: "/dashboard/compliance/[framework]",
    purpose:
      "Per-framework control browser. Shows every control in the framework with its title + description, sourced from the sx-api compliance registry.",
    whenToUse: [
      "When you need the authoritative control list for a single framework.",
      "When you're cross-walking a finding to a control id.",
      "When preparing audit evidence and need the framework's exact wording.",
    ],
    workflow: [
      "Click a framework card on `/dashboard/compliance`.",
      "The table renders every control: id, title, description.",
      "Use Cmd/Ctrl+F to find a specific control.",
      "Cross-reference the control id when filing audit evidence.",
    ],
    inputs: [
      "`GET /v1/compliance/{framework}/controls` — control list per framework.",
    ],
    outputs: [
      "Read-only table.",
    ],
    roles: ["analyst", "ops", "admin", "auditor"],
    faqs: [
      {
        q: "Why is the framework I want missing?",
        a: "Only the six supported frameworks render. Adding a new one is a backend change — file a ticket with the GRC team.",
      },
    ],
    references: [
      { label: "/dashboard/compliance/evidence", href: "/dashboard/compliance/evidence" },
    ],
  },
  {
    id: "compliance-evidence",
    title: "Compliance evidence bundles",
    route: "/dashboard/compliance/evidence",
    purpose:
      "Run the evidence collectors and ship the resulting manifests to S3 for auditor consumption. Tracks every shipped bundle with its framework, artefact count, and shipping timestamp.",
    whenToUse: [
      "On the audit cycle cadence (typically monthly or quarterly).",
      "After a control's underlying implementation changed and you need a fresh attestation snapshot.",
      "When an auditor requests a specific control's evidence package.",
    ],
    workflow: [
      "Open Evidence. The shipped-bundle history renders top of page.",
      "Click 'Run collectors' to materialise a fresh snapshot.",
      "Click 'Ship to S3' to upload the manifest + artefact tarballs.",
      "Forward the manifest_key to the auditor.",
    ],
    inputs: [
      "Collector results: filesystem + API probes orchestrated by the evidence pipeline.",
      "S3 destination configured in the tenant's `sx-config`.",
    ],
    outputs: [
      "S3 object: `evidence/{yyyy}/{mm}/{framework}-{control}-{seq}.json`.",
      "An entry in the shipped-table for audit.",
    ],
    roles: ["admin", "auditor"],
    faqs: [
      {
        q: "Some operations still show stub data — when does it become real?",
        a: "The collectors and the S3 shipper are wired through; the table you see is real but the manual-run buttons currently stub the response. The wire format matches the production endpoint so when the proxy lands no UI change is needed.",
      },
    ],
    references: [
      { label: "/dashboard/compliance", href: "/dashboard/compliance" },
    ],
  },
  {
    id: "twin",
    title: "Cyber digital twin",
    route: "/dashboard/twin",
    purpose:
      "Render a tenant's environment as a graph projection — assets, users, services, and their relationships — so you can reason about attack surface visually.",
    whenToUse: [
      "Before planning a BAS run, to confirm the simulated attack path is realistic.",
      "When explaining attack surface to a non-technical stakeholder.",
      "When you suspect a cloud-inventory ingest is missing relationships.",
    ],
    workflow: [
      "Open Twin. The engagement dropdown is SSR-populated.",
      "Pick an engagement and click 'Load twin'.",
      "The projection renders — pan + zoom to inspect.",
      "Click a node to see its attributes; click an edge to see the relationship type.",
    ],
    inputs: [
      "`GET /v1/engagements?limit=200` — dropdown source.",
      "`GET /v1/twin/projection?engagement_id={id}` — projection payload.",
    ],
    outputs: [
      "Read-only visualisation. Feeds operator intuition only.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "The projection is empty for my engagement — why?",
        a: "The engagement might not have any assets in scope yet (the twin renders the asset-graph projection of the engagement). Add assets via the engagement detail page, then reload.",
      },
    ],
    references: [
      { label: "/dashboard/blast-radius", href: "/dashboard/blast-radius" },
      { label: "/dashboard/cloud", href: "/dashboard/cloud" },
    ],
  },
  {
    id: "blast-radius",
    title: "Blast radius",
    route: "/dashboard/blast-radius",
    purpose:
      "Pick an asset as a seed and compute which other assets would be affected if it were compromised. Helps prioritise remediation by impact instead of severity alone.",
    whenToUse: [
      "When you have multiple critical findings and need to pick which to remediate first.",
      "When sizing the blast radius of a hypothetical compromise for a tabletop exercise.",
      "When explaining the practical impact of a finding to a non-security stakeholder.",
    ],
    workflow: [
      "Open Blast Radius. The asset picker is SSR-populated from the inventory.",
      "Pick a seed asset.",
      "Click 'Compute blast radius'. The client fetches the projection on demand.",
      "Inspect the resulting set: how many downstream assets, what types, and their criticality.",
    ],
    inputs: [
      "`GET /v1/assets?limit=200` — asset picker.",
      "`POST /v1/blast-radius/compute` — compute endpoint.",
    ],
    outputs: [
      "Set of affected assets + an aggregate impact score.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "Why is the blast radius so much smaller than I expected?",
        a: "The computation walks asset-asset relationships from the cloud inventory. If relationships are missing (e.g. the connector hasn't enumerated IAM bindings yet), the radius will under-report. Re-run after a fresh inventory ingest.",
      },
    ],
    references: [
      { label: "/dashboard/cloud", href: "/dashboard/cloud" },
      { label: "/dashboard/twin", href: "/dashboard/twin" },
    ],
  },
];

export default async function DiscoveryHelpPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }
  return (
    <HelpCategoryLayout
      category="discovery"
      title="Discovery and inventory"
      intro="Every menu that brings external state into the platform or evaluates that state against a control framework. Scans seed the finding queue; cloud + twin + blast-radius let you reason about the asset graph; compliance + evidence prove it to auditors."
      tutorials={TUTORIALS}
    />
  );
}
