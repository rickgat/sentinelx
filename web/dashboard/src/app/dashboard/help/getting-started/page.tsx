import { redirect } from "next/navigation";

import { getAccessToken } from "@/lib/server-fetch";

import { HelpCategoryLayout } from "../help-layout";
import type { MenuTutorial } from "../help-types";

/**
 * Quick start tutorial — `/dashboard/help/getting-started`.
 *
 * Two MenuTutorial blocks cover the dashboard's "front door" surfaces:
 *   - `/dashboard`              (Overview / KPI landing)
 *   - `/dashboard/handbook`     (process + policy reference)
 *
 * The end-to-end "first scan" walkthrough is presented inside the
 * Overview block's workflow steps; deeper menu-specific guidance lives
 * inside the other category pages.
 */
const TUTORIALS: ReadonlyArray<MenuTutorial> = [
  {
    id: "overview",
    title: "Overview (your daily landing page)",
    route: "/dashboard",
    purpose:
      "The Overview is the first surface every operator sees after login. It pins the tenant's posture KPIs (open critical findings, MTTR, scan throughput) and the posture trend chart so you can spot drift at a glance before drilling into any single menu.",
    whenToUse: [
      "Every morning, as the start-of-shift orientation surface.",
      "After a planned maintenance window, to confirm scan throughput and finding intake resumed.",
      "When a stakeholder asks for a one-screen status snapshot.",
    ],
    workflow: [
      "Read the KPI strip at the top: critical-finding count, average MTTR, recent scan velocity.",
      "Inspect the posture trend chart — a flat or declining critical line is healthy; a spike usually means a new ingest source landed.",
      "If the KPI strip shows a non-zero critical count, follow the link to Findings and triage from there.",
      "If MTTR is regressing, jump to Remediation to look at per-check_id regression buckets.",
      "Use the sidebar to navigate to the menu that owns the workflow you actually came here for.",
    ],
    inputs: [
      "`GET /v1/engagements?limit=200` — engagement totals via the SSR `safeFetch` helper.",
      "`GET /v1/findings?limit=200` — the unfiltered finding ring for KPI counts.",
      "Posture trend series resolved by the dynamic `PostureTrend` chart.",
    ],
    outputs: [
      "KPI cards (counts, no further side effects).",
      "Click-through navigation to Findings, Remediation, and Engagements.",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "Why does the Overview show zeros even though I know we have findings?",
        a: "The page renders the SSR snapshot of the API at request time. If sx-api was unavailable when you loaded it, the safe-fetch helper returns empty pages. Refresh once the API is healthy — the **API Docs** card on the topbar reflects API status.",
      },
      {
        q: "How current is the data?",
        a: "Counts are fresh on every server-side render (no client cache). The trend chart is read from the materialised posture table, which refreshes every 5 minutes by default — see PRD §6A.2 for the data freshness contract.",
      },
    ],
    references: [
      { label: "/dashboard/findings", href: "/dashboard/findings" },
      { label: "/dashboard/remediation", href: "/dashboard/remediation" },
      { label: "Help: Posture", href: "/dashboard/help/posture" },
    ],
  },
  {
    id: "handbook",
    title: "Handbook (process and policy reference)",
    route: "/dashboard/handbook",
    purpose:
      "The Handbook is the authoritative process + policy reference for the platform. The Help section you are reading now is per-menu tutorial; the Handbook is end-to-end story (what runs the SOC, what every backing port does, what the operational caveats are).",
    whenToUse: [
      "When you need to understand *why* a menu exists, not just how to drive it.",
      "When you are writing audit evidence and need a citable description of a control.",
      "When you are onboarding a new module and want the section anchored to the same 8-module taxonomy as the sidebar.",
    ],
    workflow: [
      "Open the Handbook from the sidebar's Developer & Docs module.",
      "Use the left rail to jump to the module (Operations, Engagement, Discovery, …) that owns the topic.",
      "Each module section enumerates every backing crate / port and the operational caveats introduced since P0-001.",
      "If you need a how-to instead of a what-is, come back here (Help) — every Handbook module maps to a Help category.",
    ],
    inputs: [
      "Static content compiled into the page — no API fetch.",
    ],
    outputs: [
      "Anchor links to deep sections (e.g. `#findings`, `#rba`, `#scim`).",
    ],
    roles: ["analyst", "ops", "admin"],
    faqs: [
      {
        q: "When should I read the Handbook versus this Help section?",
        a: "**Help** = how do I use this menu? **Handbook** = how does this subsystem behave end-to-end? Help is task-oriented; Handbook is reference-oriented.",
      },
      {
        q: "Does the Handbook reflect the latest sprint?",
        a: "The Handbook is curated alongside each sprint close — see the version stamp at the top of the page. New features land in Help first (lower friction) and graduate to the Handbook once the workflow is stable.",
      },
    ],
    references: [
      { label: "/dashboard/handbook", href: "/dashboard/handbook" },
      { label: "PRD §6A — Posture surface", href: "/dashboard/help/posture" },
    ],
  },
];

export default async function GettingStartedPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }
  return (
    <HelpCategoryLayout
      category="getting-started"
      title="Getting started"
      intro="A five-minute on-ramp. Read the Overview tutorial first, then jump to Posture for your first finding triage. If you want the deep architectural background instead, the Handbook block below tells you exactly when to use Help versus Handbook."
      tutorials={TUTORIALS}
    />
  );
}
