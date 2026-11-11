import { redirect } from "next/navigation";

import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";
import { auth } from "@/lib/auth";

import { ReportingClient, type ReportModel, type ReportSection } from "./reporting-client";

/**
 * Comprehensive platform report (cross-module).
 *
 * Aggregates the latest results from every SentinelX module into one
 * executive-grade report — generated from live process output, not
 * hand-authored. Each module is fetched independently and degrades
 * gracefully: a module the caller cannot read (or that is empty) is marked
 * "not accessible" in the coverage appendix rather than failing the page.
 *
 * The client renders it as a printable report and can export it as
 * Markdown or JSON ("generated format from the results of the processes").
 */

export const dynamic = "force-dynamic";

interface FetchResult {
  ok: boolean;
  status: number;
  data: unknown;
}

async function fetchModule(path: string, token: string): Promise<FetchResult> {
  try {
    const data = await apiGet<unknown>(path, token);
    return { ok: true, status: 200, data };
  } catch (err) {
    const status = err instanceof ApiError ? err.status : 0;
    return { ok: false, status, data: null };
  }
}

/** Extract the primary array from a list-ish payload (items/assets/…). */
function rows(data: unknown): ReadonlyArray<Record<string, unknown>> {
  if (Array.isArray(data)) {
    return data as Array<Record<string, unknown>>;
  }
  if (data !== null && typeof data === "object") {
    const obj = data as Record<string, unknown>;
    for (const key of [
      "items",
      "assets",
      "controls",
      "runs",
      "alerts",
      "anomalies",
      "decisions",
      "feeds",
      "resources",
      "baselines",
      "findings",
      "chains",
      "scans",
    ]) {
      const v = obj[key];
      if (Array.isArray(v)) {
        return v as Array<Record<string, unknown>>;
      }
    }
  }
  return [];
}

function countBy(
  list: ReadonlyArray<Record<string, unknown>>,
  field: string,
): Record<string, number> {
  const out: Record<string, number> = {};
  for (const item of list) {
    const key = typeof item[field] === "string" ? (item[field] as string) : "unknown";
    out[key] = (out[key] ?? 0) + 1;
  }
  return out;
}

export default async function ComprehensiveReportPage(): Promise<React.JSX.Element> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    redirect("/login");
  }
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  const COMPLIANCE_FRAMEWORKS: ReadonlyArray<[string, string]> = [
    ["pcidss", "PCI DSS v4.0.1"],
    ["soc2", "SOC 2"],
    ["iso27001", "ISO/IEC 27001"],
    ["nist80053", "NIST SP 800-53"],
    ["hipaa", "HIPAA"],
    ["cisaws", "CIS AWS"],
  ];

  // One parallel sweep across every module. safeFetch-style: never throws.
  const [
    tenantMe,
    findings,
    engagements,
    pentest,
    aiAssets,
    aiControls,
    basRuns,
    basChains,
    scans,
    cloud,
    drift,
    soc,
    ueba,
    rba,
    intel,
    reports,
    ...frameworks
  ] = await Promise.all([
    fetchModule("/v1/tenants/me", token),
    fetchModule("/v1/findings?limit=500", token),
    fetchModule("/v1/engagements?limit=200", token),
    fetchModule("/v1/pentest/runs", token),
    fetchModule("/v1/ai-audit/assets", token),
    fetchModule("/v1/ai-audit/controls", token),
    fetchModule("/v1/bas/runs", token),
    fetchModule("/v1/bas/chains", token),
    fetchModule("/v1/scans", token),
    fetchModule("/v1/cloud/inventory", token),
    fetchModule("/v1/cloud/drift/findings", token),
    fetchModule("/v1/soc/alerts", token),
    fetchModule("/v1/ueba/anomalies", token),
    fetchModule("/v1/rba/decisions", token),
    fetchModule("/v1/intel/feeds", token),
    fetchModule("/v1/reports", token),
    ...COMPLIANCE_FRAMEWORKS.map(([code]) =>
      fetchModule(`/v1/compliance/frameworks/${code}`, token),
    ),
  ]);

  const findingRows = rows(findings.data);
  const sev = countBy(findingRows, "severity");
  const status = countBy(findingRows, "status");
  const engRows = rows(engagements.data);
  const activeEng = engRows.filter((e) => e["status"] === "active").length;

  const critical = sev["critical"] ?? 0;
  const high = sev["high"] ?? 0;
  const medium = sev["medium"] ?? 0;
  const low = sev["low"] ?? 0;
  const info = sev["info"] ?? 0;
  const totalFindings = findingRows.length;
  // Simple weighted posture score (100 best). Mirrors the home KPI intent.
  const postureScore = Math.max(
    0,
    100 - Math.min(100, critical * 15 + high * 7 + medium * 2 + low),
  );

  const tenantName =
    tenantMe.ok && tenantMe.data !== null && typeof tenantMe.data === "object"
      ? ((tenantMe.data as Record<string, unknown>)["name"] as string | undefined) ?? "Tenant"
      : "Tenant";

  const na = (r: FetchResult): string =>
    r.ok ? "" : r.status === 403 ? " (no permission)" : " (unavailable)";

  const sections: ReportSection[] = [
    {
      key: "findings",
      title: "Vulnerability Findings",
      available: findings.ok,
      stats: [
        { label: "Total findings", value: findings.ok ? String(totalFindings) : "—" },
        { label: "Critical", value: findings.ok ? String(critical) : "—" },
        { label: "High", value: findings.ok ? String(high) : "—" },
        { label: "Medium", value: findings.ok ? String(medium) : "—" },
        { label: "Low / Info", value: findings.ok ? String(low + info) : "—" },
      ],
      note:
        findings.ok
          ? `Status breakdown: ${Object.entries(status)
              .map(([k, v]) => `${k}=${v}`)
              .join(", ") || "none"}.`
          : `Findings not accessible${na(findings)}.`,
    },
    {
      key: "engagements",
      title: "Engagements",
      available: engagements.ok,
      stats: [
        { label: "Total engagements", value: engagements.ok ? String(engRows.length) : "—" },
        { label: "Active", value: engagements.ok ? String(activeEng) : "—" },
      ],
      note: engagements.ok ? undefined : `Not accessible${na(engagements)}.`,
    },
    {
      key: "pentest",
      title: "Combined Pentest Orchestration",
      available: pentest.ok,
      stats: [{ label: "Pentest runs", value: pentest.ok ? String(rows(pentest.data).length) : "—" }],
      note: pentest.ok
        ? "Each run chains recon → scan → SCA/secret/IaC → ingest → BAS → attack-graph with cross-scanner correlation + dedup."
        : `Not accessible${na(pentest)}.`,
    },
    {
      key: "ai-audit",
      title: "AI Security Audit",
      available: aiAssets.ok || aiControls.ok,
      stats: [
        { label: "AI assets inventoried", value: aiAssets.ok ? String(rows(aiAssets.data).length) : "—" },
        { label: "AI governance controls", value: aiControls.ok ? String(rows(aiControls.data).length) : "—" },
      ],
      note: "Covers AI-BOM, prompt-injection / jailbreak probing (OWASP LLM Top-10 + MITRE ATLAS), model-file scan, and NIST AI RMF / ISO 42001 / EU AI Act controls.",
    },
    {
      key: "bas",
      title: "Breach & Attack Simulation",
      available: basRuns.ok || basChains.ok,
      stats: [
        { label: "BAS runs", value: basRuns.ok ? String(rows(basRuns.data).length) : "—" },
        { label: "Attack chains", value: basChains.ok ? String(rows(basChains.data).length) : "—" },
      ],
    },
    {
      key: "discovery",
      title: "Attack Surface & Discovery",
      available: scans.ok,
      stats: [{ label: "Discovery scans", value: scans.ok ? String(rows(scans.data).length) : "—" }],
      note: scans.ok ? undefined : `Not accessible${na(scans)}.`,
    },
    {
      key: "cloud",
      title: "Cloud Posture & Drift",
      available: cloud.ok || drift.ok,
      stats: [
        { label: "Cloud resources", value: cloud.ok ? String(rows(cloud.data).length) : "—" },
        { label: "Drift findings", value: drift.ok ? String(rows(drift.data).length) : "—" },
      ],
    },
    {
      key: "soc",
      title: "SOC Alerts",
      available: soc.ok,
      stats: [{ label: "Correlated alerts", value: soc.ok ? String(rows(soc.data).length) : "—" }],
    },
    {
      key: "ueba",
      title: "UEBA Behavioural Anomalies",
      available: ueba.ok,
      stats: [{ label: "Anomalies", value: ueba.ok ? String(rows(ueba.data).length) : "—" }],
    },
    {
      key: "rba",
      title: "Risk-Based Authentication",
      available: rba.ok,
      stats: [{ label: "Recent decisions", value: rba.ok ? String(rows(rba.data).length) : "—" }],
    },
    {
      key: "intel",
      title: "Threat Intelligence Feeds",
      available: intel.ok,
      stats: [{ label: "Feeds tracked", value: intel.ok ? String(rows(intel.data).length) : "—" }],
    },
    {
      key: "compliance",
      title: "Compliance Control Coverage",
      available: frameworks.some((f) => f.ok),
      stats: COMPLIANCE_FRAMEWORKS.map(([, label], i) => ({
        label,
        value: frameworks[i]?.ok === true ? `${rows(frameworks[i]?.data).length} controls` : "—",
      })),
      note: "Control catalogs mapped per framework; PCI DSS covers all 12 requirements (v4.0.1).",
    },
    {
      key: "reports",
      title: "Rendered Reports",
      available: reports.ok,
      stats: [{ label: "Reports on file", value: reports.ok ? String(rows(reports.data).length) : "—" }],
    },
  ];

  const model: ReportModel = {
    tenantName,
    generatedBy: session.user?.email ?? session.user?.name ?? "operator",
    generatedAtIso: new Date().toISOString(),
    kpis: {
      postureScore,
      totalFindings,
      critical,
      high,
      activeEngagements: activeEng,
    },
    severity: { critical, high, medium, low, info },
    sections,
    coverage: sections.map((s) => ({ title: s.title, available: s.available })),
  };

  return <ReportingClient model={model} />;
}
