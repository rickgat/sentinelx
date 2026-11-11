import { redirect } from "next/navigation";
import {
  Activity,
  AlertTriangle,
  Building2,
  ClipboardList,
  Crosshair,
  ShieldAlert,
  TrendingUp,
} from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";
import type { Asset, Engagement, Finding, Page } from "@/lib/types";
import type { BasRunHistoryItem } from "../bas/bas-client";
import type { ScanRecord } from "../scans/scans-client";
import { AnalyticsClient } from "./analytics-client";

/**
 * Analytics dashboard — comprehensive aggregate view across the tenant.
 *
 * SSR fan-out fetches all data in parallel. Charts + tables render on the
 * client using recharts. Static counters render server-side so the page
 * is useful even before JS hydrates.
 */

interface BasRunBody {
  items: BasRunHistoryItem[];
}

interface ScanBody {
  items: ScanRecord[];
}

export default async function AnalyticsPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  // Fan-out fetches — each absorbs its own failure so a single broken
  // source doesn't blank the whole page.
  const [
    engagementsResult,
    findingsResult,
    assetsResult,
    scansResult,
    basRunsResult,
  ] = await Promise.allSettled([
    apiGet<Page<Engagement>>("/v1/engagements?limit=200", token),
    apiGet<Page<Finding>>("/v1/findings?limit=500", token),
    apiGet<Page<Asset>>("/v1/assets?limit=500", token),
    apiGet<ScanBody>("/v1/scans?limit=200", token),
    apiGet<BasRunBody>("/v1/bas/runs?limit=200", token),
  ]);

  const engagements: Engagement[] =
    engagementsResult.status === "fulfilled" ? engagementsResult.value.items : [];
  const findings: Finding[] =
    findingsResult.status === "fulfilled" ? findingsResult.value.items : [];
  const assets: Asset[] =
    assetsResult.status === "fulfilled" ? assetsResult.value.items : [];
  const scans: ScanRecord[] =
    scansResult.status === "fulfilled" ? scansResult.value.items : [];
  const basRuns: BasRunHistoryItem[] =
    basRunsResult.status === "fulfilled" ? basRunsResult.value.items : [];

  void (engagementsResult instanceof ApiError);

  // -------- Derived aggregates --------------------------------------------

  const findingsBySeverity = bucketCounts(findings.map((f) => f.severity));
  const findingsByStatus = bucketCounts(findings.map((f) => f.status));
  const engagementsByStatus = bucketCounts(engagements.map((e) => e.status));
  const assetsByKind = bucketCounts(assets.map((a) => a.kind));
  const basByOutcome = bucketCounts(basRuns.map((b) => b.outcome));
  const basByTechnique = bucketCounts(basRuns.map((b) => b.technique_id));

  // Severity-weighted "risk pressure" — informational only.
  const severityWeight: Record<string, number> = {
    critical: 10,
    high: 5,
    medium: 2,
    low: 1,
    info: 0,
  };
  const riskPressure = findings.reduce(
    (acc, f) => acc + (severityWeight[f.severity] ?? 0),
    0,
  );

  // Findings per day (last 14 days, using last_seen).
  const findingsTimeline = timelineFromIso(
    findings.map((f) => f.last_seen),
    14,
  );

  // Scans per day (last 14 days, using finished_at).
  const scansTimeline = timelineFromIso(
    scans.map((s) => s.finished_at),
    14,
  );

  // Findings inside scans = total scan-derived findings.
  const scanFindingsCount = scans.reduce(
    (acc, s) => acc + (Array.isArray(s.findings) ? s.findings.length : 0),
    0,
  );

  // Average scan findings per scan, last-10 trend.
  const recentScans = [...scans].slice(0, 10);
  const recentBasRuns = [...basRuns].slice(0, 10);

  // Top targets — group scans by target.
  const targetCounts = new Map<string, number>();
  for (const s of scans) {
    targetCounts.set(s.target, (targetCounts.get(s.target) ?? 0) + s.findings.length);
  }
  const topTargets = Array.from(targetCounts.entries())
    .map(([target, findings_count]) => ({ target, findings_count }))
    .sort((a, b) => b.findings_count - a.findings_count)
    .slice(0, 10);

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <div className="flex items-center gap-2">
          <TrendingUp className="h-5 w-5 text-accent" aria-hidden />
          <h1 className="text-xl font-semibold">Analytics & Reporting</h1>
        </div>
        <p className="text-sm text-muted-foreground">
          Cross-tenant aggregates across engagements, assets, findings, scans, and
          BAS runs. Numbers reflect the current bearer-token tenant.
        </p>
      </header>

      {/* Top-line counters (SSR — no JS needed) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <Counter
          label="Engagements"
          value={engagements.length}
          icon={ClipboardList}
        />
        <Counter
          label="Assets"
          value={assets.length}
          icon={Building2}
        />
        <Counter
          label="Findings"
          value={findings.length}
          icon={AlertTriangle}
        />
        <Counter
          label="Scans"
          value={scans.length}
          sub={`${scanFindingsCount} sub-findings`}
          icon={ShieldAlert}
        />
        <Counter
          label="BAS Runs"
          value={basRuns.length}
          icon={Crosshair}
        />
        <Counter
          label="Risk Pressure"
          value={riskPressure}
          sub="Σ severity-weighted"
          icon={Activity}
        />
      </div>

      {/* Section: findings */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Findings</CardTitle>
          <CardDescription>
            Distribution by severity, status, and last-seen timeline.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <AnalyticsClient
            findingsBySeverity={findingsBySeverity}
            findingsByStatus={findingsByStatus}
            findingsTimeline={findingsTimeline}
            engagementsByStatus={engagementsByStatus}
            assetsByKind={assetsByKind}
            basByOutcome={basByOutcome}
            basByTechnique={basByTechnique}
            scansTimeline={scansTimeline}
            recentScans={recentScans}
            recentBasRuns={recentBasRuns}
            topTargets={topTargets}
          />
        </CardContent>
      </Card>

      {/* Static summary table for screen-readers / no-JS */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Engagement portfolio</CardTitle>
            <CardDescription>By status, across all engagements in the tenant.</CardDescription>
          </CardHeader>
          <CardContent>
            <KvTable rows={engagementsByStatus} totalLabel="Total engagements" />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Asset catalogue</CardTitle>
            <CardDescription>By kind, derived from <code>asset.kind</code>.</CardDescription>
          </CardHeader>
          <CardContent>
            <KvTable rows={assetsByKind} totalLabel="Total assets" />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function Counter({
  label,
  value,
  sub,
  icon: Icon,
}: {
  label: string;
  value: number;
  sub?: string;
  icon: React.ComponentType<{ className?: string; "aria-hidden"?: boolean }>;
}) {
  return (
    <div className="rounded-sx border border-border bg-card p-3">
      <div className="flex items-center gap-2 text-muted-foreground">
        <Icon className="h-3.5 w-3.5" aria-hidden />
        <span className="text-[10px] uppercase tracking-wider">{label}</span>
      </div>
      <p className="mt-1 text-2xl font-semibold tabular-nums">{value.toLocaleString()}</p>
      {sub !== undefined ? (
        <p className="text-[10px] text-muted-foreground mt-0.5">{sub}</p>
      ) : null}
    </div>
  );
}

function KvTable({
  rows,
  totalLabel,
}: {
  rows: Array<{ key: string; count: number }>;
  totalLabel: string;
}) {
  const total = rows.reduce((acc, r) => acc + r.count, 0);
  if (rows.length === 0) {
    return <p className="text-xs text-muted-foreground">No data.</p>;
  }
  return (
    <table className="w-full text-xs">
      <tbody>
        {rows.map((r) => (
          <tr key={r.key} className="border-b border-border last:border-0">
            <td className="py-1.5 capitalize">{r.key.replace(/_/g, " ")}</td>
            <td className="py-1.5 text-right tabular-nums">{r.count}</td>
            <td className="py-1.5 text-right text-muted-foreground tabular-nums">
              {total > 0 ? `${Math.round((r.count / total) * 100)}%` : "—"}
            </td>
          </tr>
        ))}
        <tr className="font-medium">
          <td className="pt-2">{totalLabel}</td>
          <td className="pt-2 text-right tabular-nums">{total}</td>
          <td className="pt-2 text-right text-muted-foreground">100%</td>
        </tr>
      </tbody>
    </table>
  );
}

function bucketCounts(values: string[]): Array<{ key: string; count: number }> {
  const m = new Map<string, number>();
  for (const v of values) {
    m.set(v, (m.get(v) ?? 0) + 1);
  }
  return Array.from(m.entries())
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count);
}

function timelineFromIso(
  isoTimestamps: string[],
  days: number,
): Array<{ date: string; count: number }> {
  const buckets = new Map<string, number>();
  const now = new Date();
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(now);
    d.setUTCDate(d.getUTCDate() - i);
    const key = d.toISOString().slice(0, 10);
    buckets.set(key, 0);
  }
  for (const iso of isoTimestamps) {
    const key = iso.slice(0, 10);
    if (buckets.has(key)) {
      buckets.set(key, (buckets.get(key) ?? 0) + 1);
    }
  }
  return Array.from(buckets.entries()).map(([date, count]) => ({ date, count }));
}
