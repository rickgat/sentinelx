import { redirect } from "next/navigation";
import { CheckCircle2, RefreshCw, TrendingDown, TrendingUp } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { apiGet } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";
import type {
  MttrBucket,
  RegressingTechnique,
  RegressionEvent,
  RegressionList,
  RemediationMetrics,
} from "@/types/remediation";

const DEFAULT_WINDOW_DAYS = 30;
const REGRESSIONS_LIMIT = 25;

/**
 * SSR dashboard for P1-011 remediation outcomes.
 *
 * Three panels:
 *   - MTTR by severity (critical -> info)
 *   - Headline regression rate over the window
 *   - Top regressing `check_id`s with their closure / regression counts
 *
 * MTTR is stored as seconds; the page renders human-friendly
 * `days / hours` per spec.
 */
export default async function RemediationOutcomesPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  const [metricsResult, regressionsResult] = await Promise.allSettled([
    apiGet<RemediationMetrics>(
      `/v1/remediation/outcomes/metrics?window_days=${DEFAULT_WINDOW_DAYS}`,
      token,
    ),
    apiGet<RegressionList>(
      `/v1/remediation/outcomes/regressions?limit=${REGRESSIONS_LIMIT}`,
      token,
    ),
  ]);

  const metrics: RemediationMetrics | null =
    metricsResult.status === "fulfilled" ? metricsResult.value : null;
  const regressions: RegressionEvent[] =
    regressionsResult.status === "fulfilled" ? regressionsResult.value.items : [];

  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <div className="flex items-center gap-2">
          <CheckCircle2 className="h-5 w-5 text-accent" aria-hidden />
          <h1 className="text-xl font-semibold">Remediation Outcomes</h1>
        </div>
        <p className="text-sm text-muted-foreground">
          MTTR by severity, regression rate, and top regressing checks. Window:
          last {DEFAULT_WINDOW_DAYS} days.
        </p>
      </header>

      {metrics === null ? (
        <Card>
          <CardContent className="py-6 text-sm text-muted-foreground">
            No metrics available. Outcomes are recorded automatically when a
            finding transitions to <code>closed</code>; regressions are
            detected when a finding for the same asset + check re-opens
            within the lookback window.
          </CardContent>
        </Card>
      ) : (
        <>
          <Headline metrics={metrics} />
          <div className="grid gap-4 lg:grid-cols-2">
            <MttrPanel buckets={metrics.mttr_by_severity} />
            <TopRegressingPanel items={metrics.top_regressing} />
          </div>
          <RegressionsPanel items={regressions} />
        </>
      )}
    </div>
  );
}

function Headline({ metrics }: { metrics: RemediationMetrics }) {
  const ratePercent = (metrics.regression_rate * 100).toFixed(1);
  const isHealthy = metrics.regression_rate < 0.05;
  const Icon = isHealthy ? TrendingDown : TrendingUp;
  const variant = isHealthy ? "success" : "critical";
  return (
    <div className="grid gap-4 sm:grid-cols-3">
      <Card>
        <CardHeader className="pb-2">
          <CardDescription>Closures (window)</CardDescription>
          <CardTitle className="text-2xl">{metrics.closure_count}</CardTitle>
        </CardHeader>
      </Card>
      <Card>
        <CardHeader className="pb-2">
          <CardDescription>Regressions</CardDescription>
          <CardTitle className="text-2xl">{metrics.regression_count}</CardTitle>
        </CardHeader>
      </Card>
      <Card>
        <CardHeader className="pb-2">
          <CardDescription className="flex items-center gap-1">
            <Icon className="h-3 w-3" aria-hidden /> Regression rate
          </CardDescription>
          <CardTitle className="text-2xl flex items-center gap-2">
            {ratePercent}%
            <Badge variant={variant}>
              {isHealthy ? "healthy" : "watch"}
            </Badge>
          </CardTitle>
        </CardHeader>
      </Card>
    </div>
  );
}

function MttrPanel({ buckets }: { buckets: MttrBucket[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">MTTR by severity</CardTitle>
        <CardDescription>
          Mean time-to-remediate from open to closed, per severity bucket.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {buckets.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No closures recorded in the window yet.
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead className="text-xs text-muted-foreground uppercase tracking-wider">
              <tr>
                <th className="text-left font-medium pb-2">Severity</th>
                <th className="text-right font-medium pb-2">Closures</th>
                <th className="text-right font-medium pb-2">MTTR</th>
              </tr>
            </thead>
            <tbody>
              {buckets.map((b) => (
                <tr key={b.severity} className="border-t border-border">
                  <td className="py-2 font-mono">
                    <Badge variant={badgeVariantForSeverity(b.severity)}>
                      {b.severity}
                    </Badge>
                  </td>
                  <td className="py-2 text-right font-mono">{b.sample_size}</td>
                  <td className="py-2 text-right font-mono">
                    {formatDuration(b.mttr_seconds)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </CardContent>
    </Card>
  );
}

function TopRegressingPanel({ items }: { items: RegressingTechnique[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center gap-1">
          <RefreshCw className="h-4 w-4" aria-hidden /> Top regressing checks
        </CardTitle>
        <CardDescription>
          Checks that came back inside the window, ordered by regression count.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {items.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No regressions in the window. Nothing has re-opened.
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead className="text-xs text-muted-foreground uppercase tracking-wider">
              <tr>
                <th className="text-left font-medium pb-2">check_id</th>
                <th className="text-right font-medium pb-2">Regressions</th>
                <th className="text-right font-medium pb-2">Closures</th>
              </tr>
            </thead>
            <tbody>
              {items.map((t) => (
                <tr key={t.check_id} className="border-t border-border">
                  <td className="py-2 font-mono break-all">{t.check_id}</td>
                  <td className="py-2 text-right font-mono">
                    {t.regression_count}
                  </td>
                  <td className="py-2 text-right font-mono">
                    {t.closure_count}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </CardContent>
    </Card>
  );
}

function RegressionsPanel({ items }: { items: RegressionEvent[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Recent regression events</CardTitle>
        <CardDescription>
          Newest-first feed of finding re-opens within the lookback window
          (capped at {REGRESSIONS_LIMIT}).
        </CardDescription>
      </CardHeader>
      <CardContent>
        {items.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No regression events recorded.
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead className="text-xs text-muted-foreground uppercase tracking-wider">
              <tr>
                <th className="text-left font-medium pb-2">Detected</th>
                <th className="text-left font-medium pb-2">Asset</th>
                <th className="text-left font-medium pb-2">check_id</th>
                <th className="text-right font-medium pb-2">Gap</th>
              </tr>
            </thead>
            <tbody>
              {items.map((r) => (
                <tr key={r.id} className="border-t border-border">
                  <td className="py-2 font-mono text-xs">{r.detected_at}</td>
                  <td className="py-2 font-mono">{r.asset_id}</td>
                  <td className="py-2 font-mono break-all">{r.check_id}</td>
                  <td className="py-2 text-right font-mono">
                    {formatDuration(r.gap_seconds)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </CardContent>
    </Card>
  );
}

function formatDuration(seconds: number): string {
  if (seconds <= 0) {
    return "0s";
  }
  const days = Math.floor(seconds / 86_400);
  const hours = Math.floor((seconds % 86_400) / 3_600);
  if (days > 0) {
    return hours > 0 ? `${days}d ${hours}h` : `${days}d`;
  }
  if (hours > 0) {
    const mins = Math.floor((seconds % 3_600) / 60);
    return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
  }
  const mins = Math.floor(seconds / 60);
  if (mins > 0) {
    return `${mins}m`;
  }
  return `${seconds}s`;
}

function badgeVariantForSeverity(
  severity: string,
):
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "outline" {
  switch (severity) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    case "info":
      return "info";
    default:
      return "outline";
  }
}
