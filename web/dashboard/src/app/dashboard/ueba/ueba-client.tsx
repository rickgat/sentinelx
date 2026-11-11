"use client";

import * as React from "react";
import { UserCheck } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

/**
 * UEBA dashboard — recent anomalies + per-user baseline drill-down.
 */

export interface UebaAnomalyDimView {
  dimension: string;
  score: number;
  reason: string;
}

export interface UebaAnomalyView {
  id: string;
  tenant_id?: string;
  user_id: string;
  event_id?: string;
  score: number;
  dimensions: UebaAnomalyDimView[];
  severity: string;
  detected_at: string;
}

export interface UebaBaselineView {
  tenant_id?: string;
  user_id: string;
  login_hour_counts: number[];
  ip_prefixes: Record<string, number>;
  accessed_assets: Record<string, number>;
  updated_at?: string;
}

interface BaselineEnvelope {
  data?: UebaBaselineView;
  error?: { code?: string; message?: string };
}

const SEVERITY_VARIANT: Record<string, "critical" | "high" | "medium" | "low" | "info"> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
};

function severityBadge(label: string) {
  const variant = SEVERITY_VARIANT[label] ?? "info";
  return <Badge variant={variant}>{label}</Badge>;
}

interface UebaClientProps {
  initialAnomalies: ReadonlyArray<UebaAnomalyView>;
}

export function UebaClient({ initialAnomalies }: UebaClientProps) {
  const [anomalies] = React.useState<ReadonlyArray<UebaAnomalyView>>(initialAnomalies);
  const [selected, setSelected] = React.useState<UebaAnomalyView | null>(null);
  const [baseline, setBaseline] = React.useState<UebaBaselineView | null>(null);
  const [loadingBaseline, setLoadingBaseline] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const onSelect = React.useCallback(async (row: UebaAnomalyView) => {
    setSelected(row);
    setBaseline(null);
    setError(null);
    setLoadingBaseline(true);
    try {
      const res = await fetch(
        `/api/ueba/baselines/${encodeURIComponent(row.user_id)}`,
        { cache: "no-store" },
      );
      const body = (await res.json()) as BaselineEnvelope;
      if (!res.ok || body.data === undefined) {
        setError(body.error?.message ?? `Request failed with status ${res.status.toString()}`);
        return;
      }
      setBaseline(body.data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "request failed");
    } finally {
      setLoadingBaseline(false);
    }
  }, []);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <UserCheck className="h-5 w-5 text-accent" aria-hidden />
        <h1 className="text-lg font-semibold tracking-tight">UEBA</h1>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Recent anomalies</CardTitle>
          <CardDescription>
            Per-user behavioural-baseline deviations, sorted by score
            descending. Click a row to inspect the user&apos;s baseline.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {anomalies.length === 0 ? (
            <p className="text-sm text-muted-foreground">No anomalies detected yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Detected at</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Score</TableHead>
                  <TableHead>Dimensions</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead aria-label="actions" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {anomalies.map((a) => (
                  <TableRow key={a.id}>
                    <TableCell className="font-mono text-xs">
                      {a.detected_at}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{a.user_id}</TableCell>
                    <TableCell>{severityBadge(a.severity)}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {a.score.toFixed(2)}
                    </TableCell>
                    <TableCell className="text-xs">
                      {a.dimensions.map((d) => d.dimension).join(", ")}
                    </TableCell>
                    <TableCell className="text-xs">
                      {a.dimensions.map((d) => d.reason).join("; ")}
                    </TableCell>
                    <TableCell>
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => {
                          void onSelect(a);
                        }}
                      >
                        Baseline
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {selected !== null && (
        <Card>
          <CardHeader>
            <CardTitle>Baseline for {selected.user_id}</CardTitle>
            <CardDescription>
              Bounded login-hour histogram (24 buckets), most-seen /16 IP
              prefixes (cap 100), accessed asset ids (cap 100).
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {loadingBaseline && (
              <p className="text-sm text-muted-foreground">Loading baseline…</p>
            )}
            {error !== null && (
              <p className="text-sm text-critical">{error}</p>
            )}
            {baseline !== null && !loadingBaseline && (
              <BaselinePanels baseline={baseline} />
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function BaselinePanels({ baseline }: { baseline: UebaBaselineView }) {
  const hours = baseline.login_hour_counts;
  const maxBucket = Math.max(1, ...hours);
  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
      <div>
        <h3 className="mb-2 text-sm font-semibold">Login hour-of-day (UTC)</h3>
        <div className="flex items-end gap-1">
          {hours.map((count, h) => (
            <div
              key={h}
              className="flex w-3 flex-col items-center"
              title={`hour ${h.toString()}: ${count.toString()}`}
            >
              <div
                className="w-full rounded-sm bg-accent"
                style={{ height: `${((count / maxBucket) * 60).toString()}px` }}
              />
              <span className="mt-1 text-[10px] text-muted-foreground">
                {h % 6 === 0 ? h : ""}
              </span>
            </div>
          ))}
        </div>
      </div>

      <div>
        <h3 className="mb-2 text-sm font-semibold">/16 IP prefixes</h3>
        <ul className="space-y-1 text-xs">
          {Object.entries(baseline.ip_prefixes).length === 0 && (
            <li className="text-muted-foreground">None observed.</li>
          )}
          {Object.entries(baseline.ip_prefixes)
            .sort((a, b) => b[1] - a[1])
            .map(([prefix, count]) => (
              <li key={prefix} className="font-mono">
                <span>{prefix}</span>
                <span className="ml-2 text-muted-foreground">
                  ({count.toString()})
                </span>
              </li>
            ))}
        </ul>
      </div>

      <div>
        <h3 className="mb-2 text-sm font-semibold">Accessed assets</h3>
        <ul className="space-y-1 text-xs">
          {Object.entries(baseline.accessed_assets).length === 0 && (
            <li className="text-muted-foreground">None observed.</li>
          )}
          {Object.entries(baseline.accessed_assets)
            .sort((a, b) => b[1] - a[1])
            .map(([asset, count]) => (
              <li key={asset} className="font-mono">
                <span>{asset}</span>
                <span className="ml-2 text-muted-foreground">
                  ({count.toString()})
                </span>
              </li>
            ))}
        </ul>
      </div>
    </div>
  );
}
