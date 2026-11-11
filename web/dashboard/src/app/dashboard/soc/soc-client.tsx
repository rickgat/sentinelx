"use client";

import * as React from "react";
import { Siren } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SeverityBadge } from "@/components/severity-badge";
import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/types";

/**
 * Wire projection of `GET /v1/soc/alerts` (one item).
 *
 * Mirrors `crates/sx-api/src/view/soc_view.rs::SocAlertView`. `severity`
 * is left as a free-form string upstream — we narrow to the dashboard's
 * `Severity` union at render time, defaulting unknowns to `"info"`.
 */
export interface SocAlert {
  id: string;
  severity: string;
  kind: string;
  title: string;
  fired_at: string;
  tenant_id: string | null;
}

const SEVERITIES: ReadonlyArray<Severity | "all"> = [
  "all",
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

const REFRESH_MS = 30_000;

interface AlertsEnvelope {
  data?: { items: SocAlert[] };
  error?: { code?: string; message?: string; request_id?: string };
}

interface Props {
  initialData: ReadonlyArray<SocAlert>;
  apiAvailable: boolean;
}

function narrowSeverity(raw: string): Severity {
  if (
    raw === "critical" ||
    raw === "high" ||
    raw === "medium" ||
    raw === "low" ||
    raw === "info"
  ) {
    return raw;
  }
  return "info";
}

function truncateTenant(raw: string | null): string {
  if (raw === null || raw.length === 0) {
    return "global";
  }
  if (raw.length <= 12) {
    return raw;
  }
  return `${raw.slice(0, 8)}…`;
}

function timeOf(iso: string): string {
  // Accept anything; surface the HH:MM:SS slice if present, else the raw string.
  if (iso.length >= 19 && iso.charAt(10) === "T") {
    return iso.slice(11, 19);
  }
  return iso;
}

export function SocClient({ initialData, apiAvailable }: Props) {
  const [rows, setRows] = React.useState<ReadonlyArray<SocAlert>>(initialData);
  const [severityFilter, setSeverityFilter] = React.useState<Severity | "all">("all");
  const [acknowledged, setAcknowledged] = React.useState<ReadonlyArray<string>>([]);
  const [refreshing, setRefreshing] = React.useState(false);
  const [available, setAvailable] = React.useState(apiAvailable);
  const [lastRefresh, setLastRefresh] = React.useState<string | null>(null);

  const refresh = React.useCallback(async () => {
    setRefreshing(true);
    try {
      const res = await fetch("/api/soc/alerts", { cache: "no-store" });
      const parsed: AlertsEnvelope = await res.json().catch(() => ({}));
      if (res.ok && parsed.data !== undefined) {
        setRows(parsed.data.items);
        setAvailable(true);
        setLastRefresh(new Date().toISOString());
      } else {
        setAvailable(false);
      }
    } catch {
      setAvailable(false);
    } finally {
      setRefreshing(false);
    }
  }, []);

  React.useEffect(() => {
    const id = window.setInterval(() => {
      void refresh();
    }, REFRESH_MS);
    return () => window.clearInterval(id);
  }, [refresh]);

  function acknowledge(id: string) {
    setAcknowledged((current) =>
      current.includes(id) ? current : [...current, id],
    );
  }

  const filtered = React.useMemo(() => {
    if (severityFilter === "all") {
      return rows;
    }
    return rows.filter((r) => narrowSeverity(r.severity) === severityFilter);
  }, [rows, severityFilter]);

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-start justify-between space-y-0">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Siren className="h-4 w-4 text-critical" aria-hidden />
              SOC alert feed
            </CardTitle>
            <CardDescription>
              Live correlator buffer from <code>GET /v1/soc/alerts</code>.
              Auto-refreshes every 30 s. Acknowledgements are local-only and
              reset on reload.
            </CardDescription>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <Label htmlFor="soc-severity">Severity</Label>
              <select
                id="soc-severity"
                value={severityFilter}
                onChange={(event) =>
                  setSeverityFilter(event.currentTarget.value as Severity | "all")
                }
                className="h-8 rounded-sx border border-border bg-transparent px-2 text-xs text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                {SEVERITIES.map((sev) => (
                  <option key={sev} value={sev} className="bg-card text-foreground">
                    {sev === "all" ? "All" : sev}
                  </option>
                ))}
              </select>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void refresh()}
              disabled={refreshing}
            >
              {refreshing ? "Refreshing…" : "Refresh"}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {!available ? (
            <div
              role="alert"
              className="mb-4 rounded-sx border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical"
            >
              API unavailable — SOC alerts could not be loaded.
            </div>
          ) : null}
          {lastRefresh !== null ? (
            <p className="mb-2 text-[10px] uppercase tracking-wide text-muted-foreground">
              Last refresh: {lastRefresh.slice(11, 19)} UTC
            </p>
          ) : null}
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Time</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Title</TableHead>
                <TableHead>Tenant</TableHead>
                <TableHead className="text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.length === 0 ? (
                <TableRow>
                  <TableCell
                    colSpan={5}
                    className="py-8 text-center text-xs text-muted-foreground"
                  >
                    No alerts yet — POST events to{" "}
                    <code>/v1/soc/events</code> to feed the correlator.
                  </TableCell>
                </TableRow>
              ) : (
                filtered.map((alert) => {
                  const isAck = acknowledged.includes(alert.id);
                  const sev = narrowSeverity(alert.severity);
                  return (
                    <TableRow
                      key={alert.id}
                      className={cn(isAck ? "opacity-40" : undefined)}
                    >
                      <TableCell className="text-xs font-mono">
                        {timeOf(alert.fired_at)}
                      </TableCell>
                      <TableCell>
                        <SeverityBadge severity={sev} />
                      </TableCell>
                      <TableCell className="text-sm">{alert.title}</TableCell>
                      <TableCell
                        className="text-xs font-mono"
                        title={alert.tenant_id ?? "global"}
                      >
                        {truncateTenant(alert.tenant_id)}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={isAck}
                          onClick={() => acknowledge(alert.id)}
                        >
                          {isAck ? "Acknowledged" : "Acknowledge"}
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
