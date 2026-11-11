"use client";

import * as React from "react";
import { ShieldAlert } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/components/toast";
import type { Asset, Engagement } from "@/lib/types";

export interface ScanFinding {
  check_id: string;
  severity: string;
  title: string;
  description: string;
  recommendation?: string;
}

export interface ScanRecord {
  id: string;
  tenant_id: string;
  kind: string;
  target: string;
  engagement_id?: string;
  started_at: string;
  finished_at: string;
  status: string;
  error?: string;
  findings: ScanFinding[];
}

interface ScanResponse {
  data?: ScanRecord;
  error?: { code?: string; message?: string };
}

export function ScansClient({
  initial,
  engagements,
  assets,
}: {
  initial: ReadonlyArray<ScanRecord>;
  engagements: ReadonlyArray<Engagement>;
  assets: ReadonlyArray<Asset>;
}) {
  const toast = useToast();
  const [target, setTarget] = React.useState("");
  const [engagementId, setEngagementId] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);
  const [scans, setScans] = React.useState<ReadonlyArray<ScanRecord>>(initial);
  const [expandedId, setExpandedId] = React.useState<string | null>(
    initial.length > 0 ? (initial[0]?.id ?? null) : null,
  );

  // Filter target suggestions by selected engagement: scopes + asset
  // identifiers. Web-friendly URLs ("https://…", "host.domain") only.
  const targetSuggestions = React.useMemo<TargetSuggestion[]>(() => {
    const selected = engagements.find((e) => e.id === engagementId);
    const out: TargetSuggestion[] = [];
    const seen = new Set<string>();
    function push(v: string, label: string) {
      if (v.length === 0 || seen.has(v)) return;
      seen.add(v);
      out.push({ value: v, label });
    }
    if (selected !== undefined) {
      for (const s of selected.scopes ?? []) push(s, `scope of ${selected.name}`);
    }
    for (const a of assets) {
      if (selected === undefined || a.engagement_id === engagementId) {
        // Only domain/url/host kinds make sense for HTTP probe.
        if (a.kind === "domain" || a.kind === "url" || a.kind === "host") {
          push(a.identifier, `${a.kind}`);
        }
      }
    }
    if (selected === undefined) {
      for (const e of engagements) {
        for (const s of e.scopes ?? []) push(s, `scope of ${e.name}`);
      }
    }
    return out;
  }, [engagements, assets, engagementId]);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const t = target.trim();
    if (t.length === 0) {
      toast.push({ kind: "error", message: "target is required." });
      return;
    }
    setSubmitting(true);
    try {
      const body: Record<string, unknown> = { target: t };
      if (engagementId.trim().length > 0) {
        body.engagement_id = engagementId.trim();
      }
      const res = await fetch("/api/scans/http-headers", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const parsed: ScanResponse = await res.json().catch(() => ({}));
      if (!res.ok || parsed.data === undefined) {
        const detail = parsed.error?.message ?? `Scan failed (${res.status})`;
        toast.push({ kind: "error", message: detail });
        return;
      }
      const newScan = parsed.data;
      setScans((current) => [newScan, ...current].slice(0, 200));
      setExpandedId(newScan.id);
      toast.push({
        kind: "success",
        message: `Scan finished — ${newScan.findings.length} findings.`,
      });
    } catch {
      toast.push({ kind: "error", message: "Network error — please retry." });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-accent" aria-hidden />
            HTTP Security Header Scan
          </CardTitle>
          <CardDescription>
            Probes a target for missing security headers, server fingerprint, and TLS
            policy hints. Passive — sends one GET request.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="scan-target">Target</Label>
              <Input
                id="scan-target"
                value={target}
                list="scan-target-options"
                onChange={(event) => setTarget(event.currentTarget.value)}
                placeholder="select or type host / scope / URL"
                required
              />
              <datalist id="scan-target-options">
                {targetSuggestions.map((s) => (
                  <option key={s.value} value={s.value} label={s.label} />
                ))}
              </datalist>
              {targetSuggestions.length > 0 ? (
                <p className="text-[11px] text-muted-foreground">
                  Start typing to filter {targetSuggestions.length} suggestion
                  {targetSuggestions.length === 1 ? "" : "s"}.
                </p>
              ) : null}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="scan-engagement">Engagement (optional)</Label>
              <select
                id="scan-engagement"
                value={engagementId}
                onChange={(event) => setEngagementId(event.currentTarget.value)}
                className="h-9 w-full rounded-sx border border-border bg-transparent px-2 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                <option value="" className="bg-card text-foreground">
                  — None —
                </option>
                {engagements.map((e) => (
                  <option key={e.id} value={e.id} className="bg-card text-foreground">
                    {e.name}
                  </option>
                ))}
              </select>
              {engagementId.length > 0 ? (
                <p className="text-[11px] font-mono text-muted-foreground">
                  {engagementId}
                </p>
              ) : null}
            </div>
            <div className="md:col-span-2 flex justify-end">
              <Button type="submit" disabled={submitting}>
                {submitting ? "Scanning…" : "Run scan"}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Scan history</CardTitle>
          <CardDescription>
            Persisted server-side via <code className="text-foreground">GET /v1/scans</code>.
            Click a row to expand findings.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Time</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Findings</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {scans.length === 0 ? (
                <TableRow>
                  <TableCell
                    colSpan={4}
                    className="py-8 text-center text-xs text-muted-foreground"
                  >
                    No scans yet — run one above.
                  </TableCell>
                </TableRow>
              ) : (
                scans.map((scan) => (
                  <React.Fragment key={scan.id}>
                    <TableRow
                      className="cursor-pointer"
                      onClick={() =>
                        setExpandedId(expandedId === scan.id ? null : scan.id)
                      }
                    >
                      <TableCell className="text-xs font-mono">
                        {scan.finished_at.slice(11, 19)}
                      </TableCell>
                      <TableCell className="text-xs">{scan.target}</TableCell>
                      <TableCell>
                        <StatusBadge status={scan.status} />
                      </TableCell>
                      <TableCell className="text-xs text-right font-mono">
                        {scan.findings.length}
                      </TableCell>
                    </TableRow>
                    {expandedId === scan.id ? (
                      <TableRow>
                        <TableCell colSpan={4} className="p-0">
                          <div className="bg-muted/20 p-3 space-y-2">
                            {scan.error !== undefined ? (
                              <p className="text-xs text-critical">{scan.error}</p>
                            ) : null}
                            {scan.findings.length === 0 ? (
                              <p className="text-xs text-muted-foreground">
                                No findings recorded.
                              </p>
                            ) : (
                              <div className="space-y-2">
                                {scan.findings.map((f) => (
                                  <div
                                    key={f.check_id}
                                    className="rounded-sx border border-border bg-card p-2"
                                  >
                                    <div className="flex items-center gap-2">
                                      <SeverityBadge severity={f.severity} />
                                      <span className="text-xs font-mono text-muted-foreground">
                                        {f.check_id}
                                      </span>
                                    </div>
                                    <p className="mt-1 text-xs font-medium">{f.title}</p>
                                    <p className="mt-1 text-[11px] text-muted-foreground">
                                      {f.description}
                                    </p>
                                    {f.recommendation !== undefined ? (
                                      <p className="mt-1 text-[11px] text-accent">
                                        Fix: <code>{f.recommendation}</code>
                                      </p>
                                    ) : null}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ) : null}
                  </React.Fragment>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  if (status === "ok") {
    return <Badge variant="success">{status}</Badge>;
  }
  return <Badge variant="critical">{status}</Badge>;
}

interface TargetSuggestion {
  value: string;
  label: string;
}

function SeverityBadge({ severity }: { severity: string }) {
  switch (severity) {
    case "critical":
      return <Badge variant="critical">{severity}</Badge>;
    case "high":
      return <Badge variant="critical">{severity}</Badge>;
    case "medium":
      return <Badge variant="medium">{severity}</Badge>;
    case "low":
      return <Badge variant="info">{severity}</Badge>;
    default:
      return <Badge variant="outline">{severity}</Badge>;
  }
}
