"use client";

import * as React from "react";
import { ScrollText } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
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

/**
 * Wire projection of `GET /v1/logs` (one item).
 *
 * Mirrors `crates/sx-api/src/view/log_ingest_view.rs::OcsfEventView`.
 * The `metadata.tenant_id` is server-stamped from the bearer's tenant
 * claim, so this dashboard only renders rows the caller is entitled to.
 */
export interface OcsfMetadataView {
  version: string;
  product: string;
  source_type: string;
  tenant_id: string;
}

export interface ObservableView {
  name: string;
  type: string;
  value: string;
}

export interface OcsfEventView {
  class_uid: number;
  category_uid: number;
  time: string;
  severity_id: number;
  raw: string;
  metadata: OcsfMetadataView;
  observables: ObservableView[];
}

const SUPPORTED_SOURCES: ReadonlyArray<string> = [
  "cloudtrail",
  "syslog_rfc5424",
  "suricata_eve",
];

interface LogsEnvelope {
  data?: { items: OcsfEventView[] };
  error?: { code?: string; message?: string; request_id?: string };
}

interface IngestEnvelope {
  data?: { accepted: number };
  error?: { code?: string; message?: string; request_id?: string };
}

interface Props {
  initialData: ReadonlyArray<OcsfEventView>;
  apiAvailable: boolean;
}

function severityLabel(id: number): string {
  switch (id) {
    case 0:
      return "unknown";
    case 1:
      return "info";
    case 2:
      return "low";
    case 3:
      return "medium";
    case 4:
      return "high";
    case 5:
      return "critical";
    case 6:
      return "fatal";
    default:
      return "unknown";
  }
}

function severityClass(id: number): string {
  switch (id) {
    case 4:
      return "bg-warning/20 text-warning";
    case 5:
    case 6:
      return "bg-critical/20 text-critical";
    case 3:
      return "bg-accent/20 text-accent";
    default:
      return "bg-muted text-muted-foreground";
  }
}

function timeOf(iso: string): string {
  if (iso.length >= 19 && iso.charAt(10) === "T") {
    return iso.slice(11, 19);
  }
  return iso;
}

function truncate(raw: string, max: number): string {
  if (raw.length <= max) {
    return raw;
  }
  return `${raw.slice(0, max)}…`;
}

export function LogsClient({ initialData, apiAvailable }: Props) {
  const [rows, setRows] = React.useState<ReadonlyArray<OcsfEventView>>(initialData);
  const [refreshing, setRefreshing] = React.useState(false);
  const [available, setAvailable] = React.useState(apiAvailable);
  const [lastRefresh, setLastRefresh] = React.useState<string | null>(null);
  const [source, setSource] = React.useState<string>(SUPPORTED_SOURCES[0] ?? "cloudtrail");
  const [payload, setPayload] = React.useState<string>("");
  const [submitting, setSubmitting] = React.useState(false);
  const [submitError, setSubmitError] = React.useState<string | null>(null);
  const [submitOk, setSubmitOk] = React.useState<string | null>(null);

  const refresh = React.useCallback(async () => {
    setRefreshing(true);
    try {
      const res = await fetch("/api/logs?limit=50", { cache: "no-store" });
      const parsed: LogsEnvelope = await res.json().catch(() => ({}));
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

  async function handleIngest(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmitError(null);
    setSubmitOk(null);
    if (payload.trim().length === 0) {
      setSubmitError("Payload is required.");
      return;
    }
    setSubmitting(true);
    try {
      const res = await fetch("/api/logs/ingest", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ source, payload }),
        cache: "no-store",
      });
      const parsed: IngestEnvelope = await res.json().catch(() => ({}));
      if (res.ok && parsed.data !== undefined) {
        setSubmitOk(`Accepted ${parsed.data.accepted} event(s).`);
        setPayload("");
        await refresh();
      } else {
        setSubmitError(parsed.error?.message ?? `HTTP ${res.status}`);
      }
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : "submit failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-start justify-between space-y-0">
          <div>
            <CardTitle className="flex items-center gap-2">
              <ScrollText className="h-4 w-4 text-accent" aria-hidden />
              OCSF log events
            </CardTitle>
            <CardDescription>
              Recent ingested OCSF events from <code>GET /v1/logs</code>. The
              ring buffer is per-tenant (cap 10&nbsp;000 events). Use the
              ingest form below to submit a raw payload for parsing.
            </CardDescription>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => void refresh()}
            disabled={refreshing}
          >
            {refreshing ? "Refreshing…" : "Refresh"}
          </Button>
        </CardHeader>
        <CardContent>
          {!available ? (
            <div
              role="alert"
              className="mb-4 rounded-sx border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical"
            >
              API unavailable — log events could not be loaded.
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
                <TableHead>Source</TableHead>
                <TableHead>Class</TableHead>
                <TableHead>Observables</TableHead>
                <TableHead>Raw (preview)</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.length === 0 ? (
                <TableRow>
                  <TableCell
                    colSpan={6}
                    className="py-8 text-center text-xs text-muted-foreground"
                  >
                    No events yet — POST a payload to <code>/v1/logs/ingest</code>{" "}
                    or use the form below.
                  </TableCell>
                </TableRow>
              ) : (
                rows.map((event, idx) => (
                  <TableRow
                    key={`${event.metadata.source_type}-${event.time}-${idx}`}
                  >
                    <TableCell className="text-xs font-mono">
                      {timeOf(event.time)}
                    </TableCell>
                    <TableCell>
                      <span
                        className={`inline-flex items-center rounded-sx px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${severityClass(event.severity_id)}`}
                      >
                        {severityLabel(event.severity_id)}
                      </span>
                    </TableCell>
                    <TableCell className="text-xs font-mono">
                      {event.metadata.source_type}
                    </TableCell>
                    <TableCell className="text-xs font-mono">
                      {event.class_uid}/{event.category_uid}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {event.observables.length === 0
                        ? "—"
                        : `${event.observables.length} field(s)`}
                    </TableCell>
                    <TableCell className="text-xs font-mono">
                      {truncate(event.raw, 80)}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Manual ingest</CardTitle>
          <CardDescription>
            Submit a single raw payload to <code>POST /v1/logs/ingest</code>{" "}
            for parsing into an OCSF event. The list above refreshes on
            success.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form className="space-y-3" onSubmit={(e) => void handleIngest(e)}>
            <div className="space-y-1">
              <Label htmlFor="logs-source">Source</Label>
              <select
                id="logs-source"
                value={source}
                onChange={(event) => setSource(event.currentTarget.value)}
                className="h-9 w-full rounded-sx border border-border bg-transparent px-2 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                {SUPPORTED_SOURCES.map((s) => (
                  <option key={s} value={s} className="bg-card text-foreground">
                    {s}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-1">
              <Label htmlFor="logs-payload">Payload (raw text)</Label>
              <Input
                id="logs-payload"
                type="text"
                value={payload}
                onChange={(event) => setPayload(event.currentTarget.value)}
                placeholder={
                  source === "cloudtrail"
                    ? '{"eventTime":"2026-06-12T10:30:01Z",...}'
                    : source === "syslog_rfc5424"
                      ? "<134>1 2026-06-12T10:30:01Z host app 1 ID - message"
                      : '{"timestamp":"2026-06-12T10:30:01Z","event_type":"dns",...}'
                }
                disabled={submitting}
                maxLength={16384}
              />
              <p className="text-[10px] text-muted-foreground">
                Max 16&nbsp;384 bytes — payloads beyond this are rejected
                upstream.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <Button type="submit" size="sm" disabled={submitting}>
                {submitting ? "Submitting…" : "Ingest"}
              </Button>
              {submitOk !== null ? (
                <span className="text-xs text-accent" role="status">
                  {submitOk}
                </span>
              ) : null}
              {submitError !== null ? (
                <span className="text-xs text-critical" role="alert">
                  {submitError}
                </span>
              ) : null}
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
