"use client";

import * as React from "react";
import { Network } from "lucide-react";

import { Badge } from "@/components/ui/badge";
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
import type { Engagement } from "@/lib/types";

/**
 * Cyber Digital Twin viewer client.
 *
 * Calls the dashboard proxy at `/api/twin/{engagement_id}` and renders
 * three sections:
 *   1. Headline totals (assets, edges, compromised).
 *   2. An asset table — id, kind, identifier, risk score (as a horizontal
 *      progress bar) and compromise state badge.
 *   3. An edge table — from → to plus exploit probability.
 *
 * The backend payload is normalised tolerantly so minor schema churn
 * (extra fields, missing optional fields) does not break the renderer.
 */

type CompromiseState = "compromised" | "at_risk" | "clean" | "unknown";

interface TwinAsset {
  id: string;
  kind: string;
  identifier: string;
  risk_score: number;
  compromise_state: CompromiseState;
}

interface TwinEdge {
  from: string;
  to: string;
  exploit_probability: number;
}

interface TwinPayload {
  assets: ReadonlyArray<TwinAsset>;
  edges: ReadonlyArray<TwinEdge>;
  compromised: ReadonlyArray<string>;
}

interface ApiErrorEnvelope {
  code?: string;
  message?: string;
  request_id?: string;
}

interface Props {
  engagements: ReadonlyArray<Engagement>;
  apiAvailable: boolean;
}

export function TwinClient({ engagements, apiAvailable }: Props) {
  const [selected, setSelected] = React.useState<string>("");
  const [twin, setTwin] = React.useState<TwinPayload | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<ApiErrorEnvelope | null>(null);

  async function loadTwin(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (selected.length === 0) {
      setError({ message: "Select an engagement first." });
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/twin/${encodeURIComponent(selected)}`);
      const parsed = (await res.json().catch(() => ({}))) as {
        data?: unknown;
        error?: ApiErrorEnvelope;
      };
      if (!res.ok) {
        setError(parsed.error ?? { message: `Twin load failed (${res.status})` });
        setTwin(null);
        return;
      }
      setTwin(normaliseTwin(parsed.data));
    } catch {
      setError({ message: "Network error — please retry." });
      setTwin(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Network className="h-4 w-4 text-accent" aria-hidden />
            Cyber Digital Twin
          </CardTitle>
          <CardDescription>
            Inspect the simulated twin of an engagement: assets with their
            current risk scores, attack edges between them, and the set of
            assets that the simulator has marked as compromised.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {!apiAvailable ? (
            <div
              role="alert"
              className="mb-4 rounded-sx border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical"
            >
              API unavailable — engagement list could not be loaded.
            </div>
          ) : null}
          <form
            onSubmit={loadTwin}
            className="grid grid-cols-1 gap-3 md:grid-cols-3"
          >
            <div className="space-y-1.5 md:col-span-2">
              <Label htmlFor="twin-engagement">Engagement</Label>
              <select
                id="twin-engagement"
                value={selected}
                onChange={(event) => setSelected(event.currentTarget.value)}
                className="h-9 w-full rounded-sx border border-border bg-transparent px-2 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                <option value="" className="bg-card text-foreground">
                  — Select an engagement —
                </option>
                {engagements.map((e) => (
                  <option
                    key={e.id}
                    value={e.id}
                    className="bg-card text-foreground"
                  >
                    {e.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex items-end">
              <Button
                type="submit"
                disabled={loading || selected.length === 0}
                className="w-full md:w-auto"
              >
                {loading ? "Loading…" : "Load twin"}
              </Button>
            </div>
          </form>

          {error !== null ? (
            <div
              role="alert"
              className="mt-4 rounded-sx border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical"
            >
              <div>{error.message ?? "Twin request failed."}</div>
              {typeof error.request_id === "string" &&
              error.request_id.length > 0 ? (
                <div className="mt-0.5 text-[10px] opacity-80">
                  request id: <code>{error.request_id}</code>
                </div>
              ) : null}
            </div>
          ) : null}
        </CardContent>
      </Card>

      {twin === null ? (
        <Card>
          <CardContent className="py-10 text-center text-xs text-muted-foreground">
            {loading
              ? "Loading twin…"
              : "Select an engagement and click Load twin to inspect the simulated environment."}
          </CardContent>
        </Card>
      ) : (
        <TwinView twin={twin} />
      )}
    </div>
  );
}

function TwinView({ twin }: { twin: TwinPayload }) {
  const compromisedCount = twin.compromised.length;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <CountCard label="Assets" value={twin.assets.length} />
        <CountCard label="Edges" value={twin.edges.length} />
        <CountCard label="Compromised" value={compromisedCount} accent />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Assets ({twin.assets.length})</CardTitle>
          <CardDescription>
            Risk score is shown as a horizontal bar; the compromise state badge
            reflects the simulator&apos;s current verdict.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {twin.assets.length === 0 ? (
            <div className="py-6 text-center text-xs text-muted-foreground">
              No assets in this twin.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>Kind</TableHead>
                  <TableHead>Identifier</TableHead>
                  <TableHead className="w-[220px]">Risk score</TableHead>
                  <TableHead>State</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {twin.assets.map((asset) => (
                  <TableRow key={asset.id}>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {shortId(asset.id)}
                    </TableCell>
                    <TableCell className="text-xs">{asset.kind}</TableCell>
                    <TableCell className="text-xs">
                      {asset.identifier}
                    </TableCell>
                    <TableCell>
                      <RiskBar score={asset.risk_score} />
                    </TableCell>
                    <TableCell>
                      <StateBadge state={asset.compromise_state} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Edges ({twin.edges.length})</CardTitle>
          <CardDescription>
            Directed attack-graph edges with the simulator&apos;s
            per-edge exploit probability.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {twin.edges.length === 0 ? (
            <div className="py-6 text-center text-xs text-muted-foreground">
              No edges in this twin.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>From</TableHead>
                  <TableHead>To</TableHead>
                  <TableHead className="w-[220px]">Exploit probability</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {twin.edges.map((edge, idx) => (
                  <TableRow key={`${edge.from}-${edge.to}-${idx}`}>
                    <TableCell className="font-mono text-xs">
                      {shortId(edge.from)}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {shortId(edge.to)}
                    </TableCell>
                    <TableCell>
                      <ProbabilityBar value={edge.exploit_probability} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function CountCard({
  label,
  value,
  accent = false,
}: {
  label: string;
  value: number;
  accent?: boolean;
}) {
  return (
    <div className="rounded-sx border border-border bg-card p-4">
      <div className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
      <div
        className={
          accent
            ? "mt-1 font-mono text-2xl font-semibold text-critical"
            : "mt-1 font-mono text-2xl font-semibold text-foreground"
        }
      >
        {value.toLocaleString()}
      </div>
    </div>
  );
}

function RiskBar({ score }: { score: number }) {
  const pct = Math.round(Math.max(0, Math.min(1, score)) * 100);
  const tone =
    pct >= 80
      ? "bg-critical"
      : pct >= 60
        ? "bg-high"
        : pct >= 40
          ? "bg-medium"
          : "bg-low";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
        <div
          className={`h-full rounded-full ${tone}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="w-10 text-right font-mono text-[11px] text-muted-foreground">
        {pct}%
      </span>
    </div>
  );
}

function ProbabilityBar({ value }: { value: number }) {
  const pct = Math.round(Math.max(0, Math.min(1, value)) * 100);
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
        <div
          className="h-full rounded-full bg-accent"
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="w-10 text-right font-mono text-[11px] text-muted-foreground">
        {pct}%
      </span>
    </div>
  );
}

function StateBadge({ state }: { state: CompromiseState }) {
  switch (state) {
    case "compromised":
      return <Badge variant="critical">compromised</Badge>;
    case "at_risk":
      return <Badge variant="high">at risk</Badge>;
    case "clean":
      return <Badge variant="success">clean</Badge>;
    default:
      return <Badge variant="outline">unknown</Badge>;
  }
}

function shortId(id: string): string {
  const trimmed = id.trim();
  if (trimmed.length <= 12) {
    return trimmed;
  }
  return `${trimmed.slice(0, 8)}…${trimmed.slice(-4)}`;
}

function isCompromiseState(value: unknown): value is CompromiseState {
  return (
    value === "compromised" ||
    value === "at_risk" ||
    value === "clean" ||
    value === "unknown"
  );
}

/**
 * Coerce the backend twin payload into a renderable shape.
 *
 * Accepted shapes:
 *   - `{ assets, edges, compromised }`
 *   - `{ twin: { assets, edges, compromised } }`
 *
 * Unknown compromise states fall back to `"unknown"`. Numeric scores
 * default to 0 and edges referencing missing assets are kept as-is so
 * the operator can still see the wire-level payload.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function normaliseTwin(input: any): TwinPayload {
  if (input === null || typeof input !== "object") {
    return { assets: [], edges: [], compromised: [] };
  }
  const root =
    typeof input.twin === "object" && input.twin !== null ? input.twin : input;

  const assetsRaw = Array.isArray(root.assets) ? root.assets : [];
  const assets: TwinAsset[] = [];
  for (const raw of assetsRaw) {
    if (raw === null || typeof raw !== "object") {
      continue;
    }
    const id = typeof raw.id === "string" ? raw.id : "";
    if (id.length === 0) {
      continue;
    }
    const kind = typeof raw.kind === "string" ? raw.kind : "unknown";
    const identifier =
      typeof raw.identifier === "string" ? raw.identifier : id;
    const risk_score =
      typeof raw.risk_score === "number" && Number.isFinite(raw.risk_score)
        ? raw.risk_score
        : 0;
    const compromise_state = isCompromiseState(raw.compromise_state)
      ? raw.compromise_state
      : "unknown";
    assets.push({ id, kind, identifier, risk_score, compromise_state });
  }

  const edgesRaw = Array.isArray(root.edges) ? root.edges : [];
  const edges: TwinEdge[] = [];
  for (const raw of edgesRaw) {
    if (raw === null || typeof raw !== "object") {
      continue;
    }
    const from = typeof raw.from === "string" ? raw.from : "";
    const to = typeof raw.to === "string" ? raw.to : "";
    if (from.length === 0 || to.length === 0) {
      continue;
    }
    const exploit_probability =
      typeof raw.exploit_probability === "number" &&
      Number.isFinite(raw.exploit_probability)
        ? raw.exploit_probability
        : 0;
    edges.push({ from, to, exploit_probability });
  }

  const compromisedRaw = Array.isArray(root.compromised)
    ? root.compromised
    : [];
  const compromised: string[] = [];
  for (const raw of compromisedRaw) {
    if (typeof raw === "string" && raw.length > 0) {
      compromised.push(raw);
    }
  }

  return { assets, edges, compromised };
}
