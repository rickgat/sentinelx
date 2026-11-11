"use client";

import * as React from "react";
import { Network } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { Engagement, Severity } from "@/lib/types";

/**
 * Attack-graph visualisation page.
 *
 * Renders the graph payload for the currently-selected engagement using a
 * lightweight deterministic circular layout — no force-simulation
 * dependency. Above 50 nodes the SVG becomes unreadable, so the page
 * gracefully degrades to a flat from/to/kind table. The toggle button at
 * the top is always available so operators can swap views even on small
 * graphs.
 *
 * Payload tolerance: the backend currently emits
 * `{ paths: [{ id, score, length }] }` from `POST /v1/graph/attack-paths`.
 * We project each path into a single "path node" with edges synthesised
 * by length, AND we still accept a future `{ nodes, edges }` shape so the
 * page does not need to be rewritten when the contract grows.
 */

type GraphNode = {
  id: string;
  label: string;
  severity: Severity;
};

type GraphEdge = {
  from: string;
  to: string;
  kind: string;
};

type ViewMode = "graph" | "table";

interface GraphPayload {
  nodes: ReadonlyArray<GraphNode>;
  edges: ReadonlyArray<GraphEdge>;
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

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  info: "#3b82f6",
};

const MAX_INLINE_NODES = 50;

export function GraphClient({ engagements, apiAvailable }: Props) {
  const [selected, setSelected] = React.useState<string>("");
  const [payload, setPayload] = React.useState<GraphPayload | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<ApiErrorEnvelope | null>(null);
  const [mode, setMode] = React.useState<ViewMode>("graph");

  React.useEffect(() => {
    if (selected.length === 0) {
      setPayload(null);
      setError(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    fetch(`/api/graph/${encodeURIComponent(selected)}`, { method: "GET" })
      .then(async (res) => {
        const json = (await res.json().catch(() => ({}))) as {
          data?: unknown;
          error?: ApiErrorEnvelope;
        };
        if (cancelled) {
          return;
        }
        if (!res.ok) {
          setError(json.error ?? { message: `Request failed (${res.status})` });
          setPayload(null);
          return;
        }
        setPayload(normalisePayload(json.data));
      })
      .catch(() => {
        if (cancelled) {
          return;
        }
        setError({ message: "Network error — please retry." });
        setPayload(null);
      })
      .finally(() => {
        if (cancelled) {
          return;
        }
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selected]);

  const nodeCount = payload?.nodes.length ?? 0;
  const tooBig = nodeCount > MAX_INLINE_NODES;
  const effectiveMode: ViewMode = tooBig ? "table" : mode;

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Network className="h-4 w-4 text-accent" aria-hidden />
              Attack graph
            </CardTitle>
            <CardDescription>
              Asset relationship view, colour-coded by max-severity finding.
            </CardDescription>
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => setMode(mode === "graph" ? "table" : "graph")}
            disabled={tooBig || payload === null}
            title={tooBig ? "Graph too large; locked to table view." : undefined}
          >
            {effectiveMode === "graph" ? "Show table" : "Show graph"}
          </Button>
        </CardHeader>
        <CardContent className="space-y-4">
          {!apiAvailable ? (
            <div
              role="alert"
              className="rounded-sx border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical"
            >
              API unavailable — engagement list could not be loaded.
            </div>
          ) : null}
          <div className="flex flex-col gap-1.5 sm:max-w-sm">
            <Label htmlFor="graph-engagement">Engagement</Label>
            <select
              id="graph-engagement"
              value={selected}
              onChange={(event) => setSelected(event.currentTarget.value)}
              className="h-9 rounded-sx border border-border bg-transparent px-2 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              <option value="" className="bg-card text-foreground">
                — Select an engagement —
              </option>
              {engagements.map((e) => (
                <option key={e.id} value={e.id} className="bg-card text-foreground">
                  {e.name}
                </option>
              ))}
            </select>
          </div>

          {error !== null ? (
            <div
              role="alert"
              className="rounded-sx border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical"
            >
              <div>{error.message ?? "Graph request failed."}</div>
              {typeof error.request_id === "string" && error.request_id.length > 0 ? (
                <div className="mt-0.5 text-[10px] opacity-80">
                  request id: <code>{error.request_id}</code>
                </div>
              ) : null}
            </div>
          ) : null}

          {selected.length === 0 ? (
            <div className="rounded-sx border border-dashed border-border px-3 py-8 text-center text-xs text-muted-foreground">
              Select an engagement to view its attack graph.
            </div>
          ) : loading ? (
            <div className="rounded-sx border border-dashed border-border px-3 py-8 text-center text-xs text-muted-foreground">
              Loading graph…
            </div>
          ) : payload === null ? null : payload.nodes.length === 0 ? (
            <div className="rounded-sx border border-dashed border-border px-3 py-8 text-center text-xs text-muted-foreground">
              No graph data for this engagement.
            </div>
          ) : effectiveMode === "graph" ? (
            <GraphSvg payload={payload} />
          ) : (
            <GraphTable payload={payload} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}

interface GraphViewProps {
  payload: GraphPayload;
}

function GraphSvg({ payload }: GraphViewProps) {
  const [hover, setHover] = React.useState<string | null>(null);

  const width = 720;
  const height = 480;
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.min(width, height) / 2 - 40;

  const positions = React.useMemo(() => {
    const n = payload.nodes.length;
    const out = new Map<string, { x: number; y: number }>();
    payload.nodes.forEach((node, i) => {
      const angle = (i / Math.max(n, 1)) * Math.PI * 2 - Math.PI / 2;
      out.set(node.id, {
        x: cx + radius * Math.cos(angle),
        y: cy + radius * Math.sin(angle),
      });
    });
    return out;
  }, [payload.nodes, cx, cy, radius]);

  return (
    <div className="w-full overflow-auto rounded-sx border border-border bg-background/40 p-2">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-[480px] w-full"
        role="img"
        aria-label="Attack graph"
      >
        {payload.edges.map((edge, idx) => {
          const a = positions.get(edge.from);
          const b = positions.get(edge.to);
          if (a === undefined || b === undefined) {
            return null;
          }
          return (
            <line
              key={`${edge.from}-${edge.to}-${idx}`}
              x1={a.x}
              y1={a.y}
              x2={b.x}
              y2={b.y}
              stroke="currentColor"
              strokeOpacity={0.25}
              strokeWidth={1}
              className="text-muted-foreground"
            />
          );
        })}
        {payload.nodes.map((node) => {
          const pos = positions.get(node.id);
          if (pos === undefined) {
            return null;
          }
          const color = SEVERITY_COLOR[node.severity];
          const isHovered = hover === node.id;
          return (
            <g
              key={node.id}
              onMouseEnter={() => setHover(node.id)}
              onMouseLeave={() => setHover((current) => (current === node.id ? null : current))}
              style={{ cursor: "pointer" }}
            >
              <circle
                cx={pos.x}
                cy={pos.y}
                r={isHovered ? 9 : 6}
                fill={color}
                fillOpacity={0.8}
                stroke={color}
                strokeWidth={isHovered ? 2 : 1}
              />
              {isHovered ? (
                <g>
                  <rect
                    x={pos.x + 10}
                    y={pos.y - 18}
                    width={Math.max(60, node.label.length * 7 + 12)}
                    height={22}
                    rx={4}
                    fill="#0f172a"
                    fillOpacity={0.92}
                    stroke="currentColor"
                    strokeOpacity={0.4}
                    className="text-border"
                  />
                  <text
                    x={pos.x + 16}
                    y={pos.y - 3}
                    fontSize={11}
                    fill="#f8fafc"
                  >
                    {node.label}
                  </text>
                </g>
              ) : null}
            </g>
          );
        })}
      </svg>
      <SeverityLegend />
    </div>
  );
}

function GraphTable({ payload }: GraphViewProps) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>From</TableHead>
          <TableHead>To</TableHead>
          <TableHead>Kind</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {payload.edges.length === 0 ? (
          <TableRow>
            <TableCell colSpan={3} className="py-6 text-center text-xs text-muted-foreground">
              No edges in this graph.
            </TableCell>
          </TableRow>
        ) : (
          payload.edges.map((edge, idx) => (
            <TableRow key={`${edge.from}-${edge.to}-${idx}`}>
              <TableCell className="font-mono text-xs">{edge.from}</TableCell>
              <TableCell className="font-mono text-xs">{edge.to}</TableCell>
              <TableCell>{edge.kind}</TableCell>
            </TableRow>
          ))
        )}
      </TableBody>
    </Table>
  );
}

function SeverityLegend() {
  const items: ReadonlyArray<{ label: string; severity: Severity }> = [
    { label: "Critical", severity: "critical" },
    { label: "High", severity: "high" },
    { label: "Medium", severity: "medium" },
    { label: "Low", severity: "low" },
    { label: "Info", severity: "info" },
  ];
  return (
    <div className="mt-2 flex flex-wrap items-center gap-3 px-1 text-[10px] text-muted-foreground">
      {items.map((item) => (
        <div key={item.severity} className="flex items-center gap-1">
          <span
            aria-hidden
            className="inline-block h-2 w-2 rounded-full"
            style={{ background: SEVERITY_COLOR[item.severity] }}
          />
          <span>{item.label}</span>
        </div>
      ))}
    </div>
  );
}

/**
 * Coerce whatever the backend returns into a `{ nodes, edges }` projection
 * the renderer can consume. Three shapes are recognised:
 *   1. `{ nodes: [...], edges: [...] }` — passed through with light
 *      normalisation.
 *   2. `{ paths: [...] }` — the current sx-api attack-path shape; one
 *      node per path, edges synthesised by `length`.
 *   3. Anything else → empty graph.
 *
 * The `any` casts are confined to this envelope-handling helper.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function normalisePayload(input: any): GraphPayload {
  if (input === null || typeof input !== "object") {
    return { nodes: [], edges: [] };
  }
  if (Array.isArray(input.nodes) && Array.isArray(input.edges)) {
    const nodes: GraphNode[] = [];
    for (const raw of input.nodes) {
      if (raw === null || typeof raw !== "object") {
        continue;
      }
      const id = typeof raw.id === "string" ? raw.id : null;
      if (id === null) {
        continue;
      }
      const label = typeof raw.label === "string" ? raw.label : id;
      const severity: Severity = isSeverity(raw.severity) ? raw.severity : "info";
      nodes.push({ id, label, severity });
    }
    const edges: GraphEdge[] = [];
    for (const raw of input.edges) {
      if (raw === null || typeof raw !== "object") {
        continue;
      }
      const from = typeof raw.from === "string" ? raw.from : null;
      const to = typeof raw.to === "string" ? raw.to : null;
      if (from === null || to === null) {
        continue;
      }
      const kind = typeof raw.kind === "string" ? raw.kind : "related";
      edges.push({ from, to, kind });
    }
    return { nodes, edges };
  }
  if (Array.isArray(input.paths)) {
    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];
    for (const raw of input.paths) {
      if (raw === null || typeof raw !== "object") {
        continue;
      }
      const id = typeof raw.id === "string" ? raw.id : null;
      if (id === null) {
        continue;
      }
      const score = typeof raw.score === "number" ? raw.score : 0;
      const length = typeof raw.length === "number" ? Math.max(1, Math.floor(raw.length)) : 1;
      nodes.push({
        id,
        label: `${id} · score ${score.toFixed(1)} · len ${length}`,
        severity: severityFromScore(score),
      });
      // Synthesise self-loop edges to convey path length in the table fallback.
      for (let i = 0; i < length; i += 1) {
        edges.push({ from: id, to: id, kind: `hop-${i + 1}` });
      }
    }
    return { nodes, edges };
  }
  return { nodes: [], edges: [] };
}

function isSeverity(value: unknown): value is Severity {
  return (
    value === "critical" ||
    value === "high" ||
    value === "medium" ||
    value === "low" ||
    value === "info"
  );
}

function severityFromScore(score: number): Severity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score >= 1) return "low";
  return "info";
}
