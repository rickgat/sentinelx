"use client";

import * as React from "react";
import { Target } from "lucide-react";

import { Badge } from "@/components/ui/badge";
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
import type { Asset } from "@/lib/types";

/**
 * Cloud blast-radius viewer.
 *
 * Calls the dashboard proxy at `/api/cloud/blast-radius` with
 * `{ seed_asset_id, max_depth }`. The seed is chosen from an
 * autocomplete-style picker (the engagement-scoped asset list); the
 * max-depth slider is clamped client-side to the same `1..=5` range
 * the backend enforces so the user gets immediate feedback.
 *
 * The response is rendered as:
 *   1. Summary tiles (seed, depth used, total risk, cached badge).
 *   2. A ranked impact table — asset id / name / depth / edge kind /
 *      criticality / score.
 *
 * Edge-kind values are surface-rendered via a small badge palette so
 * IAM-chain rows visually dominate s3-acl rows even when their scores
 * are within rounding distance.
 */

interface ImpactedAsset {
  asset_id: string;
  name: string;
  depth: number;
  edge_kind: string;
  criticality: string;
  impact_score: number;
}

interface BlastResponse {
  seed_asset_id: string;
  max_depth: number;
  decay_base: number;
  impacted: ReadonlyArray<ImpactedAsset>;
  total_score: number;
  cached: boolean;
}

interface ApiErrorEnvelope {
  code?: string;
  message?: string;
  request_id?: string;
}

interface Props {
  assets: ReadonlyArray<Asset>;
  apiAvailable: boolean;
}

const MIN_DEPTH = 1;
const MAX_DEPTH = 5;

function clampDepth(raw: number): number {
  if (!Number.isFinite(raw)) {
    return 3;
  }
  if (raw < MIN_DEPTH) return MIN_DEPTH;
  if (raw > MAX_DEPTH) return MAX_DEPTH;
  return Math.floor(raw);
}

function edgeBadgeVariant(
  kind: string,
): "critical" | "high" | "medium" | "low" | "default" | "info" | "success" | "outline" {
  switch (kind) {
    case "iam_role_chain":
    case "kms_grant":
      return "critical";
    case "network_peer":
      return "default";
    case "s3_acl":
    case "security_group_edge":
      return "info";
    default:
      return "outline";
  }
}

function criticalityBadgeVariant(
  c: string,
): "critical" | "high" | "medium" | "low" | "default" | "info" | "success" | "outline" {
  switch (c) {
    case "crown_jewel":
      return "critical";
    case "production":
      return "default";
    case "staging":
      return "info";
    default:
      return "outline";
  }
}

export function BlastRadiusClient({ assets, apiAvailable }: Props) {
  const [seed, setSeed] = React.useState<string>("");
  const [depth, setDepth] = React.useState<number>(3);
  const [loading, setLoading] = React.useState(false);
  const [report, setReport] = React.useState<BlastResponse | null>(null);
  const [error, setError] = React.useState<ApiErrorEnvelope | null>(null);

  async function compute(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmed = seed.trim();
    if (trimmed.length === 0) {
      setError({ message: "Select or enter a seed asset id." });
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/cloud/blast-radius", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          seed_asset_id: trimmed,
          max_depth: clampDepth(depth),
        }),
      });
      const parsed = (await res.json().catch(() => ({}))) as {
        data?: BlastResponse;
        error?: ApiErrorEnvelope;
      };
      if (!res.ok || parsed.data === undefined) {
        setError(
          parsed.error ?? { message: `Blast-radius failed (${res.status})` },
        );
        setReport(null);
        return;
      }
      setReport(parsed.data);
    } catch {
      setError({ message: "Network error — please retry." });
      setReport(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Target className="h-4 w-4 text-accent" aria-hidden />
            Cloud Blast Radius
          </CardTitle>
          <CardDescription>
            Given a compromised seed asset, the BFS walks the cloud
            knowledge graph (IAM chains, KMS grants, network peers, S3
            ACLs, security-group edges) and returns the ranked downstream
            impact set. Results computed within the last hour come from
            cache.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {!apiAvailable ? (
            <div
              role="alert"
              className="mb-4 rounded-sx border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical"
            >
              API unavailable — asset list could not be preloaded; you can
              still paste a seed asset id below.
            </div>
          ) : null}
          <form
            onSubmit={compute}
            className="grid grid-cols-1 gap-3 md:grid-cols-3"
          >
            <div className="space-y-1.5 md:col-span-2">
              <Label htmlFor="seed-asset">Seed asset</Label>
              <Input
                id="seed-asset"
                list="blast-asset-options"
                value={seed}
                placeholder="asset-id or pick from list"
                onChange={(event) => setSeed(event.currentTarget.value)}
                autoComplete="off"
              />
              <datalist id="blast-asset-options">
                {assets.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.identifier} ({a.kind})
                  </option>
                ))}
              </datalist>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="depth-slider">
                Max depth: <span className="font-mono">{depth}</span>
              </Label>
              <input
                id="depth-slider"
                type="range"
                min={MIN_DEPTH}
                max={MAX_DEPTH}
                value={depth}
                onChange={(event) =>
                  setDepth(clampDepth(Number(event.currentTarget.value)))
                }
                className="w-full"
              />
            </div>
            <div className="md:col-span-3 flex justify-end">
              <Button type="submit" disabled={loading}>
                {loading ? "Computing…" : "Compute blast radius"}
              </Button>
            </div>
          </form>
          {error !== null ? (
            <div
              role="alert"
              className="mt-4 rounded-sx border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical"
            >
              {error.message ?? "Request failed."}
              {error.request_id !== undefined && error.request_id.length > 0 ? (
                <span className="ml-2 font-mono text-[10px] opacity-70">
                  req {error.request_id}
                </span>
              ) : null}
            </div>
          ) : null}
        </CardContent>
      </Card>

      {report !== null ? (
        <>
          <Card>
            <CardHeader>
              <CardTitle>Summary</CardTitle>
              <CardDescription>
                Bi-directional BFS @ depth {report.max_depth}, decay base
                {" "}
                {report.decay_base.toFixed(2)}.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid grid-cols-1 gap-3 md:grid-cols-4">
              <SummaryTile label="Seed" value={report.seed_asset_id} mono />
              <SummaryTile
                label="Depth"
                value={`${report.max_depth} hops`}
              />
              <SummaryTile
                label="Total impact"
                value={report.total_score.toFixed(2)}
              />
              <SummaryTile
                label="Cache"
                value={report.cached ? "hit" : "fresh"}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Impacted assets ({report.impacted.length})</CardTitle>
              <CardDescription>
                Ranked by impact score — `criticality × edge_weight ×
                decay(depth)`.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Asset</TableHead>
                    <TableHead>Name</TableHead>
                    <TableHead>Depth</TableHead>
                    <TableHead>Edge</TableHead>
                    <TableHead>Criticality</TableHead>
                    <TableHead>Score</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {report.impacted.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center text-xs text-muted-foreground">
                        No downstream assets reachable from this seed.
                      </TableCell>
                    </TableRow>
                  ) : (
                    report.impacted.map((row) => (
                      <TableRow key={row.asset_id}>
                        <TableCell className="font-mono text-xs">
                          {row.asset_id}
                        </TableCell>
                        <TableCell>{row.name}</TableCell>
                        <TableCell>{row.depth}</TableCell>
                        <TableCell>
                          <Badge variant={edgeBadgeVariant(row.edge_kind)}>
                            {row.edge_kind}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant={criticalityBadgeVariant(row.criticality)}>
                            {row.criticality}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono">
                          {row.impact_score.toFixed(3)}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </>
      ) : null}
    </div>
  );
}

function SummaryTile({
  label,
  value,
  mono = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="rounded-sx border border-border bg-card/30 p-3">
      <div className="text-xs uppercase tracking-wide text-muted-foreground">
        {label}
      </div>
      <div className={mono ? "font-mono text-sm" : "text-sm"}>{value}</div>
    </div>
  );
}
