"use client";

import * as React from "react";
import { Play, Upload } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
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

/**
 * Evidence collector control surface (client island).
 *
 * Renders three stacked sections:
 *   1. The run form (framework selector + output directory + Run button),
 *      which POSTs to `/api/compliance/evidence/run` and renders the
 *      returned artifact list inline.
 *   2. The shipped-to-S3 status table, seeded by the server component.
 *      "Ship to S3" opens a confirmation dialog before POSTing to
 *      `/api/compliance/evidence/ship`. On success, a new synthetic row is
 *      prepended so the table reflects the just-shipped manifest.
 *
 * The proxy envelope is permissively typed because the backing route is a
 * stub today; once the real proxy lands we'll narrow this to the sx-api
 * envelope shape.
 */

const FRAMEWORKS: ReadonlyArray<EvidenceFramework> = ["soc2", "iso27001", "all"];

const FRAMEWORK_LABELS: Record<EvidenceFramework, string> = {
  soc2: "SOC 2",
  iso27001: "ISO 27001",
  all: "All frameworks",
};

const DEFAULT_OUTPUT_DIR = "./evidence/";

type EvidenceFramework = "soc2" | "iso27001" | "all";

type ShippedStatus = "ok" | "partial" | "failed";

export interface ShippedRow {
  manifest_key: string;
  framework: string;
  artifact_count: number;
  size_bytes: number;
  shipped_at: string;
  status: ShippedStatus;
}

interface ArtifactRow {
  artifact_id: string;
  framework: string;
  control_id: string;
  collector: string;
  filename: string;
  size_bytes: number;
  sha256: string;
  collected_at: string;
}

interface RunResponse {
  data?: {
    artifacts?: ReadonlyArray<unknown>;
  };
  error?: { code?: string; message?: string; request_id?: string };
}

interface ShipResponse {
  data?: {
    shipped?: number;
    manifest_key?: string;
    manifest_uri?: string;
    bucket?: string;
    shipped_at?: string;
  };
  error?: { code?: string; message?: string; request_id?: string };
}

interface Props {
  initialShipped: ReadonlyArray<ShippedRow>;
}

export function EvidenceClient({ initialShipped }: Props) {
  const toast = useToast();
  const [framework, setFramework] = React.useState<EvidenceFramework>("soc2");
  const [outputDir, setOutputDir] = React.useState<string>(DEFAULT_OUTPUT_DIR);
  const [running, setRunning] = React.useState(false);
  const [artifacts, setArtifacts] = React.useState<ReadonlyArray<ArtifactRow>>([]);
  const [shipped, setShipped] = React.useState<ReadonlyArray<ShippedRow>>(initialShipped);
  const [confirmOpen, setConfirmOpen] = React.useState(false);
  const [shipping, setShipping] = React.useState(false);

  async function handleRun(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const dir = outputDir.trim();
    if (dir.length === 0) {
      toast.push({ kind: "error", message: "Output directory is required." });
      return;
    }
    setRunning(true);
    try {
      const res = await fetch("/api/compliance/evidence/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ framework, output_dir: dir }),
      });
      const parsed: RunResponse = await res.json().catch(() => ({}));
      if (!res.ok) {
        const detail = parsed.error?.message ?? `Collector run failed (${res.status})`;
        toast.push({ kind: "error", message: detail });
        return;
      }
      const normalised = normaliseArtifacts(parsed.data?.artifacts ?? []);
      setArtifacts(normalised);
      toast.push({
        kind: "success",
        message: `Collected ${normalised.length} artifact${normalised.length === 1 ? "" : "s"}.`,
      });
    } catch {
      toast.push({ kind: "error", message: "Network error — please retry." });
    } finally {
      setRunning(false);
    }
  }

  async function handleShip() {
    if (artifacts.length === 0) {
      toast.push({
        kind: "error",
        message: "Run collectors first — there are no artifacts to ship.",
      });
      setConfirmOpen(false);
      return;
    }
    setShipping(true);
    try {
      const res = await fetch("/api/compliance/evidence/ship", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ artifact_ids: artifacts.map((a) => a.artifact_id) }),
      });
      const parsed: ShipResponse = await res.json().catch(() => ({}));
      if (!res.ok) {
        const detail = parsed.error?.message ?? `Ship failed (${res.status})`;
        toast.push({ kind: "error", message: detail });
        return;
      }
      const count = parsed.data?.shipped ?? artifacts.length;
      const key = parsed.data?.manifest_key ?? "fake/key.json";
      const shippedAt = parsed.data?.shipped_at ?? new Date().toISOString();
      const totalSize = artifacts.reduce((sum, a) => sum + a.size_bytes, 0);
      const newRow: ShippedRow = {
        manifest_key: key,
        framework,
        artifact_count: count,
        size_bytes: totalSize,
        shipped_at: shippedAt,
        status: "ok",
      };
      setShipped((current) => [newRow, ...current].slice(0, 25));
      toast.push({
        kind: "success",
        message: `Shipped ${count} artifact${count === 1 ? "" : "s"} (${key}).`,
      });
    } catch {
      toast.push({ kind: "error", message: "Network error — please retry." });
    } finally {
      setShipping(false);
      setConfirmOpen(false);
    }
  }

  return (
    <div className="space-y-6">
      <form
        onSubmit={handleRun}
        className="grid grid-cols-1 gap-3 md:grid-cols-3"
        aria-label="Run evidence collectors"
      >
        <div className="space-y-1.5">
          <Label htmlFor="evidence-framework">Framework</Label>
          <select
            id="evidence-framework"
            value={framework}
            onChange={(event) =>
              setFramework(event.currentTarget.value as EvidenceFramework)
            }
            className="h-9 w-full rounded-sx border border-border bg-transparent px-2 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            {FRAMEWORKS.map((f) => (
              <option key={f} value={f} className="bg-card text-foreground">
                {FRAMEWORK_LABELS[f]}
              </option>
            ))}
          </select>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="evidence-output-dir">Output directory</Label>
          <Input
            id="evidence-output-dir"
            value={outputDir}
            onChange={(event) => setOutputDir(event.currentTarget.value)}
            placeholder={DEFAULT_OUTPUT_DIR}
            required
          />
        </div>
        <div className="flex items-end">
          <Button type="submit" disabled={running} className="w-full md:w-auto">
            <Play className="h-4 w-4" aria-hidden />
            {running ? "Running…" : "Run collectors"}
          </Button>
        </div>
      </form>

      {artifacts.length > 0 ? (
        <section className="space-y-2" aria-label="Collected artifacts">
          <header className="flex items-center justify-between">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Collected artifacts ({artifacts.length})
            </h4>
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={() => setConfirmOpen(true)}
              disabled={shipping}
            >
              <Upload className="h-3.5 w-3.5" aria-hidden />
              Ship to S3
            </Button>
          </header>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Artifact</TableHead>
                <TableHead>Framework</TableHead>
                <TableHead>Control</TableHead>
                <TableHead>Collector</TableHead>
                <TableHead className="text-right">Size</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {artifacts.map((row) => (
                <TableRow key={row.artifact_id}>
                  <TableCell>
                    <div className="font-mono text-xs">{row.filename}</div>
                    <div className="text-[10px] text-muted-foreground">{row.artifact_id}</div>
                  </TableCell>
                  <TableCell className="text-xs uppercase tracking-wide text-muted-foreground">
                    {row.framework}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{row.control_id}</TableCell>
                  <TableCell className="text-xs">{row.collector}</TableCell>
                  <TableCell className="text-right font-mono text-xs">
                    {formatBytes(row.size_bytes)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </section>
      ) : (
        <div
          role="note"
          className="rounded-sx border border-border bg-muted/30 px-3 py-2 text-xs text-muted-foreground"
        >
          Choose a framework and click <strong>Run collectors</strong> to generate an
          artifact manifest. The manifest can then be shipped to S3 from the table below.
        </div>
      )}

      <section className="space-y-2" aria-label="Shipped manifests">
        <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Shipped to S3
        </h4>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Manifest key</TableHead>
              <TableHead>Framework</TableHead>
              <TableHead className="text-right">Artifacts</TableHead>
              <TableHead className="text-right">Size</TableHead>
              <TableHead>Shipped</TableHead>
              <TableHead>Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {shipped.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="py-8 text-center text-xs text-muted-foreground">
                  No manifests shipped yet.
                </TableCell>
              </TableRow>
            ) : (
              shipped.map((row) => (
                <TableRow key={row.manifest_key}>
                  <TableCell className="font-mono text-xs">{row.manifest_key}</TableCell>
                  <TableCell className="text-xs uppercase tracking-wide text-muted-foreground">
                    {row.framework}
                  </TableCell>
                  <TableCell className="text-right font-mono text-xs">
                    {row.artifact_count}
                  </TableCell>
                  <TableCell className="text-right font-mono text-xs">
                    {formatBytes(row.size_bytes)}
                  </TableCell>
                  <TableCell className="text-xs">{formatTimestamp(row.shipped_at)}</TableCell>
                  <TableCell>
                    <ShipBadge status={row.status} />
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </section>

      {confirmOpen ? (
        <ConfirmShipDialog
          framework={framework}
          artifactCount={artifacts.length}
          submitting={shipping}
          onCancel={() => setConfirmOpen(false)}
          onConfirm={handleShip}
        />
      ) : null}
    </div>
  );
}

function ShipBadge({ status }: { status: ShippedStatus }) {
  if (status === "ok") {
    return <Badge variant="success">ok</Badge>;
  }
  if (status === "partial") {
    return <Badge variant="medium">partial</Badge>;
  }
  return <Badge variant="critical">failed</Badge>;
}

function ConfirmShipDialog({
  framework,
  artifactCount,
  submitting,
  onCancel,
  onConfirm,
}: {
  framework: EvidenceFramework;
  artifactCount: number;
  submitting: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="ship-dialog-title"
      className="fixed inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm"
    >
      <div className="w-full max-w-md rounded-sx border border-border bg-card p-5 shadow-lg">
        <h3 id="ship-dialog-title" className="text-sm font-semibold">
          Ship evidence to S3?
        </h3>
        <p className="mt-2 text-xs text-muted-foreground">
          This will upload the manifest for <strong>{FRAMEWORK_LABELS[framework]}</strong>
          {" "}({artifactCount} artifact{artifactCount === 1 ? "" : "s"}) to the tenant
          evidence bucket and emit an audit event. The action cannot be undone from this UI.
        </p>
        <div className="mt-5 flex justify-end gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={onCancel}
            disabled={submitting}
          >
            Cancel
          </Button>
          <Button type="button" size="sm" onClick={onConfirm} disabled={submitting}>
            {submitting ? "Shipping…" : "Confirm ship"}
          </Button>
        </div>
      </div>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const kb = bytes / 1024;
  if (kb < 1024) {
    return `${kb.toFixed(1)} KB`;
  }
  return `${(kb / 1024).toFixed(2)} MB`;
}

function formatTimestamp(iso: string): string {
  return iso.replace("T", " ").replace(/\.\d+Z$/, "Z").replace(/Z$/, "Z");
}

function normaliseArtifacts(input: ReadonlyArray<unknown>): ReadonlyArray<ArtifactRow> {
  const out: ArtifactRow[] = [];
  for (const raw of input) {
    if (raw === null || typeof raw !== "object") {
      continue;
    }
    const r = raw as Record<string, unknown>;
    const artifact_id = typeof r.artifact_id === "string" ? r.artifact_id : "";
    if (artifact_id.length === 0) {
      continue;
    }
    out.push({
      artifact_id,
      framework: typeof r.framework === "string" ? r.framework : "unknown",
      control_id: typeof r.control_id === "string" ? r.control_id : "—",
      collector: typeof r.collector === "string" ? r.collector : "unknown",
      filename: typeof r.filename === "string" ? r.filename : artifact_id,
      size_bytes:
        typeof r.size_bytes === "number" && Number.isFinite(r.size_bytes)
          ? r.size_bytes
          : 0,
      sha256: typeof r.sha256 === "string" ? r.sha256 : "",
      collected_at:
        typeof r.collected_at === "string" ? r.collected_at : new Date().toISOString(),
    });
  }
  return out;
}
