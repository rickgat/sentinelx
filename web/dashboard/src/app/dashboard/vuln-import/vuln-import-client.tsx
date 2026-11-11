"use client";

import * as React from "react";
import { FileUp } from "lucide-react";

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
import { useToast } from "@/components/toast";

export interface VulnImportView {
  id: string;
  tenant_id: string;
  source: string;
  asset_count: number;
  finding_count: number;
  ingested_at: string;
  status: string;
}

export interface VulnImportResponse {
  import: VulnImportView;
  duplicates_dropped: number;
  parse_errors: number;
}

interface ImportResponseBody {
  data?: VulnImportResponse;
  error?: { code?: string; message?: string };
}

const MAX_PAYLOAD_BYTES = 100 * 1024 * 1024;

export function VulnImportClient({
  initial,
}: {
  initial: ReadonlyArray<VulnImportView>;
}) {
  const toast = useToast();
  const [source, setSource] = React.useState<"nessus" | "openvas">("nessus");
  const [file, setFile] = React.useState<File | null>(null);
  const [submitting, setSubmitting] = React.useState(false);
  const [dragOver, setDragOver] = React.useState(false);
  const [imports, setImports] =
    React.useState<ReadonlyArray<VulnImportView>>(initial);
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  const onDrop = React.useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragOver(false);
    const dropped = event.dataTransfer.files?.[0];
    if (dropped !== undefined) {
      setFile(dropped);
    }
  }, []);

  function onSelectFile(event: React.ChangeEvent<HTMLInputElement>) {
    const picked = event.currentTarget.files?.[0] ?? null;
    setFile(picked);
  }

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (file === null) {
      toast.push({ kind: "error", message: "Select a file to import." });
      return;
    }
    if (file.size > MAX_PAYLOAD_BYTES) {
      toast.push({
        kind: "error",
        message: `File exceeds 100 MiB limit (${Math.round(file.size / (1024 * 1024))} MiB).`,
      });
      return;
    }
    setSubmitting(true);
    try {
      const fd = new FormData();
      fd.append("source", source);
      fd.append("file", file, file.name);
      const res = await fetch("/api/vuln-import", {
        method: "POST",
        body: fd,
      });
      const parsed = (await res.json().catch(() => ({}))) as ImportResponseBody;
      if (!res.ok || parsed.data === undefined) {
        const detail = parsed.error?.message ?? `Import failed (${res.status})`;
        toast.push({ kind: "error", message: detail });
        return;
      }
      const fresh = parsed.data.import;
      setImports((current) => [fresh, ...current].slice(0, 200));
      setFile(null);
      if (fileInputRef.current !== null) {
        fileInputRef.current.value = "";
      }
      toast.push({
        kind: "success",
        message: `Imported ${fresh.finding_count} finding(s) across ${fresh.asset_count} asset(s) — ${parsed.data.duplicates_dropped} duplicate(s) dropped.`,
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
            <FileUp className="h-4 w-4 text-accent" aria-hidden />
            Credentialed Vulnerability Scanner Import
          </CardTitle>
          <CardDescription>
            Upload a Nessus <code>.nessus</code> export or an OpenVAS GMP XML
            report. Findings are parsed, deduplicated by{" "}
            <code>(asset, check)</code>, and persisted as an import receipt.
            Max payload: 100 MiB.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="space-y-3">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="vuln-source">Scanner source</Label>
                <select
                  id="vuln-source"
                  value={source}
                  onChange={(event) =>
                    setSource(
                      event.currentTarget.value === "openvas"
                        ? "openvas"
                        : "nessus",
                    )
                  }
                  className="h-9 w-full rounded-sx border border-border bg-transparent px-2 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  <option value="nessus" className="bg-card text-foreground">
                    Nessus (.nessus)
                  </option>
                  <option value="openvas" className="bg-card text-foreground">
                    OpenVAS / Greenbone GMP
                  </option>
                </select>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="vuln-file">Selected file</Label>
                <p
                  id="vuln-file"
                  className="h-9 truncate rounded-sx border border-dashed border-border px-2 py-1.5 text-xs font-mono text-muted-foreground"
                >
                  {file === null
                    ? "— none —"
                    : `${file.name} (${Math.round(file.size / 1024)} KiB)`}
                </p>
              </div>
            </div>

            <div
              onDragOver={(event) => {
                event.preventDefault();
                setDragOver(true);
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={onDrop}
              className={`flex flex-col items-center justify-center gap-2 rounded-sx border border-dashed p-6 text-sm text-muted-foreground transition-colors ${
                dragOver
                  ? "border-accent bg-accent/10"
                  : "border-border bg-card/40"
              }`}
            >
              <FileUp className="h-6 w-6 text-accent" aria-hidden />
              <p>Drag &amp; drop the XML payload here, or click to choose</p>
              <input
                ref={fileInputRef}
                id="vuln-file-input"
                type="file"
                accept=".xml,.nessus,application/xml,text/xml"
                onChange={onSelectFile}
                className="text-xs text-foreground"
              />
            </div>

            <div className="flex justify-end">
              <Button type="submit" disabled={submitting || file === null}>
                {submitting ? "Importing…" : "Import"}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Import history</CardTitle>
          <CardDescription>
            Persisted server-side via{" "}
            <code className="text-foreground">GET /v1/vuln/imports</code>.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Time</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Assets</TableHead>
                <TableHead className="text-right">Findings</TableHead>
                <TableHead className="text-xs">ID</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {imports.length === 0 ? (
                <TableRow>
                  <TableCell
                    colSpan={6}
                    className="py-8 text-center text-xs text-muted-foreground"
                  >
                    No imports yet — upload one above.
                  </TableCell>
                </TableRow>
              ) : (
                imports.map((row) => (
                  <TableRow key={row.id}>
                    <TableCell className="text-xs font-mono">
                      {row.ingested_at.slice(11, 19)}
                    </TableCell>
                    <TableCell className="text-xs">{row.source}</TableCell>
                    <TableCell>
                      <StatusBadge status={row.status} />
                    </TableCell>
                    <TableCell className="text-xs text-right font-mono">
                      {row.asset_count}
                    </TableCell>
                    <TableCell className="text-xs text-right font-mono">
                      {row.finding_count}
                    </TableCell>
                    <TableCell className="text-[11px] font-mono text-muted-foreground">
                      {row.id.slice(0, 8)}…
                    </TableCell>
                  </TableRow>
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
  let variant: "success" | "critical" | "outline" | "default" = "default";
  if (status === "ok") variant = "success";
  else if (status === "failed") variant = "critical";
  else if (status === "partial") variant = "outline";
  return <Badge variant={variant}>{status}</Badge>;
}
