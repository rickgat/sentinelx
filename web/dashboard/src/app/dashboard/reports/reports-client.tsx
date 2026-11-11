"use client";

import * as React from "react";
import { Download, FileText } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { useToast } from "@/components/toast";
import type { Engagement } from "@/lib/types";

/**
 * Engagement-bound report renderer.
 *
 * Posts to `/api/reports/render`, which proxies to
 * `POST /v1/reports/render`. The backend produces one of five artifacts:
 *
 *   executive_pdf  — boardroom-ready PDF
 *   technical_pdf  — full finding list + remediation tracker
 *   sarif          — SARIF 2.1 (CI/CD ingestion)
 *   stix           — STIX 2.1 (threat-intel exchange)
 *   csv            — flat finding export
 *
 * The response is `{ filename, mime_type, byte_count, inline_payload }`
 * where `inline_payload` is base64-encoded. The dashboard turns that into
 * a Blob, then either offers a download or renders an inline preview for
 * the text formats.
 */

type Format = "executive_pdf" | "technical_pdf" | "sarif" | "stix" | "csv";

const FORMAT_LABELS: Record<Format, { label: string; description: string }> = {
  executive_pdf: {
    label: "Executive PDF",
    description: "Boardroom-ready summary — one page per crown jewel.",
  },
  technical_pdf: {
    label: "Technical PDF",
    description: "Full finding list with remediation tracker.",
  },
  sarif: {
    label: "SARIF 2.1",
    description: "Static-analysis interchange — ingest into CI/CD.",
  },
  stix: {
    label: "STIX 2.1",
    description: "Threat-intel exchange format.",
  },
  csv: {
    label: "CSV",
    description: "Flat finding export for spreadsheets.",
  },
};

interface RenderResponse {
  data?: {
    filename?: string;
    mime_type?: string;
    byte_count?: number;
    inline_payload?: string;
  };
  error?: { code?: string; message?: string };
}

interface Rendered {
  filename: string;
  mimeType: string;
  byteCount: number;
  format: Format;
  blobUrl: string;
  textPreview: string | null;
}

export function ReportsClient({
  initialEngagements,
  apiAvailable,
}: {
  initialEngagements: ReadonlyArray<Engagement>;
  apiAvailable: boolean;
}) {
  const toast = useToast();
  const [format, setFormat] = React.useState<Format>("executive_pdf");
  const [engagementId, setEngagementId] = React.useState<string>(
    initialEngagements[0]?.id ?? "",
  );
  const [loading, setLoading] = React.useState(false);
  const [result, setResult] = React.useState<Rendered | null>(null);

  React.useEffect(() => {
    return () => {
      if (result !== null) {
        URL.revokeObjectURL(result.blobUrl);
      }
    };
  }, [result]);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (engagementId.length === 0) {
      toast.push({ kind: "error", message: "Select an engagement first." });
      return;
    }
    setLoading(true);
    try {
      const res = await fetch("/api/reports/render", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ engagement_id: engagementId, format }),
      });
      const parsed: RenderResponse = await res.json().catch(() => ({}));
      if (!res.ok || parsed.data === undefined) {
        const msg = parsed.error?.message ?? `Render failed (${res.status})`;
        toast.push({ kind: "error", message: msg });
        return;
      }
      const payload = parsed.data.inline_payload ?? "";
      const filename = parsed.data.filename ?? "report";
      const mimeType = parsed.data.mime_type ?? "application/octet-stream";
      const byteCount = parsed.data.byte_count ?? 0;

      let blob: Blob;
      let textPreview: string | null = null;
      try {
        const bytes = base64ToBytes(payload);
        // Slice copies into a fresh ArrayBuffer so the Blob constructor
        // accepts it under strict TS lib types (some buffer libs return
        // `ArrayBufferLike` which TS narrows away from `ArrayBuffer`).
        blob = new Blob([bytes.slice().buffer], { type: mimeType });
        if (
          mimeType.startsWith("text/") ||
          mimeType.includes("json") ||
          mimeType.includes("xml") ||
          mimeType.includes("csv")
        ) {
          textPreview = new TextDecoder("utf-8").decode(bytes).slice(0, 50_000);
        }
      } catch {
        toast.push({ kind: "error", message: "Decoding payload failed." });
        return;
      }

      if (result !== null) {
        URL.revokeObjectURL(result.blobUrl);
      }
      setResult({
        filename,
        mimeType,
        byteCount,
        format,
        blobUrl: URL.createObjectURL(blob),
        textPreview,
      });
      toast.push({
        kind: "success",
        message: `Rendered ${filename} (${formatBytes(byteCount)}).`,
      });
    } catch {
      toast.push({ kind: "error", message: "Network error — please retry." });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-4 w-4 text-accent" aria-hidden />
            Reports
          </CardTitle>
          <CardDescription>
            Render an engagement to PDF / SARIF / STIX / CSV. Output is generated
            server-side and downloaded inline.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {!apiAvailable ? (
            <div className="rounded-sx border border-critical/40 bg-critical/10 p-3 text-xs text-critical">
              Failed to load engagements. The backend may be offline.
            </div>
          ) : null}
          <form onSubmit={submit} className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="report-engagement">Engagement</Label>
              <select
                id="report-engagement"
                value={engagementId}
                onChange={(event) => setEngagementId(event.currentTarget.value)}
                disabled={initialEngagements.length === 0}
                className="h-9 w-full rounded-sx border border-border bg-transparent px-2 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                {initialEngagements.length === 0 ? (
                  <option value="" className="bg-card text-foreground">
                    No engagements available
                  </option>
                ) : (
                  initialEngagements.map((e) => (
                    <option key={e.id} value={e.id} className="bg-card text-foreground">
                      {e.name}
                    </option>
                  ))
                )}
              </select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="report-format">Format</Label>
              <select
                id="report-format"
                value={format}
                onChange={(event) => setFormat(event.currentTarget.value as Format)}
                className="h-9 w-full rounded-sx border border-border bg-transparent px-2 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                {(Object.keys(FORMAT_LABELS) as Format[]).map((f) => (
                  <option key={f} value={f} className="bg-card text-foreground">
                    {FORMAT_LABELS[f].label}
                  </option>
                ))}
              </select>
              <p className="text-[11px] text-muted-foreground">
                {FORMAT_LABELS[format].description}
              </p>
            </div>
            <div className="md:col-span-2 flex justify-end">
              <Button type="submit" disabled={loading || engagementId.length === 0}>
                {loading ? "Rendering…" : "Generate"}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Result</CardTitle>
          <CardDescription>
            {result === null
              ? "No report rendered yet. Submit the form above."
              : `${result.filename} · ${result.mimeType} · ${formatBytes(result.byteCount)}`}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {result === null ? (
            <div className="py-8 text-center text-xs text-muted-foreground">
              Empty result panel.
            </div>
          ) : (
            <div className="space-y-3">
              <div className="flex gap-2">
                <a
                  href={result.blobUrl}
                  download={result.filename}
                  className="inline-flex items-center gap-2 rounded-sx border border-border bg-card px-3 py-1.5 text-xs hover:bg-muted/30"
                >
                  <Download className="h-3.5 w-3.5" aria-hidden />
                  Download {result.filename}
                </a>
              </div>
              {result.textPreview !== null ? (
                <div>
                  <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1">
                    Inline preview
                    {result.textPreview.length >= 50_000 ? " (truncated to 50 KB)" : ""}
                  </p>
                  <pre className="max-h-[480px] overflow-auto rounded-sx border border-border bg-muted/20 p-3 text-[11px] font-mono whitespace-pre-wrap break-all">
                    {result.textPreview}
                  </pre>
                </div>
              ) : result.mimeType === "application/pdf" ? (
                <iframe
                  title="rendered-pdf"
                  src={result.blobUrl}
                  className="h-[640px] w-full rounded-sx border border-border bg-white"
                />
              ) : (
                <p className="text-xs text-muted-foreground">
                  Binary payload — use the download button above.
                </p>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const len = binary.length;
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}
