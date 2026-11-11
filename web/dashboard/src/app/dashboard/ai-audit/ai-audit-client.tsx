"use client";

import * as React from "react";
import { Bot, Loader2, PlayCircle } from "lucide-react";

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
 * AI Security Audit client — renders the AI asset inventory and governance
 * controls, and (for callers with `ai-audit:run`) triggers a full audit run
 * through the `/api/ai-audit/run` browser proxy.
 */

export interface AiAssetView {
  id: string;
  tenant_id?: string;
  kind: string;
  name: string;
  provider: string;
  endpoint?: string;
  discovered_at: string;
  metadata: Record<string, string>;
}

export interface AiControlView {
  id: string;
  title: string;
  framework: string;
  description: string;
}

interface AiControlEvidenceView {
  control_id: string;
  status: string;
  detail: string;
  collected_at: string;
}

interface AiAuditReportView {
  assets: AiAssetView[];
  probe_results: unknown[];
  modelfile_findings: unknown[];
  control_evidence: AiControlEvidenceView[];
}

interface RunEnvelope {
  data?: AiAuditReportView;
  error?: { code?: string; message?: string };
}

const KIND_LABEL: Record<string, string> = {
  llm_api_endpoint: "LLM API Endpoint",
  model_registry: "Model Registry",
  vector_store: "Vector Store",
  model_file: "Model File",
  agent_framework: "Agent Framework",
  mcp_server: "MCP Server",
};

const FRAMEWORK_LABEL: Record<string, string> = {
  nist_ai_rmf: "NIST AI RMF",
  iso_42001: "ISO/IEC 42001",
  eu_ai_act: "EU AI Act",
};

interface AiAuditClientProps {
  initialAssets: AiAssetView[];
  initialControls: AiControlView[];
  canRun: boolean;
}

export function AiAuditClient({
  initialAssets,
  initialControls,
  canRun,
}: AiAuditClientProps): React.JSX.Element {
  const [running, setRunning] = React.useState(false);
  const [report, setReport] = React.useState<AiAuditReportView | null>(null);
  const [error, setError] = React.useState<string | null>(null);

  async function runAudit(): Promise<void> {
    setRunning(true);
    setError(null);
    try {
      const res = await fetch("/api/ai-audit/run", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      });
      const body = (await res.json()) as RunEnvelope;
      if (!res.ok || body.data === undefined) {
        setError(body.error?.message ?? `audit run failed (${res.status})`);
        return;
      }
      setReport(body.data);
    } catch {
      setError("audit run request failed");
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <Card>
        <CardHeader>
          <div className="flex items-start justify-between gap-4">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Bot className="h-4 w-4 text-accent" aria-hidden />
                AI Security Audit
              </CardTitle>
              <CardDescription>
                AI asset inventory, AI-BOM, and governance controls
                (NIST AI RMF / ISO 42001 / EU AI Act). AI-SEC-001.
              </CardDescription>
            </div>
            {canRun ? (
              <Button onClick={runAudit} disabled={running}>
                {running ? (
                  <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
                ) : (
                  <PlayCircle className="h-4 w-4" aria-hidden />
                )}
                <span className="ml-2">Run audit</span>
              </Button>
            ) : null}
          </div>
        </CardHeader>
        {error !== null ? (
          <CardContent>
            <p className="text-xs text-destructive">{error}</p>
          </CardContent>
        ) : null}
        {report !== null ? (
          <CardContent>
            <p className="text-xs text-muted-foreground">
              Audit complete — {report.assets.length} asset(s),{" "}
              {report.probe_results.length} probe outcome(s),{" "}
              {report.modelfile_findings.length} model-file finding(s),{" "}
              {report.control_evidence.length} control evidence record(s).
              The run was recorded in the copilot-decision audit trail.
            </p>
          </CardContent>
        ) : null}
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>AI Asset Inventory</CardTitle>
          <CardDescription>
            Discovered AI assets for your tenant.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {initialAssets.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No AI assets discovered for this tenant yet.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Kind</TableHead>
                  <TableHead>Provider</TableHead>
                  <TableHead>Endpoint</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {initialAssets.map((a) => (
                  <TableRow key={a.id}>
                    <TableCell className="font-medium">{a.name}</TableCell>
                    <TableCell>
                      <Badge>{KIND_LABEL[a.kind] ?? a.kind}</Badge>
                    </TableCell>
                    <TableCell>{a.provider}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {a.endpoint ?? "—"}
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
          <CardTitle>AI Governance Controls</CardTitle>
          <CardDescription>
            Built-in controls across NIST AI RMF, ISO/IEC 42001, and the EU
            AI Act.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {initialControls.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No controls available.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Control</TableHead>
                  <TableHead>Framework</TableHead>
                  <TableHead>Title</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {initialControls.map((c) => (
                  <TableRow key={c.id}>
                    <TableCell className="font-mono text-xs">{c.id}</TableCell>
                    <TableCell>
                      <Badge>
                        {FRAMEWORK_LABEL[c.framework] ?? c.framework}
                      </Badge>
                    </TableCell>
                    <TableCell>{c.title}</TableCell>
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
