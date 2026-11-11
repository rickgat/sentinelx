import { notFound, redirect } from "next/navigation";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";
import type { Finding, Severity, FindingStatus } from "@/lib/types";

const sevVariant: Record<Severity, "critical" | "high" | "medium" | "outline" | "info"> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "outline",
  info: "info",
};

const statusVariant: Record<FindingStatus, "info" | "success" | "medium" | "outline"> = {
  open: "info",
  triaged: "info",
  in_progress: "medium",
  resolved: "success",
  false_positive: "outline",
  accepted: "outline",
  closed: "outline",
};

export default async function FindingDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  let finding: Finding;
  try {
    finding = await apiGet<Finding>(`/v1/findings/${encodeURIComponent(id)}`, token);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) {
      notFound();
    }
    if (err instanceof ApiError && err.status === 401) {
      redirect("/login");
    }
    throw err;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Link
          href="/dashboard/findings"
          className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-3 w-3" aria-hidden />
          Findings
        </Link>
      </div>

      <Card>
        <CardHeader className="space-y-3">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <CardTitle className="text-lg">{finding.title}</CardTitle>
              <p className="mt-1 font-mono text-[10px] text-muted-foreground">{finding.id}</p>
            </div>
            <div className="flex gap-1.5">
              <Badge variant={sevVariant[finding.severity] ?? "outline"}>{finding.severity}</Badge>
              <Badge variant={statusVariant[finding.status] ?? "outline"}>{finding.status}</Badge>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {typeof finding.description === "string" && finding.description.length > 0 ? (
            <div>
              <dt className="text-xs uppercase tracking-wide text-muted-foreground">Description</dt>
              <dd className="mt-1 whitespace-pre-wrap text-sm text-foreground">
                {finding.description}
              </dd>
            </div>
          ) : null}

          <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {typeof finding.cve_id === "string" && finding.cve_id.length > 0 ? (
              <div>
                <dt className="text-xs uppercase tracking-wide text-muted-foreground">CVE</dt>
                <dd className="mt-1 font-mono text-sm text-foreground">{finding.cve_id}</dd>
              </div>
            ) : null}
            {finding.cvss !== undefined ? (
              <div>
                <dt className="text-xs uppercase tracking-wide text-muted-foreground">CVSS</dt>
                <dd className="mt-1 text-sm text-foreground">{finding.cvss.toFixed(1)}</dd>
              </div>
            ) : null}
            <div>
              <dt className="text-xs uppercase tracking-wide text-muted-foreground">Asset</dt>
              <dd className="mt-1 font-mono text-xs text-foreground">{finding.asset_id}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-muted-foreground">First seen</dt>
              <dd className="mt-1 text-sm text-foreground">
                {finding.first_seen.slice(0, 19).replace("T", " ")}
              </dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-muted-foreground">Last seen</dt>
              <dd className="mt-1 text-sm text-foreground">
                {finding.last_seen.slice(0, 19).replace("T", " ")}
              </dd>
            </div>
          </dl>
        </CardContent>
      </Card>
    </div>
  );
}
