import { notFound, redirect } from "next/navigation";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";
import type { Engagement, EngagementStatus } from "@/lib/types";
import { EngagementActions } from "./engagement-actions";

const statusVariant: Record<EngagementStatus, "info" | "success" | "medium" | "outline"> = {
  draft: "outline",
  scheduled: "info",
  active: "success",
  paused: "medium",
  completed: "outline",
  aborted: "outline",
  cancelled: "outline",
};

export default async function EngagementDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  let engagement: Engagement;
  try {
    engagement = await apiGet<Engagement>(`/v1/engagements/${encodeURIComponent(id)}`, token);
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
          href="/dashboard/engagements"
          className="inline-flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
        >
          <ArrowLeft className="h-3 w-3" aria-hidden />
          Engagements
        </Link>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-start justify-between space-y-0">
          <div>
            <CardTitle className="text-lg">{engagement.name}</CardTitle>
            <p className="mt-1 font-mono text-[10px] text-muted-foreground">{engagement.id}</p>
          </div>
          <Badge variant={statusVariant[engagement.status] ?? "outline"}>{engagement.status}</Badge>
        </CardHeader>
        <CardContent className="space-y-4">
          {typeof engagement.description === "string" && engagement.description.length > 0 ? (
            <div>
              <dt className="text-xs uppercase tracking-wide text-muted-foreground">Description</dt>
              <dd className="mt-1 text-sm text-foreground">{engagement.description}</dd>
            </div>
          ) : null}

          <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <dt className="text-xs uppercase tracking-wide text-muted-foreground">Created</dt>
              <dd className="mt-1 text-sm text-foreground">
                {engagement.created_at.slice(0, 19).replace("T", " ")}
              </dd>
            </div>
            <div>
              <dt className="text-xs uppercase tracking-wide text-muted-foreground">Last updated</dt>
              <dd className="mt-1 text-sm text-foreground">
                {engagement.updated_at.slice(0, 19).replace("T", " ")}
              </dd>
            </div>
          </dl>

          <div>
            <dt className="text-xs uppercase tracking-wide text-muted-foreground">
              Scopes ({Array.isArray(engagement.scopes) ? engagement.scopes.length : 0})
            </dt>
            <dd className="mt-1 flex flex-wrap gap-1.5">
              {(engagement.scopes ?? []).map((scope) => (
                <code
                  key={scope}
                  className="rounded-sx border border-border bg-muted/40 px-1.5 py-0.5 font-mono text-xs text-foreground"
                >
                  {scope}
                </code>
              ))}
            </dd>
          </div>
        </CardContent>
      </Card>

      <EngagementActions id={engagement.id} status={engagement.status} />
    </div>
  );
}
