import { redirect } from "next/navigation";
import { Bot } from "lucide-react";

import { apiGet, ApiError } from "@/lib/api-client";
import { getAccessToken } from "@/lib/server-fetch";
import { auth } from "@/lib/auth";
import { hasPermission } from "@/lib/permissions";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

import {
  AiAuditClient,
  type AiAssetView,
  type AiControlView,
} from "./ai-audit-client";

/**
 * AI Security Audit (AI-SEC-001) dashboard.
 *
 * Server-rendered: gates on the `ai-audit:read` permission (403 card when
 * absent, mirroring `dashboard/admin/secrets`), then pulls the AI asset
 * inventory and the AI governance controls for the caller's tenant and hands
 * them to the client component. The client can trigger a full audit run via
 * the `/api/ai-audit/run` browser proxy.
 */

interface AssetsBody {
  assets: AiAssetView[];
}

interface ControlsBody {
  controls: AiControlView[];
}

export default async function AiAuditPage(): Promise<React.JSX.Element> {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  const session = await auth();
  const permissions = session?.user.permissions ?? [];
  if (!hasPermission(permissions, "ai_audit:read")) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bot className="h-4 w-4 text-accent" aria-hidden />
            AI Security Audit
          </CardTitle>
          <CardDescription>
            403 — you do not have the <code>ai_audit:read</code> permission
            required to view the AI security audit surface.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground">
            Ask a workspace administrator to grant the role. AI audit runs are
            recorded in the copilot-decision audit trail.
          </p>
        </CardContent>
      </Card>
    );
  }

  const [assetsResult, controlsResult] = await Promise.allSettled([
    apiGet<AssetsBody>("/v1/ai-audit/assets", token),
    apiGet<ControlsBody>("/v1/ai-audit/controls", token),
  ]);

  const assets: AiAssetView[] =
    assetsResult.status === "fulfilled" ? assetsResult.value.assets : [];
  const controls: AiControlView[] =
    controlsResult.status === "fulfilled" ? controlsResult.value.controls : [];
  void (assetsResult.status === "rejected" && assetsResult.reason instanceof ApiError);
  void (controlsResult.status === "rejected" && controlsResult.reason instanceof ApiError);

  const canRun = hasPermission(permissions, "ai_audit:run");

  return (
    <AiAuditClient
      initialAssets={assets}
      initialControls={controls}
      canRun={canRun}
    />
  );
}
