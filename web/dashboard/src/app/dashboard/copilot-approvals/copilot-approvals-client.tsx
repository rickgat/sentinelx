"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { ClipboardCheck, Check, X } from "lucide-react";

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
import { useToast } from "@/components/toast";
import { cn } from "@/lib/utils";

/**
 * P1-012 Copilot human-in-loop approval queue.
 *
 * Renders the pending-approval list SSR'd by the page wrapper plus an
 * inline Approve / Reject form per card. The Approve and Reject buttons
 * fire `POST /api/copilot/approvals/{token}/decide`. Reject requires a
 * non-empty `reason` per the backend contract.
 */

export interface PendingApprovalView {
  token: string;
  tenant_id: string;
  action_kind: string;
  action: unknown;
  proposer: string;
  status: string;
  proposed_at: string;
  expires_at: string;
}

interface Props {
  items: ReadonlyArray<PendingApprovalView>;
  apiAvailable: boolean;
  errorMessage: string | null;
}

interface DecisionEnvelope {
  data?: {
    token: string;
    status: string;
    reviewer: string;
    reason?: string;
    decided_at: string;
  };
  error?: { code?: string; message?: string; request_id?: string };
}

export function CopilotApprovalsClient({
  items,
  apiAvailable,
  errorMessage,
}: Props): React.JSX.Element {
  const toast = useToast();
  const router = useRouter();
  const [busy, setBusy] = React.useState<Record<string, boolean>>({});
  const [reasons, setReasons] = React.useState<Record<string, string>>({});

  const updateReason = React.useCallback((token: string, value: string) => {
    setReasons((prev) => ({ ...prev, [token]: value }));
  }, []);

  const decide = React.useCallback(
    async (token: string, decision: "approve" | "reject") => {
      if (busy[token] === true) {
        return;
      }
      if (decision === "reject") {
        const r = (reasons[token] ?? "").trim();
        if (r.length === 0) {
          toast.push({
            kind: "error",
            message: "Reject requires a non-empty reason.",
          });
          return;
        }
      }
      setBusy((prev) => ({ ...prev, [token]: true }));
      try {
        const body: { decision: string; reason?: string } = { decision };
        if (decision === "reject") {
          body.reason = (reasons[token] ?? "").trim();
        }
        const res = await fetch(
          `/api/copilot/approvals/${encodeURIComponent(token)}/decide`,
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            cache: "no-store",
            body: JSON.stringify(body),
          },
        );
        let parsed: DecisionEnvelope = {};
        try {
          parsed = (await res.json()) as DecisionEnvelope;
        } catch {
          parsed = {};
        }
        if (res.ok && parsed.data !== undefined) {
          toast.push({
            kind: "success",
            message: `Approval ${parsed.data.status}.`,
          });
          router.refresh();
          return;
        }
        const message =
          parsed.error?.message ?? `Decision failed (HTTP ${res.status})`;
        toast.push({ kind: "error", message });
      } catch {
        toast.push({
          kind: "error",
          message: "Network error contacting the approvals proxy.",
        });
      } finally {
        setBusy((prev) => ({ ...prev, [token]: false }));
      }
    },
    [busy, reasons, router, toast],
  );

  if (!apiAvailable) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ClipboardCheck className="h-4 w-4 text-accent" aria-hidden />
            Copilot Approvals
            <Badge variant="critical" className="ml-2">
              upstream error
            </Badge>
          </CardTitle>
          <CardDescription>
            sx-api is unreachable for this listing. Reload after the API
            comes back.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            {errorMessage ?? "Upstream request failed"}
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ClipboardCheck className="h-4 w-4 text-accent" aria-hidden />
            Copilot Approvals
            <Badge variant="low" className="ml-2">
              {items.length} pending
            </Badge>
          </CardTitle>
          <CardDescription>
            State-changing actions the AI Copilot has queued for human
            review. Approving runs the action; rejecting records the
            reason and discards it. Pending entries auto-expire after one
            hour.
          </CardDescription>
        </CardHeader>
      </Card>

      {items.length === 0 ? (
        <Card>
          <CardContent className="py-8 text-center text-sm text-muted-foreground">
            No copilot approvals are pending.
          </CardContent>
        </Card>
      ) : (
        items.map((item) => {
          const isBusy = busy[item.token] === true;
          const reason = reasons[item.token] ?? "";
          return (
            <Card key={item.token}>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <span className="font-mono text-xs uppercase tracking-wide text-muted-foreground">
                    {item.action_kind}
                  </span>
                  <Badge variant="medium" className="ml-2">
                    pending
                  </Badge>
                </CardTitle>
                <CardDescription className="space-y-1">
                  <span className="block">
                    Proposer:{" "}
                    <span className="font-mono text-xs">{item.proposer}</span>
                  </span>
                  <span className="block">
                    Proposed at:{" "}
                    <span className="font-mono text-xs">{item.proposed_at}</span>
                  </span>
                  <span className="block">
                    Expires at:{" "}
                    <span className="font-mono text-xs">{item.expires_at}</span>
                  </span>
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <pre
                  className={cn(
                    "max-h-48 overflow-y-auto rounded-sx border border-border bg-background/40 p-3 text-xs",
                  )}
                >
                  {JSON.stringify(item.action, null, 2)}
                </pre>
                <div className="space-y-2">
                  <Label htmlFor={`reason-${item.token}`}>
                    Reason (required to reject)
                  </Label>
                  <Input
                    id={`reason-${item.token}`}
                    value={reason}
                    onChange={(e) =>
                      updateReason(item.token, e.currentTarget.value)
                    }
                    placeholder="Optional on approve, required on reject"
                    maxLength={1024}
                    disabled={isBusy}
                  />
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Button
                    type="button"
                    onClick={() => void decide(item.token, "approve")}
                    disabled={isBusy}
                  >
                    <Check className="mr-1 h-4 w-4" aria-hidden />
                    {isBusy ? "Working…" : "Approve"}
                  </Button>
                  <Button
                    type="button"
                    variant="destructive"
                    onClick={() => void decide(item.token, "reject")}
                    disabled={isBusy}
                  >
                    <X className="mr-1 h-4 w-4" aria-hidden />
                    {isBusy ? "Working…" : "Reject"}
                  </Button>
                  <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
                    token:{" "}
                    <span className="font-mono">{item.token.slice(0, 8)}…</span>
                  </span>
                </div>
              </CardContent>
            </Card>
          );
        })
      )}
    </div>
  );
}
