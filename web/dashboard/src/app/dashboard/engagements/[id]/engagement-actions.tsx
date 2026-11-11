"use client";

import * as React from "react";
import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useToast } from "@/components/toast";
import type { EngagementStatus } from "@/lib/types";

interface Props {
  id: string;
  status: EngagementStatus;
}

interface ActionDef {
  label: string;
  action: "pause" | "resume" | "abort" | "complete" | "clone";
  variant?: "default" | "destructive" | "outline";
  requireConfirm?: boolean;
}

function actionsFor(status: EngagementStatus): ReadonlyArray<ActionDef> {
  const result: ActionDef[] = [{ label: "Clone", action: "clone", variant: "outline" }];
  if (status === "active") {
    result.unshift({ label: "Pause", action: "pause", variant: "outline" });
    result.unshift({ label: "Complete", action: "complete" });
    result.unshift({ label: "Abort", action: "abort", variant: "destructive", requireConfirm: true });
  } else if (status === "paused") {
    result.unshift({ label: "Resume", action: "resume" });
    result.unshift({ label: "Abort", action: "abort", variant: "destructive", requireConfirm: true });
  }
  return result;
}

export function EngagementActions({ id, status }: Props) {
  const router = useRouter();
  const toast = useToast();
  const [running, setRunning] = React.useState<string | null>(null);

  async function run(action: ActionDef) {
    if (action.requireConfirm) {
      const ok = window.confirm(`${action.label} this engagement?`);
      if (!ok) return;
    }
    setRunning(action.action);
    try {
      const body = action.action === "abort" ? { reason: "operator action" } : {};
      const res = await fetch(`/api/engagements/${encodeURIComponent(id)}/${action.action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const parsed = (await res.json().catch(() => ({}))) as {
          error?: { message?: string };
        };
        toast.push({
          kind: "error",
          message: parsed.error?.message ?? `${action.label} failed (${res.status})`,
        });
        return;
      }
      toast.push({ kind: "success", message: `${action.label} succeeded.` });
      router.refresh();
    } catch {
      toast.push({ kind: "error", message: "Network error — please retry." });
    } finally {
      setRunning(null);
    }
  }

  const actions = actionsFor(status);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">Actions</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap gap-2">
          {actions.map((a) => (
            <Button
              key={a.action}
              variant={a.variant ?? "default"}
              size="sm"
              disabled={running !== null}
              onClick={() => run(a)}
            >
              {running === a.action ? `${a.label}…` : a.label}
            </Button>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
