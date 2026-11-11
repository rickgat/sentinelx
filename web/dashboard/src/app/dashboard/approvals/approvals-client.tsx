"use client";

import * as React from "react";
import { ShieldCheck, Check } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/components/toast";
import type { Engagement } from "@/lib/types";

/**
 * BAS-run approvals entry.
 *
 * The backend approvals API does not exist yet. Until it lands, this page
 * collects approvals into `sessionStorage` so a BAS operator can sanity-
 * check that two distinct approvers exist before submitting an active-
 * exploit run on the BAS page.
 *
 * Storage shape (keyed by `(engagement_id, technique_id)`):
 *   sessionStorage["sx.approvals"] = {
 *     [`${engagement_id}::${technique_id}`]: Approval[]
 *   }
 *
 * Approval = { engagement_id, technique_id, approver_email, reason, recorded_at }.
 * Same-email duplicates inside the same key are refused.
 */

const STORAGE_KEY = "sx.approvals";
const APPROVALS_REQUIRED = 2;

interface Approval {
  engagement_id: string;
  technique_id: string;
  approver_email: string;
  reason: string;
  recorded_at: string;
}

type Store = Record<string, ReadonlyArray<Approval>>;

function storeKey(engagementId: string, techniqueId: string): string {
  return `${engagementId}::${techniqueId}`;
}

function loadStore(): Store {
  if (typeof window === "undefined") {
    return {};
  }
  try {
    const raw = window.sessionStorage.getItem(STORAGE_KEY);
    if (raw === null) {
      return {};
    }
    const parsed: unknown = JSON.parse(raw);
    if (parsed === null || typeof parsed !== "object") {
      return {};
    }
    return parsed as Store;
  } catch {
    return {};
  }
}

function persistStore(store: Store): void {
  if (typeof window === "undefined") {
    return;
  }
  try {
    window.sessionStorage.setItem(STORAGE_KEY, JSON.stringify(store));
  } catch {
    // sessionStorage may be unavailable (private browsing edge case) — swallow.
  }
}

interface Props {
  engagements: ReadonlyArray<Engagement>;
  apiAvailable: boolean;
  defaultEmail: string;
}

export function ApprovalsClient({ engagements, apiAvailable, defaultEmail }: Props) {
  const toast = useToast();
  const [engagementId, setEngagementId] = React.useState<string>("");
  const [techniqueId, setTechniqueId] = React.useState<string>("");
  const [approverEmail, setApproverEmail] = React.useState<string>(defaultEmail);
  const [reason, setReason] = React.useState<string>("");
  const [store, setStore] = React.useState<Store>({});

  // Hydrate from sessionStorage on mount only.
  React.useEffect(() => {
    setStore(loadStore());
  }, []);

  function recordApproval(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const engagement = engagementId.trim();
    const technique = techniqueId.trim();
    const email = approverEmail.trim().toLowerCase();
    const reasonTrimmed = reason.trim();

    if (engagement.length === 0) {
      toast.push({ kind: "error", message: "Engagement is required." });
      return;
    }
    if (technique.length === 0) {
      toast.push({ kind: "error", message: "Technique id is required." });
      return;
    }
    if (email.length === 0 || !email.includes("@")) {
      toast.push({ kind: "error", message: "A valid approver email is required." });
      return;
    }
    if (reasonTrimmed.length === 0) {
      toast.push({ kind: "error", message: "Reason is required." });
      return;
    }

    const key = storeKey(engagement, technique);
    const existing = store[key] ?? [];
    if (existing.some((a) => a.approver_email === email)) {
      toast.push({
        kind: "error",
        message: `${email} has already approved this technique.`,
      });
      return;
    }

    const approval: Approval = {
      engagement_id: engagement,
      technique_id: technique,
      approver_email: email,
      reason: reasonTrimmed,
      recorded_at: new Date().toISOString(),
    };
    const next: Store = { ...store, [key]: [...existing, approval] };
    setStore(next);
    persistStore(next);
    setReason("");
    toast.push({ kind: "success", message: "Approval recorded locally." });
  }

  const engagementName = React.useCallback(
    (id: string): string => {
      const match = engagements.find((e) => e.id === id);
      return match?.name ?? id;
    },
    [engagements],
  );

  const groups = React.useMemo(() => {
    return Object.entries(store)
      .map(([key, approvals]) => ({ key, approvals }))
      .sort((a, b) => a.key.localeCompare(b.key));
  }, [store]);

  return (
    <div className="space-y-4">
      <div
        role="alert"
        className="rounded-sx border border-medium/40 bg-medium/10 px-3 py-2 text-xs text-medium"
      >
        Two-person rule: every active-exploit run requires two distinct approvers.
        This UI records approvals locally for now; a backend approvals API lands in
        the next phase.
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-accent" aria-hidden />
            BAS Approvals
          </CardTitle>
          <CardDescription>
            Record an approval for a specific engagement + technique. Two distinct
            approver emails are required before the run is considered authorized.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {!apiAvailable ? (
            <div
              role="alert"
              className="mb-4 rounded-sx border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical"
            >
              API unavailable — engagement list could not be loaded.
            </div>
          ) : null}
          <form onSubmit={recordApproval} className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="approval-engagement">Engagement</Label>
              <select
                id="approval-engagement"
                value={engagementId}
                onChange={(event) => setEngagementId(event.currentTarget.value)}
                required
                className="h-9 w-full rounded-sx border border-border bg-transparent px-2 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                <option value="" className="bg-card text-foreground">
                  — select engagement —
                </option>
                {engagements.map((e) => (
                  <option key={e.id} value={e.id} className="bg-card text-foreground">
                    {e.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="approval-technique">Technique ID</Label>
              <Input
                id="approval-technique"
                value={techniqueId}
                onChange={(event) => setTechniqueId(event.currentTarget.value)}
                placeholder="T1003"
                required
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="approval-email">Approver email</Label>
              <Input
                id="approval-email"
                type="email"
                value={approverEmail}
                onChange={(event) => setApproverEmail(event.currentTarget.value)}
                placeholder="operator@example.com"
                required
              />
            </div>
            <div className="space-y-1.5 md:col-span-2">
              <Label htmlFor="approval-reason">Reason</Label>
              <textarea
                id="approval-reason"
                value={reason}
                onChange={(event) => setReason(event.currentTarget.value)}
                placeholder="Why this run is authorized…"
                rows={3}
                required
                className="flex w-full rounded-sx border border-border bg-transparent px-3 py-2 text-sm text-foreground shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              />
            </div>
            <div className="md:col-span-2 flex justify-end">
              <Button type="submit">Record approval</Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Recorded approvals (this session)</CardTitle>
          <CardDescription>
            Cleared on tab close. Backed by sessionStorage — never sent upstream.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {groups.length === 0 ? (
            <div className="py-8 text-center text-xs text-muted-foreground">
              No approvals recorded yet.
            </div>
          ) : (
            <ul className="space-y-3">
              {groups.map(({ key, approvals }) => {
                const first = approvals[0];
                if (first === undefined) {
                  return null;
                }
                const count = approvals.length;
                const satisfied = count >= APPROVALS_REQUIRED;
                return (
                  <li
                    key={key}
                    className="rounded-sx border border-border bg-card/40 p-3"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="space-y-0.5">
                        <div className="text-sm font-medium text-foreground">
                          {engagementName(first.engagement_id)}
                          <span className="ml-2 text-xs text-muted-foreground">
                            technique{" "}
                            <span className="font-mono">{first.technique_id}</span>
                          </span>
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {count} / {APPROVALS_REQUIRED} approvers
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {satisfied ? (
                          <Badge variant="success" className="gap-1">
                            <Check className="h-3 w-3" aria-hidden />
                            authorized
                          </Badge>
                        ) : (
                          <Badge variant="medium">awaiting</Badge>
                        )}
                      </div>
                    </div>
                    <ul className="mt-2 space-y-1">
                      {approvals.map((approval) => (
                        <li
                          key={`${approval.approver_email}:${approval.recorded_at}`}
                          className="flex items-start justify-between gap-3 text-xs text-muted-foreground"
                        >
                          <div className="space-y-0.5">
                            <div className="font-mono text-foreground">
                              {approval.approver_email}
                            </div>
                            <div>{approval.reason}</div>
                          </div>
                          <time className="font-mono">
                            {approval.recorded_at.slice(11, 19)}
                          </time>
                        </li>
                      ))}
                    </ul>
                  </li>
                );
              })}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
