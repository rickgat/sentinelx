"use client";

import * as React from "react";
import { Laptop, ShieldCheck } from "lucide-react";

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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/components/toast";

export type PostureRule =
  | "require_disk_encryption"
  | "require_edr"
  | "require_screen_lock";

export interface PosturePolicyView {
  os_allow_list: string[];
  os_block_list: string[];
  minimum_os_versions: Record<string, string>;
  edr_vendor_allow_list: string[];
  max_screen_lock_minutes: number | null;
  rules: ReadonlyArray<PostureRule>;
}

export interface PostureClaimsSummary {
  os_name?: string;
  os_version?: string;
  disk_encrypted: boolean;
  edr_present: boolean;
  edr_vendor?: string;
  screen_lock_minutes?: number;
}

export interface PostureSessionView {
  id: string;
  user_id: string;
  session_id: string;
  status: "trusted" | "untrusted" | "stale";
  reasons: string[];
  claims: PostureClaimsSummary;
  observed_at: string;
}

const ALL_RULES: ReadonlyArray<PostureRule> = [
  "require_disk_encryption",
  "require_edr",
  "require_screen_lock",
];

const RULE_LABELS: Record<PostureRule, string> = {
  require_disk_encryption: "Require disk encryption",
  require_edr: "Require EDR agent",
  require_screen_lock: "Require screen lock",
};

function csvToList(input: string): string[] {
  return input
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

function listToCsv(items: ReadonlyArray<string>): string {
  return items.join(", ");
}

function statusBadgeVariant(
  status: "trusted" | "untrusted" | "stale",
): "success" | "critical" | "medium" {
  switch (status) {
    case "trusted":
      return "success";
    case "untrusted":
      return "critical";
    case "stale":
      return "medium";
  }
}

export function DeviceTrustClient({
  initialPolicy,
  initialSessions,
}: {
  initialPolicy: PosturePolicyView;
  initialSessions: ReadonlyArray<PostureSessionView>;
}) {
  const toast = useToast();
  const [policy, setPolicy] = React.useState<PosturePolicyView>(initialPolicy);
  const [osAllow, setOsAllow] = React.useState(listToCsv(policy.os_allow_list));
  const [osBlock, setOsBlock] = React.useState(listToCsv(policy.os_block_list));
  const [edrVendors, setEdrVendors] = React.useState(
    listToCsv(policy.edr_vendor_allow_list),
  );
  const [maxLock, setMaxLock] = React.useState<string>(
    policy.max_screen_lock_minutes === null
      ? ""
      : String(policy.max_screen_lock_minutes),
  );
  const [rules, setRules] = React.useState<ReadonlySet<PostureRule>>(
    new Set(policy.rules),
  );
  const [submitting, setSubmitting] = React.useState(false);
  const [sessions, setSessions] = React.useState<
    ReadonlyArray<PostureSessionView>
  >(initialSessions);

  async function save() {
    const parsedLock = maxLock.trim().length === 0
      ? null
      : Math.max(0, Math.min(1440, Number.parseInt(maxLock.trim(), 10) || 0));
    const body: PosturePolicyView = {
      os_allow_list: csvToList(osAllow),
      os_block_list: csvToList(osBlock),
      minimum_os_versions: policy.minimum_os_versions,
      edr_vendor_allow_list: csvToList(edrVendors),
      max_screen_lock_minutes: parsedLock,
      rules: ALL_RULES.filter((r) => rules.has(r)),
    };
    setSubmitting(true);
    try {
      const res = await fetch("/api/device-trust/policy", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const parsed: {
        data?: PosturePolicyView;
        error?: { message?: string };
      } = await res.json().catch(() => ({}));
      if (!res.ok || parsed.data === undefined) {
        const message = parsed.error?.message ?? `Save failed (${res.status})`;
        toast.push({ kind: "error", message });
        return;
      }
      setPolicy(parsed.data);
      toast.push({ kind: "success", message: "Device-trust policy saved." });
    } catch {
      toast.push({ kind: "error", message: "Network error — please retry." });
    } finally {
      setSubmitting(false);
    }
  }

  async function refreshSessions() {
    try {
      const res = await fetch("/api/device-trust/sessions?limit=50", {
        cache: "no-store",
      });
      const parsed: {
        data?: { items: PostureSessionView[] };
        error?: { message?: string };
      } = await res.json().catch(() => ({}));
      if (!res.ok || parsed.data === undefined) {
        const message =
          parsed.error?.message ?? `Refresh failed (${res.status})`;
        toast.push({ kind: "error", message });
        return;
      }
      setSessions(parsed.data.items);
    } catch {
      toast.push({ kind: "error", message: "Network error — please retry." });
    }
  }

  function toggleRule(rule: PostureRule) {
    setRules((prev) => {
      const next = new Set(prev);
      if (next.has(rule)) next.delete(rule);
      else next.add(rule);
      return next;
    });
  }

  return (
    <div className="space-y-6">
      <header className="flex items-center gap-2">
        <Laptop className="h-5 w-5 text-accent" aria-hidden />
        <div>
          <h1 className="text-lg font-semibold">Device Trust</h1>
          <p className="text-xs text-muted-foreground">
            Per-tenant posture policy + recent session signals.
          </p>
        </div>
      </header>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-accent" aria-hidden />
            Posture policy
          </CardTitle>
          <CardDescription>
            Editing requires the <code>admin:users</code> permission.
            Comma-separated lists; leave a field empty to disable that check.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="os-allow">OS allow-list</Label>
              <Input
                id="os-allow"
                value={osAllow}
                onChange={(e) => setOsAllow(e.currentTarget.value)}
                placeholder="macOS, Windows, Linux"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="os-block">OS block-list</Label>
              <Input
                id="os-block"
                value={osBlock}
                onChange={(e) => setOsBlock(e.currentTarget.value)}
                placeholder="Windows7, MS-DOS"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="edr-vendors">EDR vendor allow-list</Label>
              <Input
                id="edr-vendors"
                value={edrVendors}
                onChange={(e) => setEdrVendors(e.currentTarget.value)}
                placeholder="CrowdStrike, SentinelOne"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="max-lock">Max screen-lock minutes</Label>
              <Input
                id="max-lock"
                value={maxLock}
                onChange={(e) => setMaxLock(e.currentTarget.value)}
                placeholder="15"
                inputMode="numeric"
              />
            </div>
          </div>
          <fieldset className="space-y-2">
            <legend className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              Rules
            </legend>
            {ALL_RULES.map((rule) => (
              <label
                key={rule}
                className="flex items-center gap-2 text-sm text-foreground"
              >
                <input
                  type="checkbox"
                  checked={rules.has(rule)}
                  onChange={() => toggleRule(rule)}
                  className="h-4 w-4 rounded border-border text-accent"
                />
                <span>{RULE_LABELS[rule]}</span>
              </label>
            ))}
          </fieldset>
          <div className="flex justify-end">
            <Button onClick={save} disabled={submitting}>
              {submitting ? "Saving…" : "Save policy"}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-2">
          <div>
            <CardTitle>Recent sessions</CardTitle>
            <CardDescription>
              Posture snapshots recorded by the API middleware, newest-first.
            </CardDescription>
          </div>
          <Button variant="outline" onClick={refreshSessions}>
            Refresh
          </Button>
        </CardHeader>
        <CardContent>
          {sessions.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No posture snapshots recorded yet. The agent will start
              populating this table once it posts an{" "}
              <code>X-Sentinelx-Device-Posture</code> header.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Status</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>OS</TableHead>
                  <TableHead>EDR</TableHead>
                  <TableHead>Disk</TableHead>
                  <TableHead>Lock</TableHead>
                  <TableHead>Observed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell>
                      <Badge variant={statusBadgeVariant(s.status)}>
                        {s.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {s.user_id}
                    </TableCell>
                    <TableCell>
                      {s.claims.os_name ?? "—"}
                      {s.claims.os_version !== undefined
                        ? ` ${s.claims.os_version}`
                        : ""}
                    </TableCell>
                    <TableCell>
                      {s.claims.edr_present
                        ? (s.claims.edr_vendor ?? "yes")
                        : "no"}
                    </TableCell>
                    <TableCell>
                      {s.claims.disk_encrypted ? "encrypted" : "open"}
                    </TableCell>
                    <TableCell>
                      {s.claims.screen_lock_minutes !== undefined
                        ? `${s.claims.screen_lock_minutes}m`
                        : "—"}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {s.observed_at}
                    </TableCell>
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
