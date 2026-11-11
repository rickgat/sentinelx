"use client";

import * as React from "react";
import Link from "next/link";
import { ShieldHalf, Smartphone } from "lucide-react";

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

export interface RbaWeightsView {
  w_ip_geo: number;
  w_velocity: number;
  w_business_hours: number;
  /** HIGH-001 — device-fingerprint signal weight. */
  w_device_fp: number;
  /** HIGH-001 — MFA-recency signal weight. */
  w_mfa_recent: number;
  /** HIGH-001 — 7-day success-rate signal weight. */
  w_success_rate: number;
  /** HIGH-001 — impossible-travel signal weight. */
  w_impossible_travel: number;
}

export interface RbaFeatureFlagsView {
  enable_ip_geo: boolean;
  enable_velocity: boolean;
  enable_business_hours: boolean;
  enable_device_fp: boolean;
  enable_mfa_recent: boolean;
  enable_success_rate: boolean;
  enable_impossible_travel: boolean;
}

export interface RbaConfigView {
  allow_threshold: number;
  block_threshold: number;
  weights: RbaWeightsView;
  feature_flags: RbaFeatureFlagsView;
  business_tz: string;
  business_hours_start: number;
  business_hours_end: number;
}

const SIGNAL_META: ReadonlyArray<{
  key: keyof RbaWeightsView;
  flag: keyof RbaFeatureFlagsView;
  label: string;
  hint: string;
}> = [
  { key: "w_ip_geo", flag: "enable_ip_geo", label: "IP-geo", hint: "Country-of-origin reputation, distance from baseline centroid." },
  { key: "w_velocity", flag: "enable_velocity", label: "Velocity", hint: "Login-attempt rate per user / IP / tenant in last minutes." },
  { key: "w_business_hours", flag: "enable_business_hours", label: "Business hours", hint: "Tenant-local hours-of-operation window." },
  { key: "w_device_fp", flag: "enable_device_fp", label: "Device fingerprint", hint: "HIGH-001. Known/unknown/revoked browser+UA hash per user." },
  { key: "w_mfa_recent", flag: "enable_mfa_recent", label: "MFA recency", hint: "HIGH-001. Strong-MFA success in last 5 minutes dampens risk." },
  { key: "w_success_rate", flag: "enable_success_rate", label: "Success rate (7d)", hint: "HIGH-001. Per-user 7-day rolling sign-in success rate." },
  { key: "w_impossible_travel", flag: "enable_impossible_travel", label: "Impossible travel", hint: "HIGH-001. Geo speed since last successful auth (> 900 km/h = impossible)." },
];

export interface RbaDecisionView {
  id: string;
  tenant_id: string;
  user_id?: string | null;
  ip: string;
  score: number;
  action: string;
  reason: string;
  decided_at: string;
}

interface RbaClientProps {
  initialDecisions: RbaDecisionView[];
  initialConfig: RbaConfigView;
}

const ACTION_BADGE_VARIANT: Record<
  string,
  "success" | "medium" | "critical" | "outline"
> = {
  allow: "success",
  step_up_mfa: "medium",
  block: "critical",
};

function actionLabel(action: string): string {
  switch (action) {
    case "allow":
      return "Allow";
    case "step_up_mfa":
      return "Step-up MFA";
    case "block":
      return "Block";
    default:
      return action;
  }
}

export function RbaClient({
  initialDecisions,
  initialConfig,
}: RbaClientProps): React.JSX.Element {
  const toast = useToast();
  const [decisions, setDecisions] =
    React.useState<RbaDecisionView[]>(initialDecisions);
  const [config, setConfig] = React.useState<RbaConfigView>(initialConfig);
  const [saving, setSaving] = React.useState(false);
  const [refreshing, setRefreshing] = React.useState(false);

  async function refreshDecisions(): Promise<void> {
    setRefreshing(true);
    try {
      const res = await fetch("/api/rba/decisions?limit=100", {
        method: "GET",
        cache: "no-store",
      });
      if (!res.ok) {
        throw new Error(`refresh failed: ${res.status}`);
      }
      const body: { data?: { decisions: RbaDecisionView[] } } = await res.json();
      setDecisions(body.data?.decisions ?? []);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "refresh failed";
      toast.push({ kind: "error", message: msg });
    } finally {
      setRefreshing(false);
    }
  }

  async function saveConfig(): Promise<void> {
    if (config.allow_threshold >= config.block_threshold) {
      toast.push({
        kind: "error",
        message: "allow_threshold must be less than block_threshold",
      });
      return;
    }
    const sum = SIGNAL_META.reduce((acc, m) => acc + config.weights[m.key], 0);
    if (sum < 0.99 || sum > 1.01) {
      toast.push({
        kind: "error",
        message: `weights must sum to ~1.0 across all 7 signals (got ${sum.toFixed(3)})`,
      });
      return;
    }
    setSaving(true);
    try {
      const res = await fetch("/api/rba/config", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(config),
        cache: "no-store",
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(text || `save failed: ${res.status}`);
      }
      const body: { data?: RbaConfigView } = await res.json();
      if (body.data !== undefined) {
        setConfig(body.data);
      }
      toast.push({ kind: "success", message: "RBA configuration saved" });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "save failed";
      toast.push({ kind: "error", message: msg });
    } finally {
      setSaving(false);
    }
  }

  function setWeight(key: keyof RbaWeightsView, raw: string): void {
    const v = Number.parseFloat(raw);
    if (!Number.isFinite(v)) {
      return;
    }
    const clamped = Math.max(0, Math.min(1, v));
    setConfig((prev) => ({
      ...prev,
      weights: { ...prev.weights, [key]: clamped },
    }));
  }

  function toggleFlag(key: keyof RbaFeatureFlagsView): void {
    setConfig((prev) => ({
      ...prev,
      feature_flags: { ...prev.feature_flags, [key]: !prev.feature_flags[key] },
    }));
  }

  const weightSum = SIGNAL_META.reduce(
    (acc, m) => acc + config.weights[m.key],
    0,
  );

  function setThreshold(
    key: "allow_threshold" | "block_threshold",
    raw: string,
  ): void {
    const v = Number.parseInt(raw, 10);
    if (!Number.isFinite(v)) {
      return;
    }
    setConfig((prev) => ({ ...prev, [key]: Math.max(0, Math.min(100, v)) }));
  }

  function setHour(
    key: "business_hours_start" | "business_hours_end",
    raw: string,
  ): void {
    const v = Number.parseInt(raw, 10);
    if (!Number.isFinite(v)) {
      return;
    }
    setConfig((prev) => ({ ...prev, [key]: Math.max(0, Math.min(23, v)) }));
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldHalf className="h-4 w-4 text-accent" aria-hidden />
            Adaptive authentication
            <Badge variant="medium" className="ml-2">
              risk-based
            </Badge>
            <Link
              href="/dashboard/rba/devices"
              className="ml-auto inline-flex items-center gap-1 rounded-sx border border-border px-2 py-1 text-xs font-normal text-foreground hover:bg-muted"
            >
              <Smartphone className="h-3.5 w-3.5" aria-hidden />
              Known devices
            </Link>
          </CardTitle>
          <CardDescription>
            Per-tenant Risk-Based Authentication policy. Tune the
            thresholds + signal weights below; the engine consults these
            on every login. The decision feed shows the last 100
            evaluations, newest first. Use the “Known devices” link to
            inspect or revoke a user’s enrolled device fingerprints.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="allow_threshold">Allow threshold (0-100)</Label>
              <Input
                id="allow_threshold"
                type="number"
                min={0}
                max={100}
                value={config.allow_threshold}
                onChange={(e) =>
                  setThreshold("allow_threshold", e.currentTarget.value)
                }
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="block_threshold">Block threshold (0-100)</Label>
              <Input
                id="block_threshold"
                type="number"
                min={0}
                max={100}
                value={config.block_threshold}
                onChange={(e) =>
                  setThreshold("block_threshold", e.currentTarget.value)
                }
              />
            </div>
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label className="text-sm font-semibold">Signals (weights + flags)</Label>
              <span
                className={
                  weightSum >= 0.99 && weightSum <= 1.01
                    ? "text-xs font-mono text-success"
                    : "text-xs font-mono text-critical"
                }
                aria-live="polite"
              >
                Σ = {weightSum.toFixed(3)} (target 1.000)
              </span>
            </div>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[180px]">Signal</TableHead>
                  <TableHead className="w-[110px]">Weight</TableHead>
                  <TableHead className="w-[80px]">Enabled</TableHead>
                  <TableHead>Description</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {SIGNAL_META.map((m) => {
                  const flagOn = config.feature_flags[m.flag];
                  return (
                    <TableRow key={m.key}>
                      <TableCell className="font-medium text-sm">
                        {m.label}
                      </TableCell>
                      <TableCell>
                        <Input
                          id={`weight-${m.key}`}
                          aria-label={`${m.label} weight`}
                          type="number"
                          step="0.05"
                          min={0}
                          max={1}
                          value={config.weights[m.key]}
                          onChange={(e) =>
                            setWeight(m.key, e.currentTarget.value)
                          }
                          disabled={!flagOn}
                        />
                      </TableCell>
                      <TableCell>
                        <button
                          type="button"
                          role="switch"
                          aria-checked={flagOn}
                          aria-label={`Toggle ${m.label}`}
                          onClick={() => toggleFlag(m.flag)}
                          className={
                            "inline-flex h-5 w-9 items-center rounded-full transition-colors " +
                            (flagOn ? "bg-success" : "bg-muted")
                          }
                        >
                          <span
                            className={
                              "inline-block h-4 w-4 transform rounded-full bg-background transition-transform " +
                              (flagOn ? "translate-x-4" : "translate-x-0.5")
                            }
                          />
                        </button>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {m.hint}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div className="space-y-1.5">
              <Label htmlFor="business_tz">Business timezone</Label>
              <Input
                id="business_tz"
                value={config.business_tz}
                onChange={(e) =>
                  setConfig((p) => ({
                    ...p,
                    business_tz: e.currentTarget.value,
                  }))
                }
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="business_hours_start">Open hour (0-23)</Label>
              <Input
                id="business_hours_start"
                type="number"
                min={0}
                max={23}
                value={config.business_hours_start}
                onChange={(e) =>
                  setHour("business_hours_start", e.currentTarget.value)
                }
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="business_hours_end">Close hour (0-23)</Label>
              <Input
                id="business_hours_end"
                type="number"
                min={0}
                max={23}
                value={config.business_hours_end}
                onChange={(e) =>
                  setHour("business_hours_end", e.currentTarget.value)
                }
              />
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <Button
              variant="outline"
              onClick={() => {
                void refreshDecisions();
              }}
              disabled={refreshing}
            >
              {refreshing ? "Refreshing…" : "Refresh feed"}
            </Button>
            <Button
              onClick={() => {
                void saveConfig();
              }}
              disabled={saving}
            >
              {saving ? "Saving…" : "Save configuration"}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Recent decisions ({decisions.length})</CardTitle>
          <CardDescription>
            Newest first. Color-coded by action — green=allow,
            amber=step-up MFA, red=block.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {decisions.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No decisions recorded yet. Trigger a login and refresh.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Decided at</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>Score</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Reason</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {decisions.map((d) => (
                  <TableRow key={d.id}>
                    <TableCell className="whitespace-nowrap font-mono text-xs">
                      {d.decided_at}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{d.ip}</TableCell>
                    <TableCell className="font-mono text-xs">
                      {d.user_id ?? "—"}
                    </TableCell>
                    <TableCell className="font-mono">{d.score}</TableCell>
                    <TableCell>
                      <Badge variant={ACTION_BADGE_VARIANT[d.action] ?? "outline"}>
                        {actionLabel(d.action)}
                      </Badge>
                    </TableCell>
                    <TableCell className="max-w-md truncate">{d.reason}</TableCell>
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
