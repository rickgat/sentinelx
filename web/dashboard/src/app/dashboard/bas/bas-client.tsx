"use client";

import * as React from "react";
import { Crosshair } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
import type { Asset, Engagement } from "@/lib/types";

const MODES: ReadonlyArray<BasMode> = ["theoretical", "safe_interactive"];

type BasMode = "theoretical" | "safe_interactive";

/**
 * BAS techniques registered by the production safety-pipeline. Hard-coded
 * here until the backend exposes a `GET /v1/bas/techniques` index. The
 * order matches `services/sx-monolith/src/adapters/bas.rs`.
 *
 * Includes the four foundation techniques plus the 25-technique P1-008
 * expansion grouped by ATT&CK tactic. Every entry tops out at
 * `passive_validation` or lower — no Active or RedTeam techniques ship.
 */
interface TechniqueEntry {
  id: string;
  label: string;
  maxMode: string;
  tactic: string;
  blurb: string;
}

const TECHNIQUES: ReadonlyArray<TechniqueEntry> = [
  // Foundation safe-only set.
  {
    id: "theoretical_reachability_v1",
    label: "Theoretical reachability",
    maxMode: "theoretical",
    tactic: "core",
    blurb: "Graph traversal only — zero packets sent.",
  },
  {
    id: "passive_cve_match_v1",
    label: "Passive CVE match",
    maxMode: "passive_validation",
    tactic: "core",
    blurb: "Match cached intel against asset fingerprints.",
  },
  {
    id: "safe_ssrf_probe_v1",
    label: "Safe SSRF probe",
    maxMode: "safe_interactive",
    tactic: "core",
    blurb: "OOB callback probe — non-destructive.",
  },
  {
    id: "safe_cred_validator_v1",
    label: "Safe credential validator",
    maxMode: "safe_interactive",
    tactic: "core",
    blurb: "Canary-credential validation against the IdP.",
  },
  // TA0001 Initial Access (P1-008).
  {
    id: "t1190_exploit_public_facing_app_v1",
    label: "T1190 Exploit public-facing app",
    maxMode: "passive_validation",
    tactic: "initial-access",
    blurb: "Counts exposed public-facing services; no probe sent.",
  },
  {
    id: "t1133_external_remote_services_v1",
    label: "T1133 External remote services",
    maxMode: "passive_validation",
    tactic: "initial-access",
    blurb: "Inventory of internet-reachable remote services.",
  },
  {
    id: "t1078_valid_accounts_v1",
    label: "T1078 Valid accounts",
    maxMode: "passive_validation",
    tactic: "initial-access",
    blurb: "Flags dormant or shared accounts that could be reused.",
  },
  {
    id: "t1566_phishing_v1",
    label: "T1566 Phishing",
    maxMode: "theoretical",
    tactic: "initial-access",
    blurb: "Theoretical phishing-surface enumeration only.",
  },
  {
    id: "t1199_trusted_relationship_v1",
    label: "T1199 Trusted relationship",
    maxMode: "passive_validation",
    tactic: "initial-access",
    blurb: "Counts trusted-partner attack paths.",
  },
  // TA0003 Persistence (P1-008).
  {
    id: "t1098_account_manipulation_v1",
    label: "T1098 Account manipulation",
    maxMode: "passive_validation",
    tactic: "persistence",
    blurb: "Detects suspicious permission/role drift.",
  },
  {
    id: "t1136_create_account_v1",
    label: "T1136 Create account",
    maxMode: "passive_validation",
    tactic: "persistence",
    blurb: "Flags recently-created accounts of interest.",
  },
  {
    id: "t1505_server_software_component_v1",
    label: "T1505 Server software component",
    maxMode: "passive_validation",
    tactic: "persistence",
    blurb: "Audits unexpected web-server modules / agents.",
  },
  {
    id: "t1547_boot_logon_autostart_v1",
    label: "T1547 Boot/Logon autostart",
    maxMode: "passive_validation",
    tactic: "persistence",
    blurb: "Inventories autostart entries; no modifications.",
  },
  {
    id: "t1543_create_or_modify_system_process_v1",
    label: "T1543 Create/Modify system process",
    maxMode: "passive_validation",
    tactic: "persistence",
    blurb: "Audits unmanaged services / daemons.",
  },
  // TA0004 Privilege Escalation (P1-008).
  {
    id: "t1068_exploit_for_privesc_v1",
    label: "T1068 Exploit for priv-esc",
    maxMode: "theoretical",
    tactic: "privilege-escalation",
    blurb: "Theoretical kernel/driver CVE reachability only.",
  },
  {
    id: "t1078_004_cloud_accounts_v1",
    label: "T1078.004 Cloud accounts",
    maxMode: "passive_validation",
    tactic: "privilege-escalation",
    blurb: "Inspects over-privileged cloud principals.",
  },
  {
    id: "t1611_escape_to_host_v1",
    label: "T1611 Escape to host",
    maxMode: "passive_validation",
    tactic: "privilege-escalation",
    blurb: "Flags privileged / hostPath containers.",
  },
  {
    id: "t1134_access_token_manipulation_v1",
    label: "T1134 Access-token manipulation",
    maxMode: "theoretical",
    tactic: "privilege-escalation",
    blurb: "Theoretical token-impersonation surface only.",
  },
  {
    id: "t1548_abuse_elevation_control_v1",
    label: "T1548 Abuse elevation control",
    maxMode: "passive_validation",
    tactic: "privilege-escalation",
    blurb: "Inspects sudoers / SUID / UAC misconfigurations.",
  },
  // TA0006 Credential Access (P1-008).
  {
    id: "t1003_os_credential_dumping_v1",
    label: "T1003 OS credential dumping",
    maxMode: "passive_validation",
    tactic: "credential-access",
    blurb: "Audits LSASS / shadow file protections.",
  },
  {
    id: "t1110_brute_force_v1",
    label: "T1110 Brute force",
    maxMode: "passive_validation",
    tactic: "credential-access",
    blurb: "Inspects lockout / MFA enforcement posture.",
  },
  {
    id: "t1056_input_capture_v1",
    label: "T1056 Input capture",
    maxMode: "theoretical",
    tactic: "credential-access",
    blurb: "Theoretical keylogger reachability only.",
  },
  {
    id: "t1212_exploit_for_cred_access_v1",
    label: "T1212 Exploit for cred access",
    maxMode: "theoretical",
    tactic: "credential-access",
    blurb: "Theoretical credential-API CVE reachability only.",
  },
  {
    id: "t1552_unsecured_credentials_v1",
    label: "T1552 Unsecured credentials",
    maxMode: "passive_validation",
    tactic: "credential-access",
    blurb: "Audits cleartext credentials in config / env.",
  },
  // TA0008 Lateral Movement (P1-008).
  {
    id: "t1021_remote_services_v1",
    label: "T1021 Remote services",
    maxMode: "passive_validation",
    tactic: "lateral-movement",
    blurb: "Audits SSH/RDP/WinRM reachability matrix.",
  },
  {
    id: "t1210_exploit_remote_services_v1",
    label: "T1210 Exploit remote services",
    maxMode: "theoretical",
    tactic: "lateral-movement",
    blurb: "Theoretical lateral CVE reachability only.",
  },
  {
    id: "t1534_internal_spearphishing_v1",
    label: "T1534 Internal spearphishing",
    maxMode: "theoretical",
    tactic: "lateral-movement",
    blurb: "Theoretical internal-mail-flow surface only.",
  },
  {
    id: "t1570_lateral_tool_transfer_v1",
    label: "T1570 Lateral tool transfer",
    maxMode: "passive_validation",
    tactic: "lateral-movement",
    blurb: "Inspects open SMB / file-share egress paths.",
  },
  {
    id: "t1080_taint_shared_content_v1",
    label: "T1080 Taint shared content",
    maxMode: "passive_validation",
    tactic: "lateral-movement",
    blurb: "Audits writable shared-content repositories.",
  },
];

const TACTICS: ReadonlyArray<{ value: string; label: string }> = [
  { value: "all", label: "All tactics" },
  { value: "core", label: "Core safe-only" },
  { value: "initial-access", label: "TA0001 Initial Access" },
  { value: "persistence", label: "TA0003 Persistence" },
  { value: "privilege-escalation", label: "TA0004 Privilege Escalation" },
  { value: "credential-access", label: "TA0006 Credential Access" },
  { value: "lateral-movement", label: "TA0008 Lateral Movement" },
];

export interface BasRunHistoryItem {
  simulation_id: string;
  tenant_id: string;
  engagement_id?: string;
  technique_id: string;
  target: string;
  mode: string;
  dry_run: boolean;
  outcome: string;
  evidence_count: number;
  created_at: string;
}

interface BasRunResponse {
  data?: {
    simulation_id?: string;
    outcome?: string;
    evidence_count?: number;
  };
  error?: { code?: string; message?: string; request_id?: string };
}

export function BasClient({
  initial,
  engagements,
  assets,
}: {
  initial: ReadonlyArray<BasRunHistoryItem>;
  engagements: ReadonlyArray<Engagement>;
  assets: ReadonlyArray<Asset>;
}) {
  const toast = useToast();
  const [tacticFilter, setTacticFilter] = React.useState<string>("all");
  const [techniqueId, setTechniqueId] = React.useState(TECHNIQUES[0]?.id ?? "");
  const [target, setTarget] = React.useState("");
  const [mode, setMode] = React.useState<BasMode>("theoretical");
  const [dryRun, setDryRun] = React.useState(false);
  const [engagementId, setEngagementId] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);
  const [runs, setRuns] = React.useState<ReadonlyArray<BasRunHistoryItem>>(initial);

  const filteredTechniques = React.useMemo<ReadonlyArray<TechniqueEntry>>(() => {
    if (tacticFilter === "all") {
      return TECHNIQUES;
    }
    return TECHNIQUES.filter((t) => t.tactic === tacticFilter);
  }, [tacticFilter]);

  // If the current selection falls outside the active tactic filter, snap to
  // the first technique in the filtered list so the dropdown is never out of
  // sync with the visible options.
  React.useEffect(() => {
    if (!filteredTechniques.some((t) => t.id === techniqueId)) {
      const first = filteredTechniques[0]?.id;
      if (first !== undefined) {
        setTechniqueId(first);
      }
    }
  }, [filteredTechniques, techniqueId]);

  // Filter target suggestions: assets of the selected engagement first, then
  // scopes from the selected engagement, then everything else.
  const targetSuggestions = React.useMemo<TargetSuggestion[]>(() => {
    const selected = engagements.find((e) => e.id === engagementId);
    const out: TargetSuggestion[] = [];
    const seen = new Set<string>();

    function push(value: string, label: string) {
      if (value.length === 0 || seen.has(value)) return;
      seen.add(value);
      out.push({ value, label });
    }

    if (selected !== undefined) {
      for (const s of selected.scopes ?? []) {
        push(s, `scope of ${selected.name}`);
      }
    }
    for (const a of assets) {
      if (selected === undefined || a.engagement_id === engagementId) {
        push(a.identifier, `${a.kind} · ${a.engagement_id.slice(0, 8)}…`);
      }
    }
    if (selected === undefined) {
      // also expose the union of all engagement scopes for free-form picking.
      for (const e of engagements) {
        for (const s of e.scopes ?? []) {
          push(s, `scope of ${e.name}`);
        }
      }
    }
    return out;
  }, [engagements, assets, engagementId]);

  const selectedTechnique = TECHNIQUES.find((t) => t.id === techniqueId);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (techniqueId.length === 0) {
      toast.push({ kind: "error", message: "Pick a technique." });
      return;
    }
    if (target.trim().length === 0) {
      toast.push({ kind: "error", message: "Target is required." });
      return;
    }
    setSubmitting(true);
    try {
      const body: Record<string, unknown> = {
        technique_id: techniqueId,
        target: target.trim(),
        mode,
        dry_run: dryRun,
      };
      if (engagementId.length > 0) {
        body.engagement_id = engagementId;
      }
      const res = await fetch("/api/bas/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const parsed: BasRunResponse = await res.json().catch(() => ({}));
      if (!res.ok) {
        const detail = parsed.error?.message ?? `Run failed (${res.status})`;
        toast.push({ kind: "error", message: detail });
        return;
      }
      const outcome = parsed.data?.outcome ?? "simulated";
      const simId = parsed.data?.simulation_id ?? "—";
      const newRow: BasRunHistoryItem = {
        simulation_id: simId,
        tenant_id: "",
        technique_id: techniqueId,
        target: target.trim(),
        mode,
        dry_run: dryRun,
        outcome,
        evidence_count: parsed.data?.evidence_count ?? 0,
        created_at: new Date().toISOString(),
      };
      if (engagementId.length > 0) {
        newRow.engagement_id = engagementId;
      }
      setRuns((current) => [newRow, ...current].slice(0, 200));
      toast.push({ kind: "success", message: `BAS run accepted (${outcome}).` });
    } catch {
      toast.push({ kind: "error", message: "Network error — please retry." });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Crosshair className="h-4 w-4 text-accent" aria-hidden />
            Breach &amp; Attack Simulation
          </CardTitle>
          <CardDescription>
            Trigger a single technique run. Every run is persisted server-side and visible
            in the history table below (newest-first).
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="bas-tactic">Tactic filter</Label>
              <select
                id="bas-tactic"
                value={tacticFilter}
                onChange={(event) => setTacticFilter(event.currentTarget.value)}
                className="h-9 w-full rounded-sx border border-border bg-transparent px-2 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                {TACTICS.map((t) => (
                  <option key={t.value} value={t.value} className="bg-card text-foreground">
                    {t.label}
                  </option>
                ))}
              </select>
              <p className="text-[11px] text-muted-foreground">
                Narrows the technique list to a single ATT&amp;CK tactic.
              </p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="bas-technique">Technique</Label>
              <select
                id="bas-technique"
                value={techniqueId}
                onChange={(event) => setTechniqueId(event.currentTarget.value)}
                className="h-9 w-full rounded-sx border border-border bg-transparent px-2 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                {filteredTechniques.map((t) => (
                  <option key={t.id} value={t.id} className="bg-card text-foreground">
                    {t.label}
                  </option>
                ))}
              </select>
              {selectedTechnique !== undefined ? (
                <p className="text-[11px] text-muted-foreground">
                  <span className="font-mono">{selectedTechnique.id}</span> · max mode{" "}
                  <Badge variant="outline" className="text-[10px]">
                    {selectedTechnique.maxMode.replace(/_/g, " ")}
                  </Badge>
                  <br />
                  {selectedTechnique.blurb}
                </p>
              ) : null}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="bas-target">Target</Label>
              <Input
                id="bas-target"
                value={target}
                list="bas-target-options"
                onChange={(event) => setTarget(event.currentTarget.value)}
                placeholder="select or type asset / scope / FQDN"
                required
              />
              <datalist id="bas-target-options">
                {targetSuggestions.map((s) => (
                  <option key={s.value} value={s.value} label={s.label} />
                ))}
              </datalist>
              {targetSuggestions.length > 0 ? (
                <p className="text-[11px] text-muted-foreground">
                  Start typing to filter {targetSuggestions.length} suggestion
                  {targetSuggestions.length === 1 ? "" : "s"} (scopes + assets).
                </p>
              ) : null}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="bas-engagement">Engagement (optional)</Label>
              <select
                id="bas-engagement"
                value={engagementId}
                onChange={(event) => setEngagementId(event.currentTarget.value)}
                className="h-9 w-full rounded-sx border border-border bg-transparent px-2 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                <option value="" className="bg-card text-foreground">
                  — None —
                </option>
                {engagements.map((e) => (
                  <option key={e.id} value={e.id} className="bg-card text-foreground">
                    {e.name}
                  </option>
                ))}
              </select>
              {engagementId.length > 0 ? (
                <p className="text-[11px] font-mono text-muted-foreground">
                  {engagementId}
                </p>
              ) : null}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="bas-mode">Mode</Label>
              <select
                id="bas-mode"
                value={mode}
                onChange={(event) => setMode(event.currentTarget.value as BasMode)}
                className="h-9 w-full rounded-sx border border-border bg-transparent px-2 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                {MODES.map((m) => (
                  <option key={m} value={m} className="bg-card text-foreground">
                    {m.replace(/_/g, " ")}
                  </option>
                ))}
              </select>
              {mode === "safe_interactive" ? (
                <p className="text-[11px] text-medium">
                  Requires the engagement&apos;s change window + 2 distinct approvers.
                </p>
              ) : null}
            </div>
            <div className="flex items-end gap-2 md:col-span-2">
              <label className="flex items-center gap-2 text-xs text-muted-foreground">
                <input
                  type="checkbox"
                  checked={dryRun}
                  onChange={(event) => setDryRun(event.currentTarget.checked)}
                  className="h-4 w-4 rounded border-border accent-accent"
                />
                <span>Dry run (no-op simulation)</span>
              </label>
            </div>
            <div className="md:col-span-2 flex justify-end">
              <Button type="submit" disabled={submitting}>
                {submitting ? "Running…" : "Run"}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Run history</CardTitle>
          <CardDescription>
            Persisted server-side via <code className="text-foreground">GET /v1/bas/runs</code>.
            Newest first; capped at 200 entries.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Time</TableHead>
                <TableHead>Technique</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Mode</TableHead>
                <TableHead>Outcome</TableHead>
                <TableHead>Simulation ID</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {runs.length === 0 ? (
                <TableRow>
                  <TableCell
                    colSpan={6}
                    className="py-8 text-center text-xs text-muted-foreground"
                  >
                    No runs yet — submit the form above.
                  </TableCell>
                </TableRow>
              ) : (
                runs.map((row) => (
                  <TableRow key={row.simulation_id}>
                    <TableCell className="text-xs font-mono">
                      {row.created_at.slice(11, 19)}
                    </TableCell>
                    <TableCell className="text-xs font-mono">{row.technique_id}</TableCell>
                    <TableCell className="text-xs">{row.target}</TableCell>
                    <TableCell className="text-xs">{row.mode.replace(/_/g, " ")}</TableCell>
                    <TableCell>
                      <OutcomeBadge outcome={row.outcome} />
                    </TableCell>
                    <TableCell className="text-[10px] font-mono text-muted-foreground">
                      {row.simulation_id.slice(0, 8)}…
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

interface TargetSuggestion {
  value: string;
  label: string;
}

function OutcomeBadge({ outcome }: { outcome: string }) {
  if (outcome === "simulated") {
    return <Badge variant="success">{outcome}</Badge>;
  }
  if (outcome === "denied" || outcome === "blocked" || outcome === "killed") {
    return <Badge variant="medium">{outcome}</Badge>;
  }
  return <Badge variant="critical">{outcome}</Badge>;
}
