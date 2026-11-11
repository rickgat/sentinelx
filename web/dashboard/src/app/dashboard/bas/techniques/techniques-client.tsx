"use client";

import * as React from "react";
import { ChevronDown, ChevronRight, ExternalLink, Search } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";

/**
 * BAS technique catalogue browser.
 *
 * The catalogue is grouped by ATT&CK tactic (phase). Each phase renders as a
 * collapsible section with a row count. A single search input filters the
 * full table by `technique_id` (case-insensitive prefix or contains) or by
 * `name` (case-insensitive contains); collapsed phases auto-expand when the
 * search matches a row inside them.
 */

export type Intensity =
  | "theoretical"
  | "passive_validation"
  | "safe_interactive"
  | "active_exploit"
  | "red_team";

export interface Technique {
  technique_id: string;
  name: string;
  phase: string;
  required_intensity: Intensity;
  platforms: ReadonlyArray<string>;
}

const PHASE_ORDER: ReadonlyArray<string> = [
  "reconnaissance",
  "resource-development",
  "initial-access",
  "execution",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
  "impact",
];

type PhaseVariant = "info" | "medium" | "high" | "critical" | "low" | "outline";

const PHASE_VARIANT: Record<string, PhaseVariant> = {
  "reconnaissance": "info",
  "resource-development": "info",
  "initial-access": "medium",
  "execution": "medium",
  "persistence": "high",
  "privilege-escalation": "high",
  "defense-evasion": "high",
  "credential-access": "critical",
  "discovery": "low",
  "lateral-movement": "critical",
  "collection": "medium",
  "command-and-control": "critical",
  "exfiltration": "critical",
  "impact": "critical",
};

const INTENSITY_VARIANT: Record<Intensity, PhaseVariant> = {
  theoretical: "info",
  passive_validation: "low",
  safe_interactive: "medium",
  active_exploit: "high",
  red_team: "critical",
};

interface Props {
  techniques: ReadonlyArray<Technique>;
}

export function TechniquesClient({ techniques }: Props) {
  const [query, setQuery] = React.useState<string>("");
  const [tacticFilter, setTacticFilter] = React.useState<string>("all");
  const [collapsed, setCollapsed] = React.useState<ReadonlyArray<string>>([]);

  const trimmed = query.trim().toLowerCase();

  // The catalogue's tactic dropdown is populated from the union of the
  // canonical PHASE_ORDER and any phases present in the supplied catalogue.
  // This keeps the dropdown stable even if a deploy adds a new tactic.
  const tacticOptions = React.useMemo<ReadonlyArray<string>>(() => {
    const present = new Set<string>();
    for (const t of techniques) {
      present.add(t.phase);
    }
    const ordered: string[] = [];
    for (const phase of PHASE_ORDER) {
      if (present.has(phase)) {
        ordered.push(phase);
      }
    }
    const extras: string[] = [];
    for (const phase of present) {
      if (!PHASE_ORDER.includes(phase)) {
        extras.push(phase);
      }
    }
    extras.sort();
    return [...ordered, ...extras];
  }, [techniques]);

  const filtered = React.useMemo<ReadonlyArray<Technique>>(() => {
    return techniques.filter((t) => {
      if (tacticFilter !== "all" && t.phase !== tacticFilter) {
        return false;
      }
      if (trimmed.length === 0) {
        return true;
      }
      return (
        t.technique_id.toLowerCase().includes(trimmed) ||
        t.name.toLowerCase().includes(trimmed)
      );
    });
  }, [techniques, trimmed, tacticFilter]);

  const grouped = React.useMemo<ReadonlyArray<readonly [string, ReadonlyArray<Technique>]>>(() => {
    const byPhase = new Map<string, Technique[]>();
    for (const t of filtered) {
      const list = byPhase.get(t.phase);
      if (list === undefined) {
        byPhase.set(t.phase, [t]);
      } else {
        list.push(t);
      }
    }
    // Stable sort by canonical PHASE_ORDER, then alpha for any unknown phase.
    const knownEntries: Array<readonly [string, ReadonlyArray<Technique>]> = [];
    const unknownEntries: Array<readonly [string, ReadonlyArray<Technique>]> = [];
    for (const phase of PHASE_ORDER) {
      const rows = byPhase.get(phase);
      if (rows !== undefined && rows.length > 0) {
        knownEntries.push([phase, rows] as const);
      }
    }
    for (const [phase, rows] of byPhase.entries()) {
      if (!PHASE_ORDER.includes(phase) && rows.length > 0) {
        unknownEntries.push([phase, rows] as const);
      }
    }
    unknownEntries.sort((a, b) => a[0].localeCompare(b[0]));
    return [...knownEntries, ...unknownEntries];
  }, [filtered]);

  function togglePhase(phase: string) {
    setCollapsed((current) =>
      current.includes(phase)
        ? current.filter((p) => p !== phase)
        : [...current, phase],
    );
  }

  // When the user is actively searching, force every matched phase open so
  // hits aren't hidden under a collapsed header.
  const effectiveCollapsed = trimmed.length === 0 ? collapsed : [];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-2 md:grid-cols-[1fr_220px]">
        <div className="relative">
          <Search
            className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
            aria-hidden
          />
          <Input
            value={query}
            onChange={(event) => setQuery(event.currentTarget.value)}
            placeholder="Search by technique id or name (e.g. T1003 or phishing)"
            className="pl-8"
            aria-label="Search techniques"
          />
        </div>
        <select
          value={tacticFilter}
          onChange={(event) => setTacticFilter(event.currentTarget.value)}
          aria-label="Filter by tactic"
          className="h-9 w-full rounded-sx border border-border bg-transparent px-2 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <option value="all" className="bg-card text-foreground">
            All tactics
          </option>
          {tacticOptions.map((phase) => (
            <option key={phase} value={phase} className="bg-card text-foreground">
              {phase.replace(/-/g, " ")}
            </option>
          ))}
        </select>
      </div>

      <div className="text-xs text-muted-foreground">
        {filtered.length === techniques.length
          ? `${techniques.length} techniques across ${grouped.length} phase${grouped.length === 1 ? "" : "s"}`
          : `${filtered.length} of ${techniques.length} techniques match`}
      </div>

      {grouped.length === 0 ? (
        <div className="rounded-sx border border-border bg-muted/30 px-3 py-8 text-center text-xs text-muted-foreground">
          No techniques match the current search.
        </div>
      ) : (
        <div className="space-y-3">
          {grouped.map(([phase, rows]) => {
            const isCollapsed = effectiveCollapsed.includes(phase);
            const variant = PHASE_VARIANT[phase] ?? "outline";
            return (
              <section
                key={phase}
                className="overflow-hidden rounded-sx border border-border"
                aria-label={`Phase ${phase}`}
              >
                <button
                  type="button"
                  onClick={() => togglePhase(phase)}
                  aria-expanded={!isCollapsed}
                  className={cn(
                    "flex w-full items-center justify-between gap-3 bg-muted/30 px-3 py-2 text-left text-sm transition-colors hover:bg-muted/60",
                  )}
                >
                  <span className="flex items-center gap-2">
                    {isCollapsed ? (
                      <ChevronRight className="h-4 w-4 text-muted-foreground" aria-hidden />
                    ) : (
                      <ChevronDown className="h-4 w-4 text-muted-foreground" aria-hidden />
                    )}
                    <Badge variant={variant}>{phase.replace(/-/g, " ")}</Badge>
                    <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                      {phase}
                    </span>
                  </span>
                  <span className="text-[11px] text-muted-foreground">
                    {rows.length} technique{rows.length === 1 ? "" : "s"}
                  </span>
                </button>
                {isCollapsed ? null : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Technique ID</TableHead>
                        <TableHead>Phase</TableHead>
                        <TableHead>Name</TableHead>
                        <TableHead>Required intensity</TableHead>
                        <TableHead>Platforms</TableHead>
                        <TableHead className="text-right">MITRE</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {rows.map((row) => (
                        <TableRow key={row.technique_id}>
                          <TableCell className="font-mono text-xs">{row.technique_id}</TableCell>
                          <TableCell className="text-xs uppercase tracking-wide text-muted-foreground">
                            {row.phase.replace(/-/g, " ")}
                          </TableCell>
                          <TableCell>{row.name}</TableCell>
                          <TableCell>
                            <Badge variant={INTENSITY_VARIANT[row.required_intensity]}>
                              {row.required_intensity.replace(/_/g, " ")}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <div className="flex flex-wrap gap-1">
                              {row.platforms.map((p) => (
                                <span
                                  key={`${row.technique_id}-${p}`}
                                  className="rounded-sx border border-border bg-transparent px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground"
                                >
                                  {p}
                                </span>
                              ))}
                            </div>
                          </TableCell>
                          <TableCell className="text-right">
                            <a
                              href={mitreUrl(row.technique_id)}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center gap-1 text-xs text-accent hover:underline"
                            >
                              View on MITRE
                              <ExternalLink className="h-3 w-3" aria-hidden />
                            </a>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </section>
            );
          })}
        </div>
      )}
    </div>
  );
}

function mitreUrl(techniqueId: string): string {
  const trimmed = techniqueId.trim().toUpperCase();
  if (!/^T\d{4}(\.\d{3})?$/.test(trimmed)) {
    return `https://attack.mitre.org/techniques/${trimmed}/`;
  }
  const [parent, sub] = trimmed.split(".");
  if (sub === undefined) {
    return `https://attack.mitre.org/techniques/${parent}/`;
  }
  return `https://attack.mitre.org/techniques/${parent}/${sub}/`;
}
