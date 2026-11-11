"use client";

import * as React from "react";
import { ChevronRight, Crosshair, ExternalLink } from "lucide-react";

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
import type { Engagement } from "@/lib/types";

/**
 * AI Red Team chain composer.
 *
 * Submits the selected engagement plus a max-steps cap (1..=14, default 8)
 * to the dashboard proxy at `/api/redteam/chain` and renders the returned
 * chain as a horizontal MITRE ATT&CK kill-chain. Each step is a card
 * containing its phase, technique id, confidence, and a deep link to the
 * MITRE ATT&CK technique page; cards are connected by chevron arrows.
 *
 * The chain payload is normalised tolerantly so the renderer survives
 * minor backend churn (extra fields, missing optional fields).
 */

const MIN_STEPS = 1;
const MAX_STEPS = 14;
const DEFAULT_STEPS = 8;

const KILL_CHAIN_PHASES: ReadonlyArray<string> = [
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

interface ChainStep {
  phase: string;
  technique_id: string;
  technique_name: string;
  confidence: number;
  rationale: string;
}

interface ChainPayload {
  steps: ReadonlyArray<ChainStep>;
  chain_score: number;
  explanation: string;
}

interface ApiErrorEnvelope {
  code?: string;
  message?: string;
  request_id?: string;
}

interface Props {
  engagements: ReadonlyArray<Engagement>;
  apiAvailable: boolean;
}

export function RedTeamClient({ engagements, apiAvailable }: Props) {
  const [selected, setSelected] = React.useState<string>("");
  const [maxSteps, setMaxSteps] = React.useState<number>(DEFAULT_STEPS);
  const [maxStepsText, setMaxStepsText] = React.useState<string>(String(DEFAULT_STEPS));
  const [chain, setChain] = React.useState<ChainPayload | null>(null);
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState<ApiErrorEnvelope | null>(null);

  function clampMaxSteps(raw: string): number {
    const parsed = Number.parseInt(raw, 10);
    if (Number.isNaN(parsed)) {
      return DEFAULT_STEPS;
    }
    if (parsed < MIN_STEPS) {
      return MIN_STEPS;
    }
    if (parsed > MAX_STEPS) {
      return MAX_STEPS;
    }
    return parsed;
  }

  async function compose(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (selected.length === 0) {
      setError({ message: "Select an engagement first." });
      return;
    }
    const clamped = clampMaxSteps(maxStepsText);
    setMaxSteps(clamped);
    setMaxStepsText(String(clamped));
    setSubmitting(true);
    setError(null);
    try {
      const res = await fetch("/api/redteam/chain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ engagement_id: selected, max_steps: clamped }),
      });
      const parsed = (await res.json().catch(() => ({}))) as {
        data?: unknown;
        error?: ApiErrorEnvelope;
      };
      if (!res.ok) {
        setError(parsed.error ?? { message: `Compose failed (${res.status})` });
        setChain(null);
        return;
      }
      setChain(normaliseChain(parsed.data));
    } catch {
      setError({ message: "Network error — please retry." });
      setChain(null);
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
            AI Red Team chain
          </CardTitle>
          <CardDescription>
            Compose a kill-chain of MITRE ATT&amp;CK techniques for an engagement.
            The chain is ordered along the standard reconnaissance → impact axis.
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
          <form onSubmit={compose} className="grid grid-cols-1 gap-3 md:grid-cols-3">
            <div className="space-y-1.5 md:col-span-2">
              <Label htmlFor="redteam-engagement">Engagement</Label>
              <select
                id="redteam-engagement"
                value={selected}
                onChange={(event) => setSelected(event.currentTarget.value)}
                className="h-9 w-full rounded-sx border border-border bg-transparent px-2 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                <option value="" className="bg-card text-foreground">
                  — Select an engagement —
                </option>
                {engagements.map((e) => (
                  <option key={e.id} value={e.id} className="bg-card text-foreground">
                    {e.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="redteam-max-steps">Max steps (1–{MAX_STEPS})</Label>
              <Input
                id="redteam-max-steps"
                type="number"
                inputMode="numeric"
                min={MIN_STEPS}
                max={MAX_STEPS}
                value={maxStepsText}
                onChange={(event) => setMaxStepsText(event.currentTarget.value)}
                onBlur={() => {
                  const clamped = clampMaxSteps(maxStepsText);
                  setMaxSteps(clamped);
                  setMaxStepsText(String(clamped));
                }}
              />
            </div>
            <div className="md:col-span-3 flex justify-end">
              <Button type="submit" disabled={submitting || selected.length === 0}>
                {submitting ? "Composing…" : "Compose"}
              </Button>
            </div>
          </form>

          {error !== null ? (
            <div
              role="alert"
              className="mt-4 rounded-sx border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical"
            >
              <div>{error.message ?? "Chain request failed."}</div>
              {typeof error.request_id === "string" && error.request_id.length > 0 ? (
                <div className="mt-0.5 text-[10px] opacity-80">
                  request id: <code>{error.request_id}</code>
                </div>
              ) : null}
            </div>
          ) : null}
        </CardContent>
      </Card>

      {chain === null ? (
        <Card>
          <CardContent className="py-10 text-center text-xs text-muted-foreground">
            {submitting
              ? "Composing chain…"
              : "Select an engagement and click Compose to build a kill-chain."}
            <div className="mt-1 text-[10px] text-muted-foreground/70">
              Max steps will be clamped to {MIN_STEPS}–{MAX_STEPS} (default {DEFAULT_STEPS}).
            </div>
            <div className="sr-only">Current cap: {maxSteps}</div>
          </CardContent>
        </Card>
      ) : (
        <ChainView chain={chain} />
      )}
    </div>
  );
}

function ChainView({ chain }: { chain: ChainPayload }) {
  if (chain.steps.length === 0) {
    return (
      <Card>
        <CardContent className="py-10 text-center text-xs text-muted-foreground">
          No steps in the composed chain.
        </CardContent>
      </Card>
    );
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>Kill-chain ({chain.steps.length} steps)</CardTitle>
        <CardDescription>
          Each card is one MITRE ATT&amp;CK technique. Scroll horizontally if the chain overflows.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="w-full overflow-x-auto pb-2">
          <ol className="flex min-w-max items-stretch gap-2">
            {chain.steps.map((step, idx) => (
              <li key={`${step.technique_id}-${idx}`} className="flex items-stretch gap-2">
                <StepCard step={step} index={idx} />
                {idx < chain.steps.length - 1 ? (
                  <div className="flex items-center text-muted-foreground" aria-hidden>
                    <ChevronRight className="h-5 w-5" />
                  </div>
                ) : null}
              </li>
            ))}
          </ol>
        </div>
        <ChainScoreSummary
          score={chain.chain_score}
          explanation={chain.explanation}
          stepCount={chain.steps.length}
        />
      </CardContent>
    </Card>
  );
}

function StepCard({ step, index }: { step: ChainStep; index: number }) {
  const variant = PHASE_VARIANT[step.phase] ?? "outline";
  const confidencePct = Math.round(Math.max(0, Math.min(1, step.confidence)) * 100);
  const url = mitreUrl(step.technique_id);
  return (
    <div className="flex w-56 flex-col gap-2 rounded-sx border border-border bg-card p-3 shadow-sm">
      <div className="flex items-center justify-between gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
          Step {index + 1}
        </span>
        <Badge variant={variant} title={step.phase}>
          {step.phase.replace(/-/g, " ")}
        </Badge>
      </div>
      <div className="space-y-0.5">
        <div className="font-mono text-sm font-semibold text-foreground">
          {step.technique_id}
        </div>
        <div className="line-clamp-2 text-xs text-muted-foreground">
          {step.technique_name}
        </div>
      </div>
      <div>
        <div className="mb-1 flex items-center justify-between text-[10px] text-muted-foreground">
          <span>Confidence</span>
          <span className="font-mono">{confidencePct}%</span>
        </div>
        <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
          <div
            className="h-full rounded-full bg-accent"
            style={{ width: `${confidencePct}%` }}
          />
        </div>
      </div>
      {step.rationale.length > 0 ? (
        <p className="line-clamp-3 text-[11px] leading-snug text-muted-foreground">
          {step.rationale}
        </p>
      ) : null}
      {url !== null ? (
        <a
          href={url}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-auto inline-flex items-center gap-1 text-[11px] text-accent hover:underline"
        >
          MITRE ATT&amp;CK
          <ExternalLink className="h-3 w-3" aria-hidden />
        </a>
      ) : null}
    </div>
  );
}

function ChainScoreSummary({
  score,
  explanation,
  stepCount,
}: {
  score: number;
  explanation: string;
  stepCount: number;
}) {
  const pct = Math.round(Math.max(0, Math.min(1, score)) * 100);
  const variant: PhaseVariant =
    pct >= 80 ? "critical" : pct >= 60 ? "high" : pct >= 40 ? "medium" : "low";
  return (
    <div className="rounded-sx border border-border bg-background/40 p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-sm font-semibold">Chain score</span>
          <Badge variant={variant}>{pct}%</Badge>
        </div>
        <span className="text-[11px] text-muted-foreground">
          {stepCount} steps composed
        </span>
      </div>
      <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-muted">
        <div className="h-full rounded-full bg-accent" style={{ width: `${pct}%` }} />
      </div>
      {explanation.length > 0 ? (
        <p className="mt-3 text-xs text-muted-foreground">{explanation}</p>
      ) : null}
    </div>
  );
}

function mitreUrl(techniqueId: string): string | null {
  const trimmed = techniqueId.trim().toUpperCase();
  if (!/^T\d{4}(\.\d{3})?$/.test(trimmed)) {
    return null;
  }
  const [parent, sub] = trimmed.split(".");
  if (sub === undefined) {
    return `https://attack.mitre.org/techniques/${parent}/`;
  }
  return `https://attack.mitre.org/techniques/${parent}/${sub}/`;
}

function isKillChainPhase(value: unknown): value is string {
  return typeof value === "string" && KILL_CHAIN_PHASES.includes(value);
}

/**
 * Coerce the backend chain payload into a renderable shape.
 *
 * Accepted shapes:
 *   - `{ steps: [...], chain_score, explanation }`
 *   - `{ chain: { steps, ... } }`
 *
 * Unknown phases fall back to "execution"; missing confidences default to
 * 0.5; missing scores default to 0.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function normaliseChain(input: any): ChainPayload {
  if (input === null || typeof input !== "object") {
    return { steps: [], chain_score: 0, explanation: "" };
  }
  // Allow a `{ chain: { ... } }` envelope.
  const root = typeof input.chain === "object" && input.chain !== null ? input.chain : input;
  const stepsRaw = Array.isArray(root.steps) ? root.steps : [];
  const steps: ChainStep[] = [];
  for (const raw of stepsRaw) {
    if (raw === null || typeof raw !== "object") {
      continue;
    }
    const technique_id =
      typeof raw.technique_id === "string" ? raw.technique_id : "";
    if (technique_id.length === 0) {
      continue;
    }
    const phase = isKillChainPhase(raw.phase) ? raw.phase : "execution";
    const technique_name =
      typeof raw.technique_name === "string" ? raw.technique_name : technique_id;
    const confidence =
      typeof raw.confidence === "number" && Number.isFinite(raw.confidence)
        ? raw.confidence
        : 0.5;
    const rationale = typeof raw.rationale === "string" ? raw.rationale : "";
    steps.push({ phase, technique_id, technique_name, confidence, rationale });
  }
  const chain_score =
    typeof root.chain_score === "number" && Number.isFinite(root.chain_score)
      ? root.chain_score
      : 0;
  const explanation = typeof root.explanation === "string" ? root.explanation : "";
  return { steps, chain_score, explanation };
}
