"use client";

import * as React from "react";
import { Brain } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { cn } from "@/lib/utils";

/**
 * Inline "AI Risk Prediction" card.
 *
 * Mounted under an expanded finding row on the findings page. Fetches the
 * server-side proxy at `/api/predictive/<finding_id>`, which in turn calls
 * `POST /v1/ml/predict/finding` against sx-api. The component renders a
 * probability bar with a red-yellow-green gradient, the `risk_band` badge,
 * and the model's self-confidence as a percentage.
 */

type RiskBand = "low" | "medium" | "high" | "critical";

interface PredictResponse {
  probability: number;
  confidence: number;
  risk_band: string;
}

interface Envelope {
  data?: PredictResponse;
  error?: { code?: string; message?: string };
}

export interface PredictivePanelProps {
  finding_id: string;
}

const BAND_VARIANT: Record<RiskBand, "low" | "medium" | "high" | "critical"> = {
  low: "low",
  medium: "medium",
  high: "high",
  critical: "critical",
};

function normaliseBand(raw: string): RiskBand {
  if (raw === "low" || raw === "medium" || raw === "high" || raw === "critical") {
    return raw;
  }
  return "low";
}

function clamp01(n: number): number {
  if (!Number.isFinite(n)) {
    return 0;
  }
  if (n < 0) {
    return 0;
  }
  if (n > 1) {
    return 1;
  }
  return n;
}

export function PredictivePanel({ finding_id }: PredictivePanelProps) {
  const [state, setState] = React.useState<
    | { kind: "loading" }
    | { kind: "ready"; data: PredictResponse }
    | { kind: "error"; message: string }
  >({ kind: "loading" });

  React.useEffect(() => {
    const controller = new AbortController();
    async function load(): Promise<void> {
      try {
        const res = await fetch(
          `/api/predictive/${encodeURIComponent(finding_id)}`,
          { cache: "no-store", signal: controller.signal },
        );
        const parsed = (await res.json().catch(() => ({}))) as Envelope;
        if (controller.signal.aborted) {
          return;
        }
        if (res.ok && parsed.data !== undefined) {
          setState({ kind: "ready", data: parsed.data });
        } else {
          setState({
            kind: "error",
            message: parsed.error?.message ?? `Request failed (${res.status})`,
          });
        }
      } catch (err) {
        if (controller.signal.aborted || (err as Error).name === "AbortError") {
          return;
        }
        setState({ kind: "error", message: "Network error" });
      }
    }
    setState({ kind: "loading" });
    void load();
    return () => {
      controller.abort();
    };
  }, [finding_id]);

  return (
    <Card className="border-accent/40 bg-accent/5">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-xs">
          <Brain className="h-4 w-4 text-accent" aria-hidden />
          AI Risk Prediction
        </CardTitle>
        <CardDescription>
          GBDT risk model — probability of materialisation within 30 days.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {state.kind === "loading" ? (
          <p className="text-xs text-muted-foreground">Scoring finding…</p>
        ) : null}

        {state.kind === "error" ? (
          <div
            role="alert"
            className="rounded-sx border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical"
          >
            Prediction unavailable: {state.message}
          </div>
        ) : null}

        {state.kind === "ready" ? (
          <PredictionContent data={state.data} />
        ) : null}
      </CardContent>
    </Card>
  );
}

function PredictionContent({ data }: { data: PredictResponse }) {
  const probability = clamp01(data.probability);
  const confidence = clamp01(data.confidence);
  const band = normaliseBand(data.risk_band);
  const probabilityPct = Math.round(probability * 100);
  const confidencePct = Math.round(confidence * 100);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
            Risk band
          </span>
          <Badge variant={BAND_VARIANT[band]}>{band}</Badge>
        </div>
        <span className="text-xs font-mono text-foreground">
          {probabilityPct}%
        </span>
      </div>

      <div>
        <div
          className="relative h-2 w-full overflow-hidden rounded-full bg-muted"
          role="progressbar"
          aria-valuenow={probabilityPct}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label="Risk probability"
        >
          <div
            className="absolute inset-y-0 left-0 bg-gradient-to-r from-green-500 via-yellow-500 to-red-500"
            style={{ width: "100%" }}
          />
          <div
            className={cn(
              "absolute inset-y-0 right-0 bg-card",
              probabilityPct >= 100 ? "hidden" : undefined,
            )}
            style={{ width: `${100 - probabilityPct}%` }}
          />
        </div>
        <div className="mt-1 flex justify-between text-[10px] uppercase tracking-wide text-muted-foreground">
          <span>0%</span>
          <span>50%</span>
          <span>100%</span>
        </div>
      </div>

      <div className="flex items-center justify-between text-xs">
        <span className="text-muted-foreground">Model confidence</span>
        <span className="font-mono text-foreground">{confidencePct}%</span>
      </div>
    </div>
  );
}
