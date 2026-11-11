import type { LucideIcon } from "lucide-react";
import { ArrowDownRight, ArrowUpRight, Minus } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

type Tone = "default" | "critical" | "high" | "success" | "info";

/**
 * `direction` = which way the number moved.
 * `intent` = whether that movement is "good news" or "bad news" for this KPI.
 *
 * For a risk metric like "Critical findings", going up is BAD → `intent: "bad"`,
 * so we colour the delta rose (red). For "Posture score", up is GOOD → `intent: "good"`,
 * green. Decoupling direction from intent lets each KPI carry its own semantic.
 */
export interface KpiTrend {
  values: ReadonlyArray<number>;
  previous?: number | null | undefined;
  invertGoodness?: boolean;
}

interface KpiCardProps {
  label: string;
  value: string | number;
  helper?: string;
  icon: LucideIcon;
  tone?: Tone;
  trend?: KpiTrend | undefined;
}

const toneMap: Record<Tone, string> = {
  default: "text-foreground",
  critical: "text-critical",
  high: "text-high",
  success: "text-success",
  info: "text-info",
};

const sparkStrokeMap: Record<Tone, string> = {
  default: "stroke-muted-foreground",
  critical: "stroke-critical",
  high: "stroke-high",
  success: "stroke-success",
  info: "stroke-info",
};

function Sparkline({ values, className }: { values: ReadonlyArray<number>; className?: string }) {
  if (values.length < 2) return null;
  const w = 96;
  const h = 28;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const step = w / (values.length - 1);
  const points = values
    .map((v, i) => {
      const x = i * step;
      const y = h - ((v - min) / range) * h;
      return `${x.toFixed(2)},${y.toFixed(2)}`;
    })
    .join(" ");
  return (
    <svg
      width={w}
      height={h}
      viewBox={`0 0 ${w} ${h}`}
      className={cn("overflow-visible", className)}
      aria-hidden
    >
      <polyline
        fill="none"
        strokeWidth={1.5}
        strokeLinejoin="round"
        strokeLinecap="round"
        points={points}
      />
    </svg>
  );
}

interface DeltaBadgeProps {
  current: number;
  previous: number;
  invertGoodness: boolean;
}

function DeltaBadge({ current, previous, invertGoodness }: DeltaBadgeProps) {
  const diff = current - previous;
  const pct = previous === 0 ? null : (diff / Math.abs(previous)) * 100;
  const direction: "up" | "down" | "flat" = diff > 0 ? "up" : diff < 0 ? "down" : "flat";

  // "good" means the movement is favourable for this KPI.
  const isGood =
    direction === "flat"
      ? true
      : invertGoodness
        ? direction === "down"
        : direction === "up";

  const Icon = direction === "up" ? ArrowUpRight : direction === "down" ? ArrowDownRight : Minus;
  const colour = direction === "flat"
    ? "text-muted-foreground"
    : isGood ? "text-success" : "text-critical";
  const arrow = direction === "flat" ? "0" : `${Math.abs(diff)}`;
  const pctLabel = pct === null ? "" : ` (${pct >= 0 ? "+" : ""}${pct.toFixed(0)}%)`;

  return (
    <span
      className={cn("inline-flex items-center gap-0.5 font-mono text-[11px] tabular-nums", colour)}
      title={`Previous period: ${previous}`}
    >
      <Icon className="h-3 w-3" aria-hidden />
      {arrow}
      {pctLabel}
    </span>
  );
}

export function KpiCard({ label, value, helper, icon: Icon, tone = "default", trend }: KpiCardProps) {
  const hasTrend = trend !== undefined && trend.values.length > 1;
  const hasDelta =
    trend !== undefined &&
    trend.previous !== undefined &&
    trend.previous !== null &&
    typeof value === "number";
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-xs uppercase tracking-wide text-muted-foreground">
          {label}
        </CardTitle>
        <Icon className={cn("h-4 w-4", toneMap[tone])} aria-hidden />
      </CardHeader>
      <CardContent>
        <div className="flex items-end justify-between gap-3">
          <div className="min-w-0">
            <div className={cn("text-3xl font-semibold tracking-tight font-mono tabular-nums", toneMap[tone])}>
              {value}
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1">
              {hasDelta ? (
                <DeltaBadge
                  current={value as number}
                  previous={trend.previous as number}
                  invertGoodness={trend?.invertGoodness ?? false}
                />
              ) : null}
              {helper !== undefined ? (
                <CardDescription className="text-[11px]">{helper}</CardDescription>
              ) : null}
            </div>
          </div>
          {hasTrend ? (
            <Sparkline values={trend.values} className={sparkStrokeMap[tone]} />
          ) : null}
        </div>
      </CardContent>
    </Card>
  );
}
