"use client";

import * as React from "react";
import { Area, AreaChart, CartesianGrid, Tooltip, XAxis, YAxis } from "recharts";

interface TrendPoint {
  day: string;
  score: number;
}

/**
 * Deterministic seed data — 7 days of posture score in [0, 100].
 * No randomness so SSR + CSR match without hydration warnings.
 */
const SEED_DATA: ReadonlyArray<TrendPoint> = [
  { day: "Mon", score: 78 },
  { day: "Tue", score: 80 },
  { day: "Wed", score: 76 },
  { day: "Thu", score: 82 },
  { day: "Fri", score: 85 },
  { day: "Sat", score: 84 },
  { day: "Sun", score: 88 },
];

const CHART_HEIGHT = 256;
const DEFAULT_WIDTH = 800;

export function PostureTrend() {
  const containerRef = React.useRef<HTMLDivElement | null>(null);
  const [width, setWidth] = React.useState<number>(DEFAULT_WIDTH);

  React.useEffect(() => {
    const el = containerRef.current;
    if (el === null) return;
    const measure = () => {
      const w = el.clientWidth;
      if (w > 0) setWidth(w);
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  return (
    <div ref={containerRef} className="w-full" style={{ height: CHART_HEIGHT }}>
      <AreaChart
        width={width}
        height={CHART_HEIGHT}
        data={[...SEED_DATA]}
        margin={{ top: 12, right: 12, left: 0, bottom: 0 }}
      >
          <defs>
            <linearGradient id="posture-grad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="var(--color-accent)" stopOpacity={0.6} />
              <stop offset="95%" stopColor="var(--color-accent)" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke="var(--color-border)" strokeDasharray="3 3" />
          <XAxis
            dataKey="day"
            stroke="var(--color-muted-foreground)"
            fontSize={12}
            tickLine={false}
            axisLine={false}
          />
          <YAxis
            domain={[0, 100]}
            stroke="var(--color-muted-foreground)"
            fontSize={12}
            tickLine={false}
            axisLine={false}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: "var(--color-card)",
              border: "1px solid var(--color-border)",
              borderRadius: "0.5rem",
              fontSize: "0.75rem",
            }}
            labelStyle={{ color: "var(--color-muted-foreground)" }}
          />
          <Area
            type="monotone"
            dataKey="score"
            stroke="var(--color-accent)"
            strokeWidth={2}
            fill="url(#posture-grad)"
          />
      </AreaChart>
    </div>
  );
}
