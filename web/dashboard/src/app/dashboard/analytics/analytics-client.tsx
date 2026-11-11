"use client";

import * as React from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { BasRunHistoryItem } from "../bas/bas-client";
import type { ScanRecord } from "../scans/scans-client";

interface Bucket {
  key: string;
  count: number;
}

interface TimelinePoint {
  date: string;
  count: number;
}

interface TopTarget {
  target: string;
  findings_count: number;
}

interface Props {
  findingsBySeverity: Bucket[];
  findingsByStatus: Bucket[];
  findingsTimeline: TimelinePoint[];
  engagementsByStatus: Bucket[];
  assetsByKind: Bucket[];
  basByOutcome: Bucket[];
  basByTechnique: Bucket[];
  scansTimeline: TimelinePoint[];
  recentScans: ScanRecord[];
  recentBasRuns: BasRunHistoryItem[];
  topTargets: TopTarget[];
}

// Tailwind tokens resolved to CSS values that recharts can consume.
const COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#6b7280",
  open: "#ef4444",
  triaged: "#f59e0b",
  in_progress: "#3b82f6",
  resolved: "#10b981",
  closed: "#10b981",
  accepted: "#8b5cf6",
  false_positive: "#6b7280",
  draft: "#6b7280",
  scheduled: "#3b82f6",
  active: "#10b981",
  paused: "#f59e0b",
  completed: "#22d3ee",
  aborted: "#ef4444",
  cancelled: "#6b7280",
  simulated: "#10b981",
  denied: "#f59e0b",
  blocked: "#ef4444",
  killed: "#ef4444",
} as const;

function colorFor(key: string): string {
  return (COLORS as Record<string, string>)[key] ?? "#3b82f6";
}

const PIE_PALETTE = [
  "#3b82f6", "#10b981", "#f59e0b", "#8b5cf6", "#ef4444",
  "#22d3ee", "#ec4899", "#84cc16", "#eab308", "#6b7280",
];

export function AnalyticsClient({
  findingsBySeverity,
  findingsByStatus,
  findingsTimeline,
  basByOutcome,
  basByTechnique,
  scansTimeline,
  recentScans,
  recentBasRuns,
  topTargets,
}: Props) {
  return (
    <div className="space-y-6">
      {/* Severity + Status side-by-side */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <ChartCard
          title="Findings by severity"
          description="Higher bars = more findings at that severity."
        >
          {findingsBySeverity.length === 0 ? (
            <Empty>No findings recorded.</Empty>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={findingsBySeverity}>
                <CartesianGrid stroke="#27272a" strokeDasharray="3 3" />
                <XAxis dataKey="key" stroke="#a1a1aa" fontSize={11} />
                <YAxis allowDecimals={false} stroke="#a1a1aa" fontSize={11} />
                <Tooltip
                  contentStyle={{
                    background: "#18181b",
                    border: "1px solid #27272a",
                    fontSize: 12,
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {findingsBySeverity.map((b) => (
                    <Cell key={b.key} fill={colorFor(b.key)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

        <ChartCard
          title="Findings by status"
          description="Triage funnel — most actionable status is 'open'."
        >
          {findingsByStatus.length === 0 ? (
            <Empty>No findings recorded.</Empty>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={findingsByStatus}
                  dataKey="count"
                  nameKey="key"
                  innerRadius={45}
                  outerRadius={80}
                  paddingAngle={2}
                >
                  {findingsByStatus.map((b, i) => (
                    <Cell
                      key={b.key}
                      fill={
                        colorFor(b.key) === "#3b82f6"
                          ? (PIE_PALETTE[i % PIE_PALETTE.length] ?? "#3b82f6")
                          : colorFor(b.key)
                      }
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "#18181b",
                    border: "1px solid #27272a",
                    fontSize: 12,
                  }}
                />
                <Legend
                  wrapperStyle={{ fontSize: 11 }}
                  formatter={(value: string) => value.replace(/_/g, " ")}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </ChartCard>
      </div>

      {/* Timeline charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <ChartCard
          title="Findings — last 14 days"
          description="Last-seen timeline. Spikes = new vulnerabilities surfacing."
        >
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={findingsTimeline}>
              <CartesianGrid stroke="#27272a" strokeDasharray="3 3" />
              <XAxis dataKey="date" stroke="#a1a1aa" fontSize={10} />
              <YAxis allowDecimals={false} stroke="#a1a1aa" fontSize={10} />
              <Tooltip
                contentStyle={{
                  background: "#18181b",
                  border: "1px solid #27272a",
                  fontSize: 12,
                }}
              />
              <Area
                type="monotone"
                dataKey="count"
                stroke="#ef4444"
                fill="#ef4444"
                fillOpacity={0.2}
              />
            </AreaChart>
          </ResponsiveContainer>
        </ChartCard>

        <ChartCard
          title="Scans — last 14 days"
          description="HTTP scans executed per day."
        >
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={scansTimeline}>
              <CartesianGrid stroke="#27272a" strokeDasharray="3 3" />
              <XAxis dataKey="date" stroke="#a1a1aa" fontSize={10} />
              <YAxis allowDecimals={false} stroke="#a1a1aa" fontSize={10} />
              <Tooltip
                contentStyle={{
                  background: "#18181b",
                  border: "1px solid #27272a",
                  fontSize: 12,
                }}
              />
              <Area
                type="monotone"
                dataKey="count"
                stroke="#3b82f6"
                fill="#3b82f6"
                fillOpacity={0.2}
              />
            </AreaChart>
          </ResponsiveContainer>
        </ChartCard>
      </div>

      {/* BAS analytics */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <ChartCard
          title="BAS outcomes"
          description="Distribution of simulation outcomes."
        >
          {basByOutcome.length === 0 ? (
            <Empty>No BAS runs yet.</Empty>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={basByOutcome} layout="vertical">
                <CartesianGrid stroke="#27272a" strokeDasharray="3 3" />
                <XAxis type="number" stroke="#a1a1aa" fontSize={11} allowDecimals={false} />
                <YAxis dataKey="key" type="category" width={90} stroke="#a1a1aa" fontSize={11} />
                <Tooltip
                  contentStyle={{
                    background: "#18181b",
                    border: "1px solid #27272a",
                    fontSize: 12,
                  }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {basByOutcome.map((b) => (
                    <Cell key={b.key} fill={colorFor(b.key)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>

        <ChartCard
          title="BAS by technique"
          description="Which adversary techniques get rehearsed most."
        >
          {basByTechnique.length === 0 ? (
            <Empty>No BAS runs yet.</Empty>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={basByTechnique.slice(0, 6)} layout="vertical">
                <CartesianGrid stroke="#27272a" strokeDasharray="3 3" />
                <XAxis type="number" stroke="#a1a1aa" fontSize={11} allowDecimals={false} />
                <YAxis dataKey="key" type="category" width={150} stroke="#a1a1aa" fontSize={10} />
                <Tooltip
                  contentStyle={{
                    background: "#18181b",
                    border: "1px solid #27272a",
                    fontSize: 12,
                  }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]} fill="#22d3ee" />
              </BarChart>
            </ResponsiveContainer>
          )}
        </ChartCard>
      </div>

      {/* Top targets */}
      {topTargets.length > 0 ? (
        <ChartCard
          title="Top scanned targets"
          description="Sum of findings across all scans for the same target."
        >
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Target</TableHead>
                <TableHead className="text-right">Findings</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {topTargets.map((t) => (
                <TableRow key={t.target}>
                  <TableCell className="text-xs">{t.target}</TableCell>
                  <TableCell className="text-right text-xs tabular-nums">
                    {t.findings_count}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </ChartCard>
      ) : null}

      {/* Recent activity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <ChartCard title="Recent scans" description="Last 10 scans, newest first.">
          {recentScans.length === 0 ? (
            <Empty>No scans recorded.</Empty>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead className="text-right">Findings</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recentScans.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell className="text-[11px] font-mono">
                      {s.finished_at.slice(11, 19)}
                    </TableCell>
                    <TableCell className="text-xs">{s.target}</TableCell>
                    <TableCell className="text-right text-xs tabular-nums">
                      {s.findings.length}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </ChartCard>

        <ChartCard title="Recent BAS runs" description="Last 10 simulation submissions.">
          {recentBasRuns.length === 0 ? (
            <Empty>No BAS runs yet.</Empty>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>Technique</TableHead>
                  <TableHead>Outcome</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recentBasRuns.map((r) => (
                  <TableRow key={r.simulation_id}>
                    <TableCell className="text-[11px] font-mono">
                      {r.created_at.slice(11, 19)}
                    </TableCell>
                    <TableCell className="text-[11px] font-mono">
                      {r.technique_id}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          r.outcome === "simulated"
                            ? "success"
                            : r.outcome === "denied" || r.outcome === "blocked"
                              ? "medium"
                              : "outline"
                        }
                      >
                        {r.outcome}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </ChartCard>
      </div>
    </div>
  );
}

function ChartCard({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm">{title}</CardTitle>
        {description !== undefined ? (
          <CardDescription>{description}</CardDescription>
        ) : null}
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-center h-32 text-xs text-muted-foreground">
      {children}
    </div>
  );
}
