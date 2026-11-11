export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingStatus =
  | "open"
  | "triaged"
  | "in_progress"
  | "resolved"
  | "false_positive"
  | "accepted";

export interface Finding {
  id: string;
  tenant_id: string;
  engagement_id: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  asset: string;
  discovered_at: string;
}
