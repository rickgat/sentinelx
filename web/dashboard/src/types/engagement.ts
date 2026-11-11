export type EngagementStatus =
  | "draft"
  | "scheduled"
  | "active"
  | "paused"
  | "completed"
  | "cancelled";

export interface Engagement {
  id: string;
  tenant_id: string;
  name: string;
  status: EngagementStatus;
  window_start: string;
  window_end: string;
  scope_count: number;
  created_at: string;
}
