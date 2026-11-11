/**
 * Shared API types — mirror the sx-api OpenAPI schema as of phase 1.
 *
 * Wider enumerations than the backend currently emits are deliberate:
 * extra states (e.g. `scheduled`, `aborted`) are tolerated so future
 * backend additions don't break the client at compile time. Trim later
 * when the contract is frozen.
 */

export type EngagementStatus =
  | "draft"
  | "scheduled"
  | "active"
  | "paused"
  | "completed"
  | "aborted"
  | "cancelled";

export interface Engagement {
  id: string;
  tenant_id: string;
  name: string;
  description?: string;
  scopes: string[];
  status: EngagementStatus;
  created_at: string;
  updated_at: string;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingStatus =
  | "open"
  | "triaged"
  | "in_progress"
  | "resolved"
  | "false_positive"
  | "accepted"
  | "closed";

export interface Finding {
  id: string;
  tenant_id: string;
  asset_id: string;
  severity: Severity;
  status: FindingStatus;
  title: string;
  description: string;
  cvss?: number;
  first_seen: string;
  last_seen: string;
  cve_id?: string;
}

export interface Asset {
  id: string;
  tenant_id: string;
  engagement_id: string;
  kind: string;
  identifier: string;
  source: string;
  first_seen: string;
  last_seen: string;
}

export interface Page<T> {
  items: T[];
  offset: number;
  limit: number;
}

export interface Control {
  id: string;
  framework: string;
  title: string;
  family: string;
}

export interface FrameworkControls {
  framework: string;
  controls: Control[];
}

export interface TenantMe {
  id: string;
  name: string;
  slug?: string;
  status?: string;
  created_at?: string;
}

export const COMPLIANCE_FRAMEWORKS = [
  "iso27001",
  "soc2",
  "pci_dss",
  "hipaa",
  "nist_800_53",
  "cis_aws",
  "fedramp_moderate",
] as const;

export type ComplianceFramework = (typeof COMPLIANCE_FRAMEWORKS)[number];
