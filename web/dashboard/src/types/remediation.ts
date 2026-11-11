/**
 * Shared types for the P1-011 remediation outcomes surface.
 *
 * Mirrors the JSON wire schema produced by sx-api:
 *   GET /v1/remediation/outcomes/metrics
 *   GET /v1/remediation/outcomes/regressions
 */

export interface MttrBucket {
  severity: string;
  sample_size: number;
  mttr_seconds: number;
}

export interface RegressingTechnique {
  check_id: string;
  regression_count: number;
  closure_count: number;
}

export interface RemediationMetrics {
  tenant_id: string;
  window_seconds: number;
  mttr_by_severity: MttrBucket[];
  regression_rate: number;
  top_regressing: RegressingTechnique[];
  closure_count: number;
  regression_count: number;
}

export interface RegressionEvent {
  id: string;
  tenant_id: string;
  asset_id: string;
  check_id: string;
  prior_outcome_id: string;
  new_finding_id: string;
  detected_at: string;
  gap_seconds: number;
}

export interface RegressionList {
  items: RegressionEvent[];
}
