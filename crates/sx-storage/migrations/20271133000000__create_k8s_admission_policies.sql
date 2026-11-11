-- Kubernetes admission rule-pack policies (HIGH-009 durability + admin).
--
-- Persists the per-tenant admission policy set via
-- `PUT /v1/admin/runtime/k8s/policies`. Before this there was no admin
-- endpoint at all — the rule pack was seeded from `RulePack::recommended()`
-- at boot and could not be customised; now an operator-authored policy is
-- stored here and reloaded into the admission engine on every restart.
--
-- ## Storage shape
--
-- One row per tenant. The policy is a JSONB document owned by
-- `sx_api::view::k8s_admission_view::K8sAdmissionPolicyView` — a
-- declarative spec (PSS profile, built-in rule toggles, mandatory labels,
-- namespace opt-outs, dry-run). The in-crate `RulePack` carries
-- `Arc<dyn AdmissionRule>` trait objects that cannot be serialised, so the
-- spec is the durable form and the monolith reconstructs the rule pack
-- from it on load.
--
-- ## Tenant isolation
--
-- Keyed by `tenant_id` (TEXT) with an explicit `tenant_id = $1` predicate —
-- NO row-level security, the same convention as `risk_tuning_overrides` /
-- `dlp_detector_config`. The admission tenant id arrives via the
-- `X-Sentinelx-Tenant` header / the admin caller's claim and is treated as
-- free-form, so there is no FK to `tenants`.

CREATE TABLE k8s_admission_policies (
    tenant_id   TEXT PRIMARY KEY,
    spec        JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
