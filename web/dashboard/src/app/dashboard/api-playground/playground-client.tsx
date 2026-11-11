"use client";

import * as React from "react";
import {
  Plus,
  Send,
  Trash2,
  X,
  Copy,
  History,
  Settings,
  KeyRound,
  ChevronDown,
  ChevronRight,
  Activity,
  ClipboardList,
  Search,
  Crosshair,
  Eye,
  Users,
  Scale,
  Wrench,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/components/toast";
import { cn } from "@/lib/utils";

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] as const;
type Method = (typeof METHODS)[number];

interface ExampleRequest {
  method: Method;
  path: string;
  label: string;
  body?: string;
}

interface ExampleModule {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  examples: ExampleRequest[];
}

const EXAMPLE_MODULES: ExampleModule[] = [
  {
    id: "operations",
    label: "Operations",
    icon: Activity,
    examples: [
      { method: "GET", path: "/v1/soc/alerts?limit=20", label: "SOC alerts list" },
      { method: "POST", path: "/v1/soc/events", label: "Submit SOC event", body: '{"source":"playground","payload":{"kind":"test"}}' },
      { method: "POST", path: "/v1/safety/kill-switch", label: "Trip kill-switch", body: '{"reason":"runaway BAS"}' },
      { method: "GET", path: "/v1/bas/approvals", label: "BAS pending approvals" },
      { method: "POST", path: "/v1/bas/approvals", label: "Record BAS approval", body: '{"token":"<approval-token>","decision":"approve","reason":"manual sign-off"}' },
      { method: "GET", path: "/v1/copilot/approvals", label: "Copilot approvals queue" },
    ],
  },
  {
    id: "engagement",
    label: "Engagement",
    icon: ClipboardList,
    examples: [
      { method: "GET", path: "/v1/engagements?limit=20", label: "Engagements list" },
      { method: "POST", path: "/v1/engagements", label: "Create engagement", body: '{"name":"Q3 pentest","scopes":["example.com"]}' },
      { method: "GET", path: "/v1/findings?limit=20", label: "Findings list" },
      { method: "POST", path: "/v1/findings/bulk-update", label: "Findings bulk-update", body: '{"ids":["<finding-id>"],"status":"resolved"}' },
      { method: "GET", path: "/v1/remediation/outcomes/metrics", label: "Remediation metrics" },
      { method: "POST", path: "/v1/copilot/chat", label: "Copilot single-turn", body: '{"prompt":"Summarise the top open critical findings"}' },
      { method: "GET", path: "/v1/reports", label: "Reports list" },
      { method: "GET", path: "/v1/reports/comprehensive", label: "Comprehensive report (all modules)" },
      { method: "POST", path: "/v1/reports/diff", label: "Reports diff", body: '{"from_report_id":"<from>","to_report_id":"<to>"}' },
      { method: "GET", path: "/v1/reports/branding", label: "Report branding (get)" },
      { method: "PUT", path: "/v1/reports/branding", label: "Report branding (set)", body: '{"primary_color_hex":"#0A1B2C","cover_md":"# Acme","footer_md":"confidential"}' },
      { method: "GET", path: "/v1/reports/schedules", label: "Report schedules list" },
      { method: "POST", path: "/v1/reports/schedules", label: "Create report schedule", body: '{"engagement_id":"<engagement-id>","format":"executive_pdf","cron_expr":"0 0 8 * * 1","recipients":["soc@example.com"]}' },
      { method: "POST", path: "/v1/risk/calculate", label: "Compute risk", body: '{"engagement_id":"{{tenant_id}}","cvss":7.5,"epss":0.4,"exposure":0.6,"criticality":0.8}' },
    ],
  },
  {
    id: "discovery",
    label: "Discovery",
    icon: Search,
    examples: [
      { method: "GET", path: "/v1/assets?limit=20", label: "Assets list" },
      { method: "POST", path: "/v1/scans/http-headers", label: "Scan HTTP headers", body: '{"url":"https://example.com"}' },
      { method: "GET", path: "/v1/scans?limit=20", label: "Scans list" },
      { method: "POST", path: "/v1/vuln/import", label: "Vulnerability import", body: '{"source":"trivy","items":[]}' },
      { method: "POST", path: "/v1/discovery/prowler/import", label: "Prowler import", body: '{"provider":"aws","findings":[]}' },
      { method: "GET", path: "/v1/cloud/inventory", label: "Cloud inventory (cached)" },
      { method: "POST", path: "/v1/cloud/drift/scan", label: "Cloud drift scan", body: '{}' },
      { method: "GET", path: "/v1/logs?limit=20", label: "Logs (OCSF) list" },
      { method: "POST", path: "/v1/logs/ingest", label: "Ingest CloudTrail events", body: '{"source":"cloudtrail","events":[]}' },
      { method: "GET", path: "/v1/intel/feeds", label: "Threat-intel feeds" },
    ],
  },
  {
    id: "offensive",
    label: "Offensive",
    icon: Crosshair,
    examples: [
      { method: "GET", path: "/v1/bas/runs?limit=20", label: "BAS runs" },
      { method: "POST", path: "/v1/bas/run", label: "Run BAS technique", body: '{"technique_id":"T1059","engagement_id":"<engagement-id>"}' },
      { method: "GET", path: "/v1/bas/chains", label: "BAS chains" },
      { method: "POST", path: "/v1/bas/chains/{chain-id}/run", label: "Run BAS chain", body: '{"engagement_id":"<engagement-id>"}' },
      { method: "POST", path: "/v1/graph/attack-paths", label: "Search attack paths", body: '{"source":"<asset-a>","target":"<asset-b>"}' },
      { method: "POST", path: "/v1/cloud/blast-radius", label: "Compute blast radius", body: '{"asset_id":"<asset>","max_depth":3}' },
      { method: "POST", path: "/v1/discovery/dast/scan", label: "API DAST scan", body: '{"base_url":"https://api.example.com"}' },
      { method: "POST", path: "/v1/pentest/runs", label: "Combined pentest run", body: '{"engagement_id":"<engagement-id>","name":"Q4 external","targets":["web-1.example.com"],"phases":[]}' },
      { method: "GET", path: "/v1/pentest/runs", label: "Pentest runs list" },
      { method: "POST", path: "/v1/redteam/chain", label: "Compose red-team chain", body: '{"objectives":["exfil-customer-data"]}' },
    ],
  },
  {
    id: "detection",
    label: "Detection",
    icon: Eye,
    examples: [
      { method: "GET", path: "/v1/ueba/anomalies?limit=20", label: "UEBA anomalies" },
      { method: "GET", path: "/v1/device-trust/policy", label: "Device-trust policy" },
      { method: "PUT", path: "/v1/device-trust/policy", label: "Update device-trust policy", body: '{"require_managed":true,"require_disk_encryption":true,"min_os_version":"14.0"}' },
      { method: "POST", path: "/v1/runtime/falco/alerts", label: "Ingest Falco alert", body: '{"rule":"Write below etc","priority":"Warning","output":"User edited /etc/passwd"}' },
      { method: "POST", path: "/v1/hunt/query", label: "Hunt query (KQL)", body: '{"query":"events | where severity > 5 | take 20","limit":20}' },
      { method: "POST", path: "/v1/ml/predict/triage", label: "ML predict triage", body: '{"finding_id":"<finding-id>"}' },
    ],
  },
  {
    id: "identity",
    label: "Identity",
    icon: Users,
    examples: [
      { method: "POST", path: "/v1/auth/login", label: "Auth login", body: '{"email":"admin@sentinelx.dev","password":"<password>"}' },
      { method: "GET", path: "/v1/mfa/status", label: "MFA status" },
      { method: "POST", path: "/v1/mfa/enroll", label: "Start MFA enrollment", body: '{"method":"totp"}' },
      { method: "POST", path: "/v1/auth/mfa/webauthn/register/start", label: "WebAuthn register start", body: '{"display_name":"YubiKey"}' },
      { method: "GET", path: "/scim/v2/Users?count=20", label: "SCIM users list" },
      { method: "GET", path: "/v1/rba/config", label: "Adaptive auth (RBA) config" },
      { method: "PUT", path: "/v1/rba/config", label: "Update RBA config", body: '{"block_threshold":0.9,"step_up_threshold":0.6}' },
      { method: "GET", path: "/v1/auth/saml/metadata", label: "SAML SP metadata" },
    ],
  },
  {
    id: "governance",
    label: "Governance",
    icon: Scale,
    examples: [
      { method: "GET", path: "/v1/compliance/frameworks/soc2", label: "Compliance controls (SOC2)" },
      { method: "GET", path: "/v1/compliance/frameworks/pcidss", label: "Compliance controls (PCI DSS — 250)" },
      { method: "POST", path: "/v1/compliance/evidence/collect", label: "Collect evidence", body: '{"framework":"soc2"}' },
      { method: "GET", path: "/v1/compliance/evidence/bundles", label: "Evidence bundles list" },
      { method: "GET", path: "/v1/ai-audit/assets", label: "AI asset inventory" },
      { method: "GET", path: "/v1/ai-audit/controls", label: "AI governance controls" },
      { method: "GET", path: "/v1/ai-audit/aibom", label: "AI-BOM (CycloneDX-ML)" },
      { method: "POST", path: "/v1/ai-audit/run", label: "Run AI security audit", body: '{}' },
      { method: "GET", path: "/v1/audit/search?limit=20", label: "Audit search" },
      { method: "GET", path: "/v1/audit/replay", label: "Audit replay window" },
      { method: "GET", path: "/v1/audit/anchors", label: "Audit anchors" },
      { method: "GET", path: "/v1/grc/configs", label: "GRC integration configs" },
      { method: "GET", path: "/v1/ir/playbooks", label: "IR playbooks" },
      { method: "POST", path: "/v1/ir/incidents", label: "Open IR incident", body: '{"playbook_id":"<playbook>","title":"Suspected lateral movement","severity":"high"}' },
      { method: "POST", path: "/v1/dlp/scan", label: "DLP scan content", body: '{"content":"SSN: 123-45-6789","context":"slack"}' },
    ],
  },
  {
    id: "developer",
    label: "Developer",
    icon: Wrench,
    examples: [
      { method: "GET", path: "/openapi.json", label: "OpenAPI 3.1 spec" },
      { method: "GET", path: "/metrics", label: "Prometheus metrics" },
      { method: "GET", path: "/v1/plugins", label: "Plugins list" },
      { method: "POST", path: "/v1/plugins/install", label: "Install plugin", body: '{"manifest_url":"https://example.com/plugin.json","checksum_sha256":"<sha>"}' },
      { method: "GET", path: "/v1/chaos/config", label: "Chaos config" },
      { method: "PUT", path: "/v1/chaos/config", label: "Update chaos config", body: '{"enabled":true,"failure_rate":0.05}' },
      { method: "GET", path: "/v1/risk/config", label: "Risk-tuning config" },
      { method: "GET", path: "/v1/notifications/devices", label: "Mobile push devices" },
      { method: "GET", path: "/v1/integrations/bugbounty/configs", label: "Bug-bounty integrations" },
      { method: "GET", path: "/v1/soar/workflows", label: "SOAR workflows list" },
    ],
  },
];

interface KV {
  key: string;
  value: string;
  enabled: boolean;
}

interface RequestState {
  id: string;
  name: string;
  method: Method;
  url: string;
  headers: KV[];
  body: string;
  use_session_token: boolean;
}

interface ResponseState {
  status: number;
  status_text: string;
  headers: Record<string, string>;
  body: string;
  truncated: boolean;
  elapsed_ms: number;
}

interface HistoryEntry {
  id: string;
  ts: number;
  method: Method;
  url: string;
  status: number;
  elapsed_ms: number;
}

const STORAGE_TABS = "sx-playground-tabs";
const STORAGE_ENV = "sx-playground-env";
const STORAGE_HISTORY = "sx-playground-history";
const MAX_HISTORY = 50;

function genId(): string {
  return Math.random().toString(36).slice(2, 11);
}

function defaultRequest(name = "Untitled"): RequestState {
  return {
    id: genId(),
    name,
    method: "GET",
    url: "{{base_url}}/v1/engagements",
    headers: [{ key: "Accept", value: "application/json", enabled: true }],
    body: "",
    use_session_token: true,
  };
}

function defaultEnv(sxBase: string): KV[] {
  return [
    { key: "base_url", value: sxBase, enabled: true },
    { key: "tenant_id", value: "01010101-0101-0101-0101-010101010101", enabled: true },
  ];
}

function substitute(input: string, env: KV[]): string {
  return input.replace(/\{\{(\w+)\}\}/g, (_full, name: string) => {
    const kv = env.find((e) => e.enabled && e.key === name);
    return kv ? kv.value : `{{${name}}}`;
  });
}

function statusTone(s: number): "success" | "info" | "medium" | "critical" | "outline" {
  if (s >= 500) return "critical";
  if (s >= 400) return "medium";
  if (s >= 300) return "info";
  if (s >= 200) return "success";
  return "outline";
}

function tryPretty(body: string, ctype: string | undefined): string {
  if (body.length === 0) return body;
  const looksJson = ctype?.includes("json") ?? body.trimStart().startsWith("{") ?? body.trimStart().startsWith("[");
  if (!looksJson) return body;
  try {
    const j: unknown = JSON.parse(body);
    return JSON.stringify(j, null, 2);
  } catch {
    return body;
  }
}

interface Props {
  sxApiBase: string;
}

export function PlaygroundClient({ sxApiBase }: Props) {
  const toast = useToast();
  const [tabs, setTabs] = React.useState<ReadonlyArray<RequestState>>(() => [defaultRequest()]);
  const [activeId, setActiveId] = React.useState<string>(() => "");
  const [env, setEnv] = React.useState<ReadonlyArray<KV>>(() => defaultEnv(sxApiBase));
  const [history, setHistory] = React.useState<ReadonlyArray<HistoryEntry>>([]);
  const [response, setResponse] = React.useState<ResponseState | null>(null);
  const [sending, setSending] = React.useState(false);
  const [showEnv, setShowEnv] = React.useState(false);
  const [showHistory, setShowHistory] = React.useState(false);
  const [bodyView, setBodyView] = React.useState<"pretty" | "raw" | "headers">("pretty");

  // Hydrate from localStorage on mount.
  React.useEffect(() => {
    try {
      const t = window.localStorage.getItem(STORAGE_TABS);
      if (t !== null) {
        const parsed = JSON.parse(t) as ReadonlyArray<RequestState>;
        if (Array.isArray(parsed) && parsed.length > 0) {
          setTabs(parsed);
          setActiveId(parsed[0]?.id ?? "");
          return;
        }
      }
    } catch {
      /* ignore */
    }
    const seed = defaultRequest();
    setTabs([seed]);
    setActiveId(seed.id);
  }, []);

  React.useEffect(() => {
    try {
      const e = window.localStorage.getItem(STORAGE_ENV);
      if (e !== null) {
        const parsed = JSON.parse(e) as ReadonlyArray<KV>;
        if (Array.isArray(parsed)) setEnv(parsed);
      }
      const h = window.localStorage.getItem(STORAGE_HISTORY);
      if (h !== null) {
        const parsed = JSON.parse(h) as ReadonlyArray<HistoryEntry>;
        if (Array.isArray(parsed)) setHistory(parsed);
      }
    } catch {
      /* ignore */
    }
  }, []);

  // Persist tabs/env/history.
  React.useEffect(() => {
    try {
      window.localStorage.setItem(STORAGE_TABS, JSON.stringify(tabs));
    } catch {
      /* ignore */
    }
  }, [tabs]);
  React.useEffect(() => {
    try {
      window.localStorage.setItem(STORAGE_ENV, JSON.stringify(env));
    } catch {
      /* ignore */
    }
  }, [env]);
  React.useEffect(() => {
    try {
      window.localStorage.setItem(STORAGE_HISTORY, JSON.stringify(history));
    } catch {
      /* ignore */
    }
  }, [history]);

  const active = tabs.find((t) => t.id === activeId) ?? tabs[0];

  function updateActive(patch: Partial<RequestState>): void {
    if (active === undefined) return;
    setTabs((current) =>
      current.map((t) => (t.id === active.id ? { ...t, ...patch } : t)),
    );
  }

  function addTab(): void {
    const t = defaultRequest(`Untitled ${tabs.length + 1}`);
    setTabs((current) => [...current, t]);
    setActiveId(t.id);
    setResponse(null);
  }

  function closeTab(id: string): void {
    setTabs((current) => {
      const next = current.filter((t) => t.id !== id);
      if (next.length === 0) {
        const seed = defaultRequest();
        setActiveId(seed.id);
        return [seed];
      }
      if (id === activeId) setActiveId(next[0]?.id ?? "");
      return next;
    });
  }

  async function send(): Promise<void> {
    if (active === undefined) return;
    setSending(true);
    setResponse(null);
    try {
      const url = substitute(active.url, [...env]);
      const headers: Record<string, string> = {};
      for (const h of active.headers) {
        if (!h.enabled || h.key.length === 0) continue;
        headers[h.key] = substitute(h.value, [...env]);
      }
      const body =
        active.method === "GET" || active.method === "HEAD"
          ? undefined
          : substitute(active.body, [...env]);
      const res = await fetch("/api/playground/exec", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          method: active.method,
          url,
          headers,
          body,
          use_session_token: active.use_session_token,
        }),
      });
      const parsed = (await res.json()) as {
        data?: ResponseState;
        error?: { message?: string };
      };
      if (!res.ok || parsed.data === undefined) {
        toast.push({
          kind: "error",
          message: parsed.error?.message ?? `Proxy failed (${res.status})`,
        });
        return;
      }
      setResponse(parsed.data);
      setHistory((current) => {
        const entry: HistoryEntry = {
          id: genId(),
          ts: Date.now(),
          method: active.method,
          url,
          status: parsed.data!.status,
          elapsed_ms: parsed.data!.elapsed_ms,
        };
        return [entry, ...current].slice(0, MAX_HISTORY);
      });
    } catch {
      toast.push({ kind: "error", message: "Network error" });
    } finally {
      setSending(false);
    }
  }

  function copyToClipboard(text: string): void {
    void navigator.clipboard
      .writeText(text)
      .then(() => toast.push({ kind: "success", message: "Copied." }))
      .catch(() => toast.push({ kind: "error", message: "Copy failed" }));
  }

  if (active === undefined) {
    return null;
  }

  const responseCtype = response?.headers["content-type"];
  const prettyBody = response !== null ? tryPretty(response.body, responseCtype) : "";

  return (
    <div className="grid gap-4 lg:grid-cols-[1fr,360px]">
      <div className="space-y-3">
        {/* Tabs */}
        <div className="flex items-center gap-1 overflow-x-auto border-b border-border">
          {tabs.map((t) => (
            <div
              key={t.id}
              className={cn(
                "flex items-center gap-1.5 rounded-t-sx border border-b-0 px-3 py-1.5 text-xs",
                t.id === activeId
                  ? "border-border bg-card text-foreground"
                  : "border-transparent text-muted-foreground hover:bg-muted/50",
              )}
            >
              <button
                type="button"
                onClick={() => {
                  setActiveId(t.id);
                  setResponse(null);
                }}
                className="font-mono"
              >
                <span className="mr-1.5 font-semibold">{t.method}</span>
                <span className="max-w-[120px] truncate align-middle">{t.name}</span>
              </button>
              {tabs.length > 1 ? (
                <button
                  type="button"
                  aria-label={`Close ${t.name}`}
                  onClick={() => closeTab(t.id)}
                  className="rounded p-0.5 hover:bg-muted"
                >
                  <X className="h-3 w-3" aria-hidden />
                </button>
              ) : null}
            </div>
          ))}
          <button
            type="button"
            onClick={addTab}
            aria-label="New tab"
            className="ml-1 rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
          >
            <Plus className="h-4 w-4" aria-hidden />
          </button>
        </div>

        {/* Request panel */}
        <Card>
          <CardHeader className="space-y-2 pb-3">
            <div className="flex items-center gap-2">
              <Input
                value={active.name}
                onChange={(e) => updateActive({ name: e.currentTarget.value })}
                className="h-7 max-w-[260px] text-xs"
                aria-label="Tab name"
              />
              <div className="ml-auto flex gap-1">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setShowEnv((s) => !s)}
                >
                  <Settings className="mr-1 h-3.5 w-3.5" aria-hidden />
                  Env
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setShowHistory((s) => !s)}
                >
                  <History className="mr-1 h-3.5 w-3.5" aria-hidden />
                  History
                </Button>
              </div>
            </div>
            <div className="flex gap-2">
              <select
                value={active.method}
                onChange={(e) =>
                  updateActive({ method: e.currentTarget.value as Method })
                }
                className="h-9 w-24 rounded-sx border border-border bg-transparent px-2 text-sm font-semibold"
                aria-label="HTTP method"
              >
                {METHODS.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
              <Input
                value={active.url}
                onChange={(e) => updateActive({ url: e.currentTarget.value })}
                placeholder="https://api.example.com/v1/things or {{base_url}}/v1/engagements"
                className="font-mono text-xs"
                aria-label="URL"
              />
              <Button onClick={() => void send()} disabled={sending}>
                <Send className="mr-1 h-4 w-4" aria-hidden />
                {sending ? "Sending…" : "Send"}
              </Button>
            </div>
            <label className="flex items-center gap-2 text-xs text-muted-foreground">
              <input
                type="checkbox"
                checked={active.use_session_token}
                onChange={(e) =>
                  updateActive({ use_session_token: e.currentTarget.checked })
                }
              />
              <KeyRound className="h-3 w-3" aria-hidden />
              Inject dashboard session bearer token (sx-api auth)
            </label>
          </CardHeader>
          <CardContent className="space-y-4">
            <HeadersEditor
              headers={active.headers}
              onChange={(h) => updateActive({ headers: [...h] })}
            />
            <BodyEditor
              method={active.method}
              body={active.body}
              onChange={(b) => updateActive({ body: b })}
            />
          </CardContent>
        </Card>

        {/* Response */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm">Response</CardTitle>
              {response !== null ? (
                <div className="flex items-center gap-2 text-xs">
                  <Badge variant={statusTone(response.status)}>
                    {response.status} {response.status_text}
                  </Badge>
                  <span className="text-muted-foreground">{response.elapsed_ms} ms</span>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => copyToClipboard(prettyBody)}
                  >
                    <Copy className="mr-1 h-3 w-3" aria-hidden />
                    Copy body
                  </Button>
                </div>
              ) : null}
            </div>
            {response !== null ? (
              <div className="mt-2 flex gap-1 text-xs">
                {(["pretty", "raw", "headers"] as const).map((v) => (
                  <button
                    key={v}
                    type="button"
                    onClick={() => setBodyView(v)}
                    className={cn(
                      "rounded-sx px-2 py-1",
                      bodyView === v
                        ? "bg-muted text-foreground"
                        : "text-muted-foreground hover:bg-muted/50",
                    )}
                  >
                    {v}
                  </button>
                ))}
              </div>
            ) : null}
          </CardHeader>
          <CardContent>
            {response === null ? (
              <p className="py-12 text-center text-xs text-muted-foreground">
                No response yet. Configure a request above and click Send.
              </p>
            ) : (
              <ResponseBody response={response} view={bodyView} pretty={prettyBody} />
            )}
          </CardContent>
        </Card>
      </div>

      {/* Right sidebar — env / history toggle */}
      <div className="space-y-3">
        {showEnv ? (
          <EnvEditor env={env} onChange={setEnv} onClose={() => setShowEnv(false)} />
        ) : null}
        {showHistory ? (
          <HistoryPanel
            history={history}
            onPick={(h) => {
              const t = defaultRequest(h.url.slice(0, 40));
              t.method = h.method;
              t.url = h.url;
              setTabs((current) => [...current, t]);
              setActiveId(t.id);
              setResponse(null);
            }}
            onClear={() => setHistory([])}
            onClose={() => setShowHistory(false)}
          />
        ) : null}
        {!showEnv && !showHistory ? (
          <ExampleCatalog
            onPick={(ex) =>
              updateActive({
                method: ex.method,
                url: `{{base_url}}${ex.path}`,
                body: ex.body ?? "",
              })
            }
          />
        ) : null}
      </div>
    </div>
  );
}

function HeadersEditor({
  headers,
  onChange,
}: {
  headers: ReadonlyArray<KV>;
  onChange: (h: ReadonlyArray<KV>) => void;
}) {
  function update(i: number, patch: Partial<KV>): void {
    onChange(headers.map((h, idx) => (idx === i ? { ...h, ...patch } : h)));
  }
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <Label>Headers</Label>
        <Button
          size="sm"
          variant="outline"
          onClick={() =>
            onChange([...headers, { key: "", value: "", enabled: true }])
          }
        >
          <Plus className="mr-1 h-3 w-3" aria-hidden />
          Add
        </Button>
      </div>
      {headers.length === 0 ? (
        <p className="text-xs text-muted-foreground">No headers configured.</p>
      ) : (
        <div className="space-y-1">
          {headers.map((h, i) => (
            <div key={i} className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={h.enabled}
                onChange={(e) => update(i, { enabled: e.currentTarget.checked })}
                aria-label="Enable header"
              />
              <Input
                value={h.key}
                onChange={(e) => update(i, { key: e.currentTarget.value })}
                placeholder="Header-Name"
                className="h-8 font-mono text-xs"
              />
              <Input
                value={h.value}
                onChange={(e) => update(i, { value: e.currentTarget.value })}
                placeholder="value"
                className="h-8 font-mono text-xs"
              />
              <button
                type="button"
                onClick={() => onChange(headers.filter((_, idx) => idx !== i))}
                className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
                aria-label="Remove header"
              >
                <Trash2 className="h-3.5 w-3.5" aria-hidden />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function BodyEditor({
  method,
  body,
  onChange,
}: {
  method: Method;
  body: string;
  onChange: (s: string) => void;
}) {
  const disabled = method === "GET" || method === "HEAD";
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <Label htmlFor="body-editor">Body</Label>
        {disabled ? (
          <span className="text-xs text-muted-foreground">
            Body ignored for {method}
          </span>
        ) : (
          <Button
            size="sm"
            variant="outline"
            onClick={() => {
              try {
                onChange(JSON.stringify(JSON.parse(body), null, 2));
              } catch {
                /* not JSON */
              }
            }}
            disabled={body.length === 0}
          >
            Pretty
          </Button>
        )}
      </div>
      <textarea
        id="body-editor"
        value={body}
        onChange={(e) => onChange(e.currentTarget.value)}
        disabled={disabled}
        placeholder={
          disabled
            ? ""
            : '{\n  "name": "Q3 pentest",\n  "scopes": ["example.com"]\n}'
        }
        rows={8}
        className="block w-full rounded-sx border border-border bg-transparent px-3 py-2 font-mono text-xs text-foreground placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50"
      />
    </div>
  );
}

function ResponseBody({
  response,
  view,
  pretty,
}: {
  response: ResponseState;
  view: "pretty" | "raw" | "headers";
  pretty: string;
}) {
  if (view === "headers") {
    return (
      <div className="space-y-1 text-xs">
        {Object.entries(response.headers).map(([k, v]) => (
          <div key={k} className="flex gap-2 font-mono">
            <span className="min-w-[140px] text-muted-foreground">{k}:</span>
            <span className="break-all">{v}</span>
          </div>
        ))}
      </div>
    );
  }
  const text = view === "pretty" ? pretty : response.body;
  return (
    <>
      {response.truncated ? (
        <p className="mb-2 text-xs text-medium">
          Body truncated (over 1 MB shown only first 1 MB).
        </p>
      ) : null}
      <pre className="max-h-[480px] overflow-auto rounded-sx border border-border bg-muted/30 p-3 font-mono text-xs text-foreground">
        {text.length > 0 ? text : <em className="text-muted-foreground">empty body</em>}
      </pre>
    </>
  );
}

function EnvEditor({
  env,
  onChange,
  onClose,
}: {
  env: ReadonlyArray<KV>;
  onChange: (k: ReadonlyArray<KV>) => void;
  onClose: () => void;
}) {
  function update(i: number, patch: Partial<KV>): void {
    onChange(env.map((e, idx) => (idx === i ? { ...e, ...patch } : e)));
  }
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm">Environment variables</CardTitle>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close env"
          className="rounded p-1 text-muted-foreground hover:bg-muted"
        >
          <X className="h-4 w-4" aria-hidden />
        </button>
      </CardHeader>
      <CardContent className="space-y-2">
        <p className="text-xs text-muted-foreground">
          Use <code className="font-mono">{"{{name}}"}</code> in URL, headers or body to substitute.
        </p>
        {env.map((kv, i) => (
          <div key={i} className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={kv.enabled}
              onChange={(e) => update(i, { enabled: e.currentTarget.checked })}
              aria-label="Enable"
            />
            <Input
              value={kv.key}
              onChange={(e) => update(i, { key: e.currentTarget.value })}
              placeholder="name"
              className="h-8 font-mono text-xs"
            />
            <Input
              value={kv.value}
              onChange={(e) => update(i, { value: e.currentTarget.value })}
              placeholder="value"
              className="h-8 font-mono text-xs"
            />
            <button
              type="button"
              onClick={() => onChange(env.filter((_, idx) => idx !== i))}
              className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
              aria-label="Remove"
            >
              <Trash2 className="h-3.5 w-3.5" aria-hidden />
            </button>
          </div>
        ))}
        <Button
          size="sm"
          variant="outline"
          onClick={() => onChange([...env, { key: "", value: "", enabled: true }])}
        >
          <Plus className="mr-1 h-3 w-3" aria-hidden />
          Add variable
        </Button>
      </CardContent>
    </Card>
  );
}

function HistoryPanel({
  history,
  onPick,
  onClear,
  onClose,
}: {
  history: ReadonlyArray<HistoryEntry>;
  onPick: (h: HistoryEntry) => void;
  onClear: () => void;
  onClose: () => void;
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <CardTitle className="text-sm">History ({history.length})</CardTitle>
        <div className="flex gap-1">
          {history.length > 0 ? (
            <Button size="sm" variant="outline" onClick={onClear}>
              Clear
            </Button>
          ) : null}
          <button
            type="button"
            onClick={onClose}
            aria-label="Close history"
            className="rounded p-1 text-muted-foreground hover:bg-muted"
          >
            <X className="h-4 w-4" aria-hidden />
          </button>
        </div>
      </CardHeader>
      <CardContent>
        {history.length === 0 ? (
          <p className="text-xs text-muted-foreground">No requests yet.</p>
        ) : (
          <div className="space-y-1">
            {history.map((h) => (
              <button
                key={h.id}
                type="button"
                onClick={() => onPick(h)}
                className="block w-full rounded-sx border border-border p-2 text-left text-xs hover:bg-muted"
              >
                <div className="flex items-center gap-2">
                  <Badge variant={statusTone(h.status)}>{h.status}</Badge>
                  <span className="font-mono font-semibold">{h.method}</span>
                  <span className="ml-auto text-muted-foreground">{h.elapsed_ms} ms</span>
                </div>
                <p className="mt-1 truncate font-mono">{h.url}</p>
                <p className="mt-0.5 text-muted-foreground">
                  {new Date(h.ts).toLocaleString()}
                </p>
              </button>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function methodTone(m: Method): "success" | "info" | "medium" | "critical" | "outline" {
  switch (m) {
    case "GET":
      return "info";
    case "POST":
      return "success";
    case "PUT":
    case "PATCH":
      return "medium";
    case "DELETE":
      return "critical";
    default:
      return "outline";
  }
}

function ExampleCatalog({
  onPick,
}: {
  onPick: (ex: ExampleRequest) => void;
}) {
  // Default: first module open so the panel is never empty on first paint.
  const [open, setOpen] = React.useState<Record<string, boolean>>(() => ({
    operations: true,
  }));
  function toggle(id: string): void {
    setOpen((current) => ({ ...current, [id]: !current[id] }));
  }
  const totalExamples = EXAMPLE_MODULES.reduce(
    (sum, m) => sum + m.examples.length,
    0,
  );
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Quick examples</CardTitle>
        <p className="text-xs text-muted-foreground">
          {totalExamples} prebaked requests across 8 modules. Click to load into
          the active tab.
        </p>
      </CardHeader>
      <CardContent className="space-y-1.5">
        {EXAMPLE_MODULES.map((mod) => {
          const Icon = mod.icon;
          const isOpen = open[mod.id] === true;
          return (
            <div key={mod.id} className="rounded-sx border border-border">
              <button
                type="button"
                onClick={() => toggle(mod.id)}
                aria-expanded={isOpen}
                className="flex w-full items-center gap-2 px-2 py-1.5 text-xs text-foreground hover:bg-muted/50"
              >
                {isOpen ? (
                  <ChevronDown className="h-3.5 w-3.5" aria-hidden />
                ) : (
                  <ChevronRight className="h-3.5 w-3.5" aria-hidden />
                )}
                <Icon className="h-3.5 w-3.5 text-muted-foreground" aria-hidden />
                <span className="font-medium">{mod.label}</span>
                <span className="ml-auto text-muted-foreground">
                  {mod.examples.length}
                </span>
              </button>
              {isOpen ? (
                <div className="space-y-1 border-t border-border p-1.5">
                  {mod.examples.map((ex, idx) => (
                    <button
                      key={`${mod.id}-${idx}`}
                      type="button"
                      onClick={() => onPick(ex)}
                      className="block w-full rounded-sx border border-transparent p-1.5 text-left text-xs hover:border-border hover:bg-muted"
                    >
                      <div className="flex items-center gap-2">
                        <Badge variant={methodTone(ex.method)}>{ex.method}</Badge>
                        <code className="truncate font-mono text-[11px]">
                          {ex.path}
                        </code>
                      </div>
                      <p className="mt-0.5 text-muted-foreground">{ex.label}</p>
                    </button>
                  ))}
                </div>
              ) : null}
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
