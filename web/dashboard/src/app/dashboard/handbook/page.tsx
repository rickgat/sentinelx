import { redirect } from "next/navigation";
import Link from "next/link";
import {
  BookOpen,
  CheckCircle2,
  ClipboardList,
  Crosshair,
  ShieldAlert,
  ShieldCheck,
  Network,
  KeyRound,
  AlertTriangle,
  Building2,
  Cloud,
  FileBarChart,
  Code2,
  Lock,
  ChevronRight,
  Compass,
  Sword,
  Eye,
  Fingerprint,
  Gavel,
  Send,
  ScrollText,
  Bell,
  GitBranch,
  Target,
  Database,
  Bug,
  Activity,
  Server,
  Zap,
  Bot,
  UserCheck,
  Cpu,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { getAccessToken } from "@/lib/server-fetch";

/**
 * SentinelX Handbook — v1.1 (2026-06-14).
 *
 * Reorganised around the 8 sidebar modules (Operations, Engagement,
 * Discovery, Offensive, Detection, Identity, Governance, Developer).
 * Every dashboard surface, every backing port, every operational
 * caveat introduced in P0-001 … P3-010 is documented here.
 */

const SECTIONS = [
  { id: "quickstart", label: "Quickstart", icon: BookOpen },
  // Module 1: Operations
  { id: "mod-operations", label: "▸ Operations", icon: Compass, group: true },
  { id: "comprehensive", label: "Comprehensive Report", icon: FileBarChart },
  { id: "soc", label: "SOC Alerts & Correlation", icon: Bell },
  { id: "approvals", label: "Two-Person Approvals", icon: ShieldCheck },
  { id: "safety", label: "Safety / Kill-switch", icon: ShieldAlert },
  // Module 2: Engagement
  { id: "mod-engagement", label: "▸ Engagement & Findings", icon: ClipboardList, group: true },
  { id: "engagements", label: "Engagements", icon: ClipboardList },
  { id: "findings", label: "Findings & Triage", icon: AlertTriangle },
  { id: "remediation", label: "Remediation Outcomes", icon: CheckCircle2 },
  { id: "reports", label: "Reports & Templates", icon: FileBarChart },
  { id: "copilot", label: "Copilot HITL", icon: Bot },
  // Module 3: Discovery
  { id: "mod-discovery", label: "▸ Discovery & Inventory", icon: ShieldAlert, group: true },
  { id: "assets", label: "Assets & Criticality", icon: Building2 },
  { id: "scans", label: "HTTP Header Scans", icon: ShieldAlert },
  { id: "vuln-import", label: "Vulnerability Ingest", icon: Database },
  { id: "cloud", label: "Cloud Inventory & Drift", icon: Cloud },
  { id: "logs", label: "Log Ingestion (OCSF)", icon: ScrollText },
  { id: "intel", label: "Threat Intel Feeds", icon: Target },
  // Module 4: Offensive
  { id: "mod-offensive", label: "▸ Offensive Simulation", icon: Sword, group: true },
  { id: "pentest", label: "Combined Pentest", icon: Crosshair },
  { id: "bas", label: "Breach & Attack Simulation", icon: Crosshair },
  { id: "lateral", label: "Lateral Movement Chains", icon: GitBranch },
  { id: "graph", label: "Attack Graph (Neo4j)", icon: Network },
  { id: "blast-radius", label: "Blast Radius", icon: Target },
  { id: "twin", label: "Digital Twin", icon: Network },
  { id: "dast", label: "API DAST (Postman Replay)", icon: Bug },
  // Module 5: Detection
  { id: "mod-detection", label: "▸ Detection & Behavior", icon: Eye, group: true },
  { id: "ueba", label: "UEBA Baseline & Anomaly", icon: UserCheck },
  { id: "device-trust", label: "Device Trust + Posture", icon: Server },
  { id: "impossible-travel", label: "Impossible-Travel", icon: Activity },
  { id: "runtime-falco", label: "Container Runtime (Falco)", icon: Cpu },
  { id: "k8s-admission", label: "K8s Admission Analyzer", icon: ShieldAlert },
  { id: "hunting", label: "Threat Hunting (KQL/SPL)", icon: Activity },
  // Module 6: Identity & Access
  { id: "mod-iam", label: "▸ Identity & Access", icon: Fingerprint, group: true },
  { id: "auth", label: "Authentication", icon: KeyRound },
  { id: "saml", label: "SAML 2.0 SP", icon: KeyRound },
  { id: "scim", label: "SCIM 2.0 Provisioning", icon: KeyRound },
  { id: "webauthn", label: "FIDO2 / WebAuthn MFA", icon: KeyRound },
  { id: "rba", label: "Adaptive Auth (RBA)", icon: ShieldCheck },
  { id: "kek", label: "Secrets / KMS Providers", icon: Lock },
  // Module 7: Governance
  { id: "mod-governance", label: "▸ Compliance & Governance", icon: Gavel, group: true },
  { id: "compliance", label: "Controls", icon: CheckCircle2 },
  { id: "ai-audit", label: "AI Security Audit", icon: Bot },
  { id: "evidence", label: "Evidence Collector (WORM)", icon: CheckCircle2 },
  { id: "audit-replay", label: "Audit Replay", icon: Activity },
  { id: "audit-anchor", label: "TSA Audit-Chain Anchoring", icon: Lock },
  { id: "grc", label: "GRC Integration (Vanta/Drata/SN)", icon: Send },
  { id: "ir-playbooks", label: "IR Playbooks (NIST 800-61)", icon: ClipboardList },
  { id: "dlp", label: "DLP Content Inspection", icon: ShieldAlert },
  // Module 8: Developer
  { id: "mod-developer", label: "▸ Developer & Resources", icon: Code2, group: true },
  { id: "api", label: "API Access", icon: Code2 },
  { id: "soar", label: "SOAR Workflow Builder", icon: GitBranch },
  { id: "plugins", label: "Plugin SDK", icon: Cpu },
  { id: "chatops", label: "Chat-ops (Slack/Teams)", icon: Send },
  { id: "mobile-push", label: "Mobile Push (APNs+FCM)", icon: Bell },
  { id: "bug-bounty", label: "Bug Bounty Bridge", icon: Bug },
  { id: "chaos", label: "Chaos Engineering Hooks", icon: Zap },
  { id: "risk-tuning", label: "Per-Tenant Risk Tuning", icon: Activity },
  // Closing
  { id: "security-model", label: "Security Model", icon: Lock },
  { id: "ops-ref", label: "Operational Reference", icon: BookOpen },
] as const;

export default async function HandbookPage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  return (
    <div className="flex gap-6">
      {/* Sticky TOC */}
      <aside className="hidden lg:block w-72 shrink-0">
        <div className="sticky top-4 max-h-[calc(100vh-2rem)] overflow-y-auto pr-2">
          <p className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2 px-1">
            Contents · v1.1
          </p>
          <nav className="space-y-0.5">
            {SECTIONS.map((s) => (
              <a
                key={s.id}
                href={`#${s.id}`}
                className={`flex items-center gap-2 px-2 py-1.5 text-xs rounded-sx transition ${
                  "group" in s && s.group
                    ? "font-semibold text-foreground hover:bg-muted/40 mt-2 first:mt-0"
                    : "text-muted-foreground hover:text-foreground hover:bg-muted/40"
                }`}
              >
                <s.icon className="h-3 w-3" aria-hidden />
                <span>{s.label}</span>
              </a>
            ))}
          </nav>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 space-y-6 max-w-3xl scroll-pt-4">
        <header className="space-y-2">
          <div className="flex items-center gap-2">
            <BookOpen className="h-5 w-5 text-accent" aria-hidden />
            <h1 className="text-xl font-semibold">SentinelX Handbook</h1>
            <Badge variant="info">v1.1</Badge>
          </div>
          <p className="text-sm text-muted-foreground">
            Operator reference for the full SentinelX platform — 46/47 P0-P3
            capabilities (TAXII / SAML / SCIM / Neo4j / WebAuthn / KMS providers,
            UEBA / Device Trust, SOAR, SAR / GRC, audit-chain TSA anchoring, KQL
            hunting, DLP, chaos hooks, Falco runtime, mobile push, bug-bounty
            bridge, and more). Sections are organised to match the 8 sidebar
            modules. Each section deep-links via its <code>#id</code>.
          </p>
        </header>

        {/* Quickstart */}
        <Section
          id="quickstart"
          title="Quickstart"
          icon={BookOpen}
          summary="Boot, login, navigate. Three minutes."
        >
          <ol className="list-decimal pl-5 space-y-2 text-sm">
            <li>
              <b>Monolith</b> binds <code>127.0.0.1:8080</code> by default
              (set via <code>server.bind_addr</code> or
              <code>SENTINELX__SERVER__BIND_ADDR</code>). Health probe lives at
              <code>GET /healthz</code>.
            </li>
            <li>
              <b>Dashboard</b> runs Next.js 15 at <code>127.0.0.1:3000</code>.
              <code> npm run build &amp;&amp; npm start</code> for production
              (~365 ms ready, &lt;2 ms per route). Dev mode (<code>npm run dev</code>)
              recompiles per route — only use it for active development.
            </li>
            <li>
              <b>Bootstrap admin</b>: set
              <code> SENTINELX__BOOTSTRAP__ENABLED=true</code>, supply an Argon2id
              PHC via <code>ADMIN_PASSWORD_PHC</code>, pick a UUID for
              <code> ADMIN_TENANT_ID</code>. The admin gets the wildcard
              <code> *:*</code> role at boot.
            </li>
            <li>
              <b>Sidebar grouping</b>: 8 collapsible modules — Operations,
              Engagement, Discovery, Offensive, Detection, Identity, Governance,
              Developer. The module containing the active route auto-expands.
            </li>
            <li>
              <b>Global search</b>:
              <kbd className="rounded border px-1.5 py-0.5 text-[10px] font-mono">⌘K</kbd> /
              <kbd className="rounded border px-1.5 py-0.5 text-[10px] font-mono">Ctrl K</kbd>
              .
            </li>
          </ol>
          <Tip>
            Dev RBA bypass: dashboard auth.ts injects
            <code> X-Forwarded-For: 8.8.8.8</code> on the server-side
            <code> /v1/auth/login</code> fetch so RBA's IP-geo scorer sees a US
            address (home country). Production deployments rely on a reverse
            proxy to set the header from the real client IP.
          </Tip>
        </Section>

        {/* ========== MODULE 1: OPERATIONS ========== */}
        <ModuleHeader id="mod-operations" icon={Compass} title="Operations" />

        <Section
          id="comprehensive"
          title="Comprehensive Report"
          icon={FileBarChart}
          summary="One executive report aggregated from the live results of every module."
        >
          <p className="text-sm">
            <Link className="text-accent" href="/dashboard/reporting">/dashboard/reporting</Link> —
            a single, generated report that pulls the latest results across the whole platform:
            findings posture (severity breakdown + weighted posture score), engagements, pentest
            runs, AI-audit assets &amp; controls, BAS, cloud posture/drift, SOC alerts, UEBA, RBA,
            threat intel, and compliance control coverage.
          </p>
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Each module is fetched independently and <b>degrades gracefully</b> — a module you
              can&apos;t read (403) or that is empty is marked in the coverage appendix rather than
              failing the page.</li>
            <li><b>Export</b>: Print / Save as PDF, Download Markdown, Download JSON — generated
              client-side from the aggregated model.</li>
            <li><b>Server artifact</b>: <code>GET /v1/reports/comprehensive</code> returns the
              aggregated fields + a rendered Markdown document for API consumers.</li>
          </ul>
          <Tip>Requires <code>report:read</code>. Use this as the one-page executive view before an
            engagement review.</Tip>
        </Section>

        <Section
          id="soc"
          title="SOC Alerts & Correlation"
          icon={Bell}
          summary="OCSF-normalised event correlation; 50+ MITRE-mapped rules."
        >
          <p className="text-sm">
            The SOC engine (<code>sx-soc</code>) consumes OCSF-normalised events
            from the log-ingestion pipeline (see <em>Log Ingestion</em> below)
            and runs a correlation rule pack. Each fired rule emits a
            <Badge variant="medium">SOC alert</Badge> with the upstream events,
            severity, and a MITRE ATT&amp;CK technique label.
          </p>
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Browse alerts at <Link className="text-accent" href="/dashboard/soc">/dashboard/soc</Link>.</li>
            <li>List API: <code>GET /v1/soc/alerts?limit=20</code>.</li>
            <li>Per-tenant rule packs; defaults ship with 50+ rules covering credential abuse, persistence, exfil, lateral movement.</li>
          </ul>
        </Section>

        <Section
          id="approvals"
          title="Two-Person Approvals"
          icon={ShieldCheck}
          summary="Mandatory human consent gate for higher-impact actions."
        >
          <p className="text-sm">
            BAS modes at <code>safe_interactive</code> and above, plus copilot
            destructive actions, require 2 distinct approver emails on the
            <code> (engagement_id, technique_id)</code> pair before dispatch.
          </p>
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li><code>POST /v1/bas/approvals</code> — record an approval.</li>
            <li><code>GET /v1/bas/approvals</code> — auditor view, gated by <code>bas:approve_list</code>.</li>
            <li>P1-012 copilot HITL uses the same <code>ApprovalPort</code> trait — see <em>Copilot</em>.</li>
          </ul>
        </Section>

        <Section
          id="safety"
          title="Safety / Kill-switch"
          icon={ShieldAlert}
          summary="Single-trip global stop for every running technique / job."
        >
          <p className="text-sm">
            One <code>POST /v1/safety/kill-switch</code> aborts every running
            BAS technique, SOAR workflow, and continuous-validation job across
            the monolith. The trip is persisted to the audit chain and
            propagated via the <code>sentinelx.killswitch</code> Redis channel
            (or the in-memory equivalent when Redis is disabled).
          </p>
          <Tip>
            The kill-switch is the recommended response to runaway chaos
            injections (see <em>Chaos Engineering</em>) and to any active-exploit
            BAS chain that escapes its scope.
          </Tip>
        </Section>

        {/* ========== MODULE 2: ENGAGEMENT ========== */}
        <ModuleHeader id="mod-engagement" icon={ClipboardList} title="Engagement & Findings" />

        <Section
          id="engagements"
          title="Engagements"
          icon={ClipboardList}
          summary="The unit of work — a scoped security assessment with a state machine."
        >
          <p className="text-sm">An engagement is a container for assets, scans, BAS runs, findings, approvals. Lifecycle:</p>
          <div className="font-mono text-xs bg-muted/40 rounded-sx p-3 text-muted-foreground">
            draft → scheduled → active ⇄ paused → completed
            <br />                            └→ aborted / cancelled
          </div>
          <p className="text-sm">Manage at <Link className="text-accent" href="/dashboard/engagements">/dashboard/engagements</Link>.</p>
        </Section>

        <Section
          id="findings"
          title="Findings & Triage"
          icon={AlertTriangle}
          summary="severity × status grid; bulk-update; OCSF source mapping."
        >
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="rounded-sx border border-border p-2">
              <p className="font-medium mb-1">Severity</p>
              <div className="space-y-1">
                <p><Badge variant="critical">critical</Badge> CVSS ≥ 9 / active exploit</p>
                <p><Badge variant="critical">high</Badge> CVSS 7–8.9</p>
                <p><Badge variant="medium">medium</Badge> CVSS 4–6.9</p>
                <p><Badge variant="info">low</Badge> CVSS 0.1–3.9</p>
                <p><Badge variant="outline">info</Badge></p>
              </div>
            </div>
            <div className="rounded-sx border border-border p-2">
              <p className="font-medium mb-1">Status</p>
              <div className="space-y-1">
                <p><Badge variant="outline">open</Badge></p>
                <p><Badge variant="info">triaged</Badge></p>
                <p><Badge variant="medium">accepted</Badge></p>
                <p><Badge variant="success">closed</Badge></p>
              </div>
            </div>
          </div>
          <p className="text-sm">
            <code>POST /v1/findings/bulk-update</code> (cap 500 ids). Every
            status change emits a hash-chained audit row. Source field carries
            the origin: <code>scanner</code>, <code>vuln_import.nessus</code>,
            <code> bugbounty.hackerone.researcher_42</code>, <code>sca-monitor</code>, etc.
          </p>
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li><b>Continuous SCA/SBOM monitoring</b> — a background monitor parses the dependency
              vulnerability report and materialises each package vuln as a finding (idempotent).</li>
            <li><b>Alerting</b> — a finding at or above the configured threshold (default
              <code> Critical</code>) is automatically fanned out to the configured incident sinks
              (Jira / PagerDuty / Opsgenie / ServiceNow / Linear).</li>
          </ul>
        </Section>

        <Section
          id="remediation"
          title="Remediation Outcomes & Regressions"
          icon={CheckCircle2}
          summary="P1-011 — track close → reopen cycles, MTTR, regression rate."
        >
          <p className="text-sm">
            Every <code>resolved</code> → <code>open</code> transition is
            classified as a <Badge variant="critical">regression</Badge>. The
            <code> remediation_outcomes</code> table records open_at /
            closed_at / TTR_seconds / regressed_at. Surfaces:
          </p>
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li><Link className="text-accent" href="/dashboard/remediation">/dashboard/remediation</Link> — outcome dashboard, MTTR per severity.</li>
            <li><code>GET /v1/remediation/metrics</code>, <code>GET /v1/remediation/regressions</code>.</li>
          </ul>
        </Section>

        <Section
          id="reports"
          title="Reports — Templates, Branding, Diff"
          icon={FileBarChart}
          summary="Scheduled distribution + per-tenant branding + week-over-week diffs."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li><b>Templates &amp; Branding (P2-002)</b> — per-tenant logo, colours, footer; PDF / HTML renderers respect branding.</li>
            <li><b>Scheduled distribution (P2-001)</b> — cron schedules + email/S3/webhook delivery with exponential-backoff retry + dead-letter.</li>
            <li><b>Differential reports (P2-003)</b> — delta between two snapshots (new / resolved / regressions / risk score delta). API: <code>POST /v1/reports/diff?from=&lt;id&gt;&amp;to=&lt;id&gt;</code>.</li>
            <li><b>List rendered reports</b> — <code>GET /v1/reports</code> (paged, newest first).</li>
            <li>PDF, STIX 2.1, NDJSON rendering paths shared across surfaces.</li>
          </ul>
        </Section>

        <Section
          id="copilot"
          title="Copilot HITL"
          icon={Bot}
          summary="LLM-assisted copilot with human-in-loop approval gate."
        >
          <p className="text-sm">
            <Link className="text-accent" href="/dashboard/copilot">/dashboard/copilot</Link> — chat surface; destructive actions (close finding, alter remediation) route to
            <Link className="text-accent" href="/dashboard/copilot-approvals"> Copilot Approvals</Link> queue (P1-012). Approvers act via the same two-person rule trait.
          </p>
        </Section>

        {/* ========== MODULE 3: DISCOVERY ========== */}
        <ModuleHeader id="mod-discovery" icon={ShieldAlert} title="Discovery & Inventory" />

        <Section
          id="assets"
          title="Assets & Criticality"
          icon={Building2}
          summary="Typed assets with criticality-weighted risk."
        >
          <p className="text-sm">
            Types: <code>domain</code>, <code>host</code>, <code>url</code>,
            <code> cidr</code>, <code>cloud_resource</code>,
            <code> container_image</code>, <code>repo</code>. Criticality:
          </p>
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li><Badge variant="outline">unknown</Badge> treated as production for safety.</li>
            <li><Badge variant="outline">dev</Badge> / <Badge variant="outline">staging</Badge> non-prod weights.</li>
            <li><Badge variant="medium">production</Badge> default.</li>
            <li><Badge variant="critical">crown_jewel</Badge> highest weight; multiplies blast-radius risk.</li>
          </ul>
        </Section>

        <Section
          id="scans"
          title="HTTP Header Scans"
          icon={ShieldAlert}
          summary="Passive external probe — security headers, server fingerprint."
        >
          <p className="text-sm">
            <Link className="text-accent" href="/dashboard/scans">/dashboard/scans</Link>. Single
            <code> GET</code> per target. Checks: HSTS, CSP, X-Content-Type-Options,
            X-Frame-Options, Server fingerprint, Referrer-Policy,
            Permissions-Policy, X-Powered-By disclosure.
          </p>
          <Tip>Passive only — never sends payloads, never authenticates.</Tip>
        </Section>

        <Section
          id="vuln-import"
          title="Vulnerability Ingest (P0-002 + P1-009)"
          icon={Database}
          summary="Authenticated scanner output + multi-cloud Prowler intake."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li><b>OpenVAS XML</b>, <b>Nessus .nessus</b>, <b>Qualys QID JSON</b> via <code>POST /v1/vuln/import</code> (multipart, max 100 MB).</li>
            <li><b>Prowler GCP + Azure</b> JSON via <code>POST /v1/discovery/prowler/import</code>. AWS Prowler still flows through the regular cloud adapter.</li>
            <li>Background worker chunks ingestion to keep request &lt;5 s.</li>
            <li>External plugin-id → SentinelX <code>check_id</code> map with dedup on <code>(asset_id, check_id)</code>.</li>
            <li>CVSS 3.1 + CVSS 4.0 + EPSS recomputed on ingest; KEV uplift applied.</li>
          </ul>
        </Section>

        <Section
          id="cloud"
          title="Cloud Inventory & Drift Detection (P2-004)"
          icon={Cloud}
          summary="AWS/GCP/Azure inventory + Terraform / CloudFormation drift diff."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li><Link className="text-accent" href="/dashboard/cloud">/dashboard/cloud</Link> — multi-provider inventory.</li>
            <li><code>POST /v1/cloud/drift/scan</code> compares Terraform state JSON (or CFN YAML) against live inventory; emits <Badge variant="medium">CloudDriftFinding</Badge> per delta.</li>
            <li><code>GET /v1/cloud/drift/findings</code> lists per-tenant drift.</li>
          </ul>
        </Section>

        <Section
          id="logs"
          title="Log Ingestion (P0-003)"
          icon={ScrollText}
          summary="OCSF/ECS normalised pipeline — CloudTrail, syslog, JSON-batch."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li><code>POST /v1/logs/raw</code> generic JSON array (max 10 MB).</li>
            <li><code>POST /v1/logs/cloudtrail</code> CloudTrail-shaped.</li>
            <li><code>POST /v1/logs/syslog</code> RFC 5424 over HTTP.</li>
            <li>Optional Kafka consumer topic: <code>sentinelx.logs.&lt;tenant&gt;</code>.</li>
            <li>Indexed in ClickHouse <code>events_raw</code> (30d TTL) and <code>events_normalized</code> (90d TTL).</li>
            <li>50+ rule packs map MITRE ATT&amp;CK techniques into SOC alerts.</li>
          </ul>
        </Section>

        <Section
          id="intel"
          title="Threat Intel Feeds (P0-001 + P0-006 + P1-013)"
          icon={Target}
          summary="TAXII 2.1 + NVD/KEV/EPSS + Mandiant / CrowdStrike."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li><b>TAXII 2.1</b> — paginated client, bearer-auth, normalised indicators into a sharded Bloom filter + <code>tenant_iocs</code> table. LRU cap 1M / tenant.</li>
            <li><b>NVD CVE 2.0</b> with rate-limit token bucket (5/30s without API key, 50/30s with).</li>
            <li><b>CISA KEV</b> hourly refresh; KEV uplift on severity.</li>
            <li><b>EPSS</b> daily CSV gzip decompressed via <code>flate2</code>.</li>
            <li><b>Mandiant Advantage</b> + <b>CrowdStrike Falcon Intel</b> commercial adapters (OAuth2 client_credentials), token cache + 401 refresh, per-vendor rate limits (60/100 rpm). Credentials encrypted via sx-secrets.</li>
            <li><Link className="text-accent" href="/dashboard/intel">/dashboard/intel</Link> · <code>GET /v1/intel/feeds</code> (status list).</li>
          </ul>
        </Section>

        {/* ========== MODULE 4: OFFENSIVE ========== */}
        <ModuleHeader id="mod-offensive" icon={Sword} title="Offensive Simulation" />

        <Section
          id="pentest"
          title="Combined Pentest Orchestration"
          icon={Crosshair}
          summary="One engagement chaining recon → scan → SCA/secret/IaC → ingest → BAS → attack-graph."
        >
          <p className="text-sm">
            <Link className="text-accent" href="/dashboard/pentest">/dashboard/pentest</Link> —
            launch a single engagement that runs every phase in order and correlates the output:
          </p>
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li><b>Phases</b>: Recon → Enumeration → Vuln-Scan → DAST/API → SCA/Secret/IaC →
              Credentialed-Ingest → BAS-Validation → Graph-Chaining → Report.</li>
            <li><b>Correlation + dedup</b>: discovery observations and ingested vuln records are
              converted to unified findings with a stable fingerprint; duplicates across scanners
              merge (highest severity wins, evidence &amp; source list unioned).</li>
            <li><b>Attack narrative</b>: correlated findings feed the knowledge graph to surface
              attack paths; a pentest report is assembled (methodology, scope, narrative, retest).</li>
          </ul>
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Launch: <code>POST /v1/pentest/runs</code> (<code>pentest:run</code>) with
              <code> engagement_id</code>, <code>name</code>, <code>targets[]</code>.</li>
            <li>List / fetch: <code>GET /v1/pentest/runs</code> · <code>GET /v1/pentest/runs/&#123;id&#125;</code>
              (<code>pentest:read</code>).</li>
          </ul>
          <Tip>Every phase is scope- and kill-switch-gated by the engagement; an out-of-scope
            target aborts the phase.</Tip>
        </Section>

        <Section
          id="bas"
          title="Breach & Attack Simulation"
          icon={Crosshair}
          summary="50+ techniques across Initial Access / Cred-Access / Lateral / Persistence / Priv-Esc."
        >
          <p className="text-sm">Modes (in order of impact):</p>
          <div className="rounded-sx border border-border bg-muted/20 p-2 text-xs space-y-1">
            <p><Badge variant="outline">theoretical</Badge> graph traversal, zero packets. Default.</p>
            <p><Badge variant="info">passive_validation</Badge> cached intel + sig match. Internal only.</p>
            <p><Badge variant="medium">safe_interactive</Badge> non-destructive probes. <b>2 approvals required.</b></p>
            <p><Badge variant="critical">active_exploit</Badge> PoC verification. Gated off the HTTP surface; requires RoE + 3+ approvals + change window.</p>
          </div>
          <p className="text-sm">
            Library expanded to 50+ techniques (P1-008): T1003, T1056, T1110,
            T1212, T1552 (cred access); T1078, T1133, T1190, T1199, T1566
            (initial access); T1021, T1080, T1210, T1534, T1570 (lateral);
            T1098, T1136, T1505, T1543, T1547 (persistence); T1068, T1078.004,
            T1134, T1548, T1611 (privilege escalation).
          </p>
        </Section>

        <Section
          id="lateral"
          title="Lateral Movement Chain Replay (P2-015)"
          icon={GitBranch}
          summary="Pre-canned multi-step attack chains with two-person gate."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>3 canonical chains: <b>ransomware-style</b>, <b>supply-chain compromise</b>, <b>phishing → privesc → lateral</b>.</li>
            <li>Sequential <code>ChainExecutor</code> captures per-step <code>{`{technique_id, status, evidence}`}</code>.</li>
            <li>API: <code>GET /v1/bas/chains</code> · <code>POST /v1/bas/chains/{`{id}`}/run</code> · <code>GET /v1/bas/chains/runs/{`{id}`}</code>.</li>
            <li>Per-tenant <code>bas_chain_runs</code> table; RLS-forced.</li>
          </ul>
        </Section>

        <Section
          id="graph"
          title="Attack Graph (Neo4j Adapter)"
          icon={Network}
          summary="Bi-directional BFS depth ≤7, top-N by composite risk, per-tenant isolation."
        >
          <p className="text-sm">
            <b>P1-001 Neo4j adapter</b> swaps in behind the existing
            <code> GraphAttackPathsPort</code>. Bolt protocol via
            <code> neo4rs</code>. Cypher queries for bi-BFS, top-N,
            blast-radius. Every node tagged
            <code> :Asset {`{tenant_id: $tid}`}</code>; every query
            parameterised. Cross-tenant access is structurally impossible —
            covered by a dedicated test.
          </p>
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Idempotent <code>ensure_schema()</code> creates constraints + indexes.</li>
            <li>Bulk batching: 5000 nodes / 10000 edges per txn.</li>
            <li>Read latency p95 &lt; 200 ms target for top-10 path query on 1M-node graph.</li>
            <li>In-memory adjacency list remains the dev default; flip <code>graph.neo4j_enabled = true</code> to use Neo4j.</li>
          </ul>
        </Section>

        <Section
          id="blast-radius"
          title="Cloud Blast Radius (P1-010)"
          icon={Target}
          summary="IAM-role chains, KMS grants, network peers, S3 ACLs — what a foothold reaches."
        >
          <p className="text-sm">
            <Link className="text-accent" href="/dashboard/blast-radius">/dashboard/blast-radius</Link> — pick a seed asset; the graph walker emits a ranked list of reachable resources with edge-kind:
          </p>
          <ul className="list-disc pl-5 text-sm space-y-1 text-xs">
            <li><Badge variant="critical">iam_role_chain</Badge> · <Badge variant="critical">kms_grant</Badge> highest impact</li>
            <li><Badge variant="default">network_peer</Badge> default</li>
            <li><Badge variant="info">s3_acl</Badge> · <Badge variant="info">security_group_edge</Badge></li>
          </ul>
        </Section>

        <Section
          id="twin"
          title="Digital Twin"
          icon={Network}
          summary="Cyber model of the production env — explore without touching prod."
        >
          <p className="text-sm">
            <Link className="text-accent" href="/dashboard/twin">/dashboard/twin</Link> — read-only projection over which BAS / red team can plan without telemetry leaking from the real environment.
          </p>
        </Section>

        <Section
          id="dast"
          title="API DAST — Postman Replay (P2-013)"
          icon={Bug}
          summary="Auth-bypass, IDOR, missing rate-limit, verbose 5xx, insecure CORS."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Parses Postman v2.1 collection.</li>
            <li>Replays against target API with variable substitution + bearer.</li>
            <li>Signal-class detectors: auth-bypass, IDOR, missing rate-limit, verbose 500, insecure CORS.</li>
            <li>API: <code>POST /v1/discovery/dast/scan</code> (multipart). List via <code>GET /v1/discovery/dast/scans</code>.</li>
            <li>Authorization header redacted from logs and per-tenant scan history.</li>
          </ul>
        </Section>

        {/* ========== MODULE 5: DETECTION ========== */}
        <ModuleHeader id="mod-detection" icon={Eye} title="Detection & Behavior" />

        <Section
          id="ueba"
          title="UEBA — Baseline & Anomaly (P2-005)"
          icon={UserCheck}
          summary="Per-user rolling baseline (login-time, geo, asset access) + anomaly score."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Sliding baseline window per user; updates incrementally.</li>
            <li>Score features: login-hour z-score, country shift, asset-access entropy.</li>
            <li><Link className="text-accent" href="/dashboard/ueba">/dashboard/ueba</Link>. <code>GET /v1/ueba/anomalies</code>.</li>
          </ul>
        </Section>

        <Section
          id="device-trust"
          title="Device Trust + Posture (P2-008)"
          icon={Server}
          summary="Per-tenant device policy + EDR posture facts; per-session evaluation."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Policy includes EDR vendor allowlist (CrowdStrike, SentinelOne, Defender, Carbon Black), disk-encryption requirement, OS minimum versions.</li>
            <li>Per-session evaluation hooks into the middleware; failing posture → forced re-auth or step-up MFA.</li>
            <li><Link className="text-accent" href="/dashboard/device-trust">/dashboard/device-trust</Link>.</li>
          </ul>
        </Section>

        <Section
          id="impossible-travel"
          title="Impossible-Travel Detection (P2-007)"
          icon={Activity}
          summary="Great-circle distance / elapsed time > 800 km/h → SOC alert."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Per-user travel-history ring (tenant-scoped).</li>
            <li>Speed = haversine distance / elapsed time between consecutive login geos.</li>
            <li>VPN allowlist suppression: both IPs in known VPN egress range → no alert.</li>
            <li>Emits SOC finding <code>iam.impossible_travel</code> with both records as evidence.</li>
          </ul>
        </Section>

        <Section
          id="runtime-falco"
          title="Container Runtime — Falco Integration (P2-016)"
          icon={Cpu}
          summary="Falco alerts → OCSF events → K8s asset correlation → RuntimeFinding."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Webhook <code>POST /v1/runtime/falco/alerts</code> (HMAC-SHA256 per-tenant ingestion key).</li>
            <li>Normalises Falco alerts to OCSF Process / Application Activity events.</li>
            <li>Correlates with K8s assets via <code>container.image</code> + pod name.</li>
            <li>Severity mapping (Critical/Error/Warning/Notice/Info) → SentinelX severity.</li>
            <li>Golden fixtures cover: privileged escape, shell-in-container, k8s admin token mount.</li>
          </ul>
        </Section>

        <Section
          id="k8s-admission"
          title="K8s Admission Analyzer (P2-014)"
          icon={ShieldAlert}
          summary="16 rules over AdmissionReview JSON. Read-only advisory, not blocking."
        >
          <p className="text-sm">
            <code>POST /v1/k8s/admission/review</code> consumes an AdmissionReview JSON
            and returns advisory <code>K8sAdmissionFinding</code> list. 16 rules:
          </p>
          <p className="text-xs font-mono text-muted-foreground">
            privileged · hostPath · hostNetwork · hostPID · hostIPC ·
            NET_ADMIN/SYS_ADMIN · missing-seccomp · missing-AppArmor ·
            unsafe-sysctls · untrusted-registry · :latest-tag ·
            missing-resource-limits · run-as-root ·
            allowPrivilegeEscalation · readOnlyRootFilesystem=false ·
            automountServiceAccountToken-default
          </p>
        </Section>

        <Section
          id="hunting"
          title="Threat Hunting — KQL/SPL-like (P3-006)"
          icon={Activity}
          summary="Pipe-style query language compiled to parameterised ClickHouse SQL."
        >
          <p className="text-sm">
            <code>{`<source> | where <pred> | summarize <agg> by <field> | project <fields> | top <N> by <field>`}</code>
          </p>
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Sources: <code>events_raw</code>, <code>events_normalized</code>.</li>
            <li>Predicates: <code>==</code>, <code>!=</code>, <code>&gt;</code>, <code>&lt;</code>, <code>contains</code>, <code>startswith</code>, <code>in (…)</code>, <code>and</code>, <code>or</code>, <code>not</code>.</li>
            <li>Aggregations: <code>count()</code>, <code>count_distinct(field)</code>, <code>sum</code>, <code>avg</code>, <code>min</code>, <code>max</code>.</li>
            <li>Time window: <code>| timeWindow ago(24h)</code> or <code>| between(t1, t2)</code>.</li>
            <li>API: <code>POST /v1/hunt/query</code>.</li>
          </ul>
          <Tip>
            Every compiled SQL <b>auto-includes</b>
            <code> tenant_id = $tid</code> regardless of user-supplied
            predicates. Identifiers (table / column names) are whitelisted;
            values are bind-only. An adversarial query attempting
            <code> ; DROP TABLE</code> is rejected at parse time.
          </Tip>
        </Section>

        {/* ========== MODULE 6: IAM ========== */}
        <ModuleHeader id="mod-iam" icon={Fingerprint} title="Identity & Access" />

        <Section
          id="auth"
          title="Authentication & Session"
          icon={KeyRound}
          summary="Auth.js v5 dashboard + Bearer JWT API."
        >
          <p className="text-sm">
            Dashboard uses Auth.js v5 with two providers: <b>Credentials</b>
            (dev / on-prem first-launch) and <b>OIDC</b> (production SSO via
            issuer / client-id / client-secret).
          </p>
          <p className="text-sm">
            Browser never sees the refresh token — it lives in the encrypted
            <code> sentinelx.session</code> cookie. Access token only exposed
            to server components and API proxies.
          </p>
        </Section>

        <Section
          id="saml"
          title="SAML 2.0 Service Provider (P0-004)"
          icon={KeyRound}
          summary="XMLDSig verification, InResponseTo replay protection, per-tenant IdP."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li><code>GET /v1/auth/saml/metadata</code> SP metadata XML.</li>
            <li><code>POST /v1/auth/saml/acs</code> Assertion Consumer Service.</li>
            <li><code>GET /v1/auth/saml/logout</code> SLO initiator.</li>
            <li>XMLDSig with canonical XML; reject unsigned assertions.</li>
            <li><b>Replay protection</b>: <code>InResponseTo</code> + assertion-ID dedup, 5-min window.</li>
            <li>NotBefore / NotOnOrAfter validated with 30s clock skew.</li>
            <li>Per-tenant IdP config (entity_id, sso_url, slo_url, x509_cert, signing_algo).</li>
          </ul>
        </Section>

        <Section
          id="scim"
          title="SCIM 2.0 Provisioning (P0-005)"
          icon={KeyRound}
          summary="Okta / Azure AD / Google Workspace JIT + de-provisioning."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Endpoints under <code>/scim/v2/</code>: Users + Groups CRUD, ServiceProviderConfig, ResourceTypes, Schemas.</li>
            <li>Per-tenant SCIM token (separate from user JWT) for bearer auth.</li>
            <li>Filter syntax: <code>eq</code>, <code>ne</code>, <code>co</code>, <code>sw</code>, <code>ew</code>, <code>and</code>, <code>or</code>.</li>
            <li>De-provision sets <code>is_active=false</code> and revokes all sessions.</li>
            <li>Tested against Okta, Azure AD, Google Workspace SCIM clients.</li>
          </ul>
        </Section>

        <Section
          id="webauthn"
          title="FIDO2 / WebAuthn MFA (P1-002)"
          icon={KeyRound}
          summary="Roaming + platform authenticators, per-tenant attestation policy."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li><code>POST /v1/auth/mfa/webauthn/register/{`{start,finish}`}</code> + <code>/login/{`{start,finish}`}</code>.</li>
            <li>Roaming (YubiKey) + platform (TouchID, Windows Hello).</li>
            <li>Per-tenant attestation: <code>None</code> / <code>Indirect</code> / <code>Direct</code>.</li>
            <li>Per-user multiple credentials.</li>
            <li>Credential-bound JWT claim <code>cred_id</code>.</li>
            <li>Replay-safe authData counter check (W3C §7.2 step 21).</li>
          </ul>
        </Section>

        <Section
          id="rba"
          title="Adaptive Auth — RBA (P1-003)"
          icon={ShieldCheck}
          summary="Risk-based login: IP-geo + velocity + business-hours."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Signals: IP-geo (home_country, foreign, private XX, unknown ??), velocity (sliding window), business-hours window.</li>
            <li>Score 0–100. Defaults: <code>allow_threshold=30</code>, <code>block_threshold=70</code>. In-between → step-up MFA.</li>
            <li>Per-tenant config via <code>GET/PUT /v1/rba/config</code>.</li>
            <li>Per-tenant weights tunable via Risk Tuning (P1-014) — see <em>Per-Tenant Risk Tuning</em>.</li>
          </ul>
          <Tip>
            In dev with loopback (127.0.0.1) the IP-geo lookup returns
            <code> ??</code> (unknown) → score 80 → block. Either set
            <code> X-Forwarded-For</code> to a home-country IP, or
            <code> PUT /v1/rba/config</code> with
            <code> allow_threshold=99</code>.
          </Tip>
        </Section>

        <Section
          id="kek"
          title="Secrets — KEK Providers (P1-005/6/7)"
          icon={Lock}
          summary="AWS KMS, GCP Cloud KMS, Azure Key Vault — pluggable KekProvider trait."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li><b>AWS KMS</b> via <code>aws-sdk-kms</code>; customer-managed CMK + HSM CMK.</li>
            <li><b>GCP Cloud KMS</b> via REST; service account or Workload Identity Federation.</li>
            <li><b>Azure Key Vault</b> via <code>azure-sdk-for-rust</code>; CMEK + HSM keyring.</li>
            <li>Encryption context binds <code>{`{tenant_id, dek_version}`}</code> on every wrap/unwrap.</li>
            <li>Terraform modules shipped in <code>deploy/</code>.</li>
          </ul>
        </Section>

        {/* ========== MODULE 7: GOVERNANCE ========== */}
        <ModuleHeader id="mod-governance" icon={Gavel} title="Compliance & Governance" />

        <Section
          id="compliance"
          title="Controls"
          icon={CheckCircle2}
          summary="SOC 2 + ISO 27001:2022 + PCI DSS v4.0.1 (complete) + NIST 800-53 + CIS AWS + HIPAA."
        >
          <p className="text-sm">
            In-process control catalogs served by <code>sx-api</code>. Findings auto-mapped to
            controls. View at
            <Link className="text-accent" href="/dashboard/compliance"> /dashboard/compliance</Link>;
            open a framework to list its controls.
          </p>
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li><b>PCI DSS v4.0.1 is complete</b> — all 12 requirements and their defined
              sub-requirements (250 controls), e.g. <code>1.1.1</code> … <code>12.10.7</code>.</li>
            <li>API: <code>GET /v1/compliance/frameworks/&#123;code&#125;</code> where code is
              <code> pcidss</code>, <code>soc2</code>, <code>iso27001</code>, <code>nist80053</code>,
              <code> cisaws</code>, <code>hipaa</code> (<code>compliance:read</code>).</li>
          </ul>
        </Section>

        <Section
          id="ai-audit"
          title="AI Security Audit (AI-SEC-001)"
          icon={Bot}
          summary="AI-BOM, prompt-injection/jailbreak probing, model-file scan, and AI-governance controls."
        >
          <p className="text-sm">
            <Link className="text-accent" href="/dashboard/ai-audit">/dashboard/ai-audit</Link> —
            a comprehensive audit of the tenant&apos;s AI surface:
          </p>
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li><b>AI asset inventory + AI-BOM</b> — discovered from the dependency SBOM (LLM SDKs,
              vector DBs, model registries, agent frameworks, MCP servers, ML runtimes).</li>
            <li><b>Prompt-injection / jailbreak probing</b> — a scope-gated corpus tagged with
              OWASP LLM Top-10 + MITRE ATLAS; runs against the platform&apos;s own copilot when
              enabled.</li>
            <li><b>Model-file supply-chain scan</b> — dangerous pickle opcodes + safetensors header
              validation.</li>
            <li><b>AI-governance controls</b> — NIST AI RMF (GOVERN/MAP/MEASURE/MANAGE), ISO/IEC
              42001, EU AI Act.</li>
            <li>Every copilot decision is recorded to the <b>sx-audit chain</b> (prompt/response
              SHA-256 hashes + model + user, per ADR-0004 §7).</li>
          </ul>
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>API: <code>GET /v1/ai-audit/&#123;assets,aibom,controls&#125;</code>
              (<code>ai_audit:read</code>) · <code>POST /v1/ai-audit/run</code>
              (<code>ai_audit:run</code>).</li>
          </ul>
        </Section>

        <Section
          id="evidence"
          title="Automated Evidence Collector (P1-004)"
          icon={CheckCircle2}
          summary="WORM-locked S3 bundles, HMAC-signed manifests, 7-year retention."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Built-in collectors: MFA enrolment rate, AWS IAM password policy, Vault sealed-state, kill-switch-tested-recently, audit-chain integrity verify.</li>
            <li>Per-control cron (default weekly).</li>
            <li>Storage: S3 Object Lock Compliance mode, 7-year retention.</li>
            <li>ZIP bundle export: <code>manifest.json</code> + HMAC-SHA256 hashes per file (per-tenant secret via sx-secrets).</li>
            <li>API: <code>POST /v1/compliance/evidence/collect</code> · <code>GET /v1/compliance/evidence/bundles</code> · <code>GET /v1/compliance/evidence/bundles/{`{id}`}/download</code>.</li>
          </ul>
        </Section>

        <Section
          id="audit-replay"
          title="Audit Replay / Time-Travel (P3-009)"
          icon={Activity}
          summary="Reconstruct state mutations for an entity within a time window."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li><code>GET /v1/audit/replay?entity_type=user&amp;entity_id=…&amp;from=…&amp;to=…</code></li>
            <li>Returns ordered timeline + state at each step.</li>
            <li>Hash-chain integrity verified before serving; broken chain surfaces as <Badge variant="critical">chain_verified=false</Badge> with structured <code>chain_error</code>.</li>
            <li>Cross-tenant entity lookups rejected (tested).</li>
          </ul>
        </Section>

        <Section
          id="audit-anchor"
          title="External Audit-Chain Anchoring — TSA (P1-015)"
          icon={Lock}
          summary="RFC 3161 timestamp signing of periodic Merkle roots."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Periodic Merkle-root snapshot of the audit hash-chain (default 1 h, configurable) per tenant.</li>
            <li>RFC 3161 TSA client: POSTs TimeStampReq, parses TimeStampResp, verifies signature against pinned CA.</li>
            <li>Per-tenant <code>audit_anchor_runs</code> table with run_id, merkle_root, tsa_serial, tsa_genTime, anchored_at, payload_bytes.</li>
            <li>Invalid signature → CRITICAL sx-audit event.</li>
            <li>API: <code>GET /v1/audit/anchors</code> · <code>POST /v1/audit/anchors/verify/{`{run_id}`}</code> for on-demand re-verification.</li>
          </ul>
        </Section>

        <Section
          id="grc"
          title="GRC Integration (P2-009) — Vanta · Drata · ServiceNow"
          icon={Send}
          summary="Outbound push of findings + control evidence."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Adapters: Vanta, Drata, ServiceNow.</li>
            <li>Per-tenant config rows with API tokens encrypted via sx-secrets.</li>
            <li>Retry with exponential backoff; dead-letter on permanent failure.</li>
            <li>Endpoints: <code>POST /v1/grc/configs</code>, <code>POST /v1/grc/configs/{`{kind}`}/test</code>, <code>POST /v1/grc/push</code>, <code>GET /v1/grc/configs</code>.</li>
            <li>Audit log per push (HTTP code + redacted reason).</li>
          </ul>
        </Section>

        <Section
          id="ir-playbooks"
          title="In-App IR Playbooks — NIST 800-61 (P3-004)"
          icon={ClipboardList}
          summary="Preparation → Detection → Containment → Eradication → Recovery → Post-Incident."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>4 pre-canned playbooks: <b>ransomware</b>, <b>data exfiltration</b>, <b>credential compromise</b>, <b>insider threat</b>.</li>
            <li>State machine per incident; per-phase checklist; status per step (todo/in_progress/done/skipped + reason).</li>
            <li>API: <code>GET /v1/ir/playbooks</code>, <code>POST /v1/ir/incidents</code>, <code>PATCH /v1/ir/incidents/{`{id}`}/steps/{`{step}`}</code>, <code>GET /v1/ir/incidents/{`{id}`}</code>.</li>
            <li>Per-tenant <code>ir_incidents</code> + <code>ir_step_audit</code> tables (RLS-forced).</li>
          </ul>
        </Section>

        <Section
          id="dlp"
          title="DLP Content Inspection (P2-006)"
          icon={ShieldAlert}
          summary="PII regex, secrets (AWS/GCP/Slack/GitHub PAT), Luhn-validated CC, redaction."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Trait <code>ContentInspector</code> + 12+ detectors (SSN, credit card via Luhn, email, phone, passport, AWS access/secret key, GCP service-account key, GitHub PAT, JWT, Slack token, PEM private key, named-entity).</li>
            <li>API: <code>POST /v1/dlp/scan</code> (multipart, max 10 MB).</li>
            <li>Per-tenant detector config: which detectors enabled.</li>
            <li>Audit log per scan.</li>
          </ul>
        </Section>

        {/* ========== MODULE 8: DEVELOPER ========== */}
        <ModuleHeader id="mod-developer" icon={Code2} title="Developer & Resources" />

        <Section
          id="api"
          title="API Access"
          icon={Code2}
          summary="OpenAPI 3.1 + interactive playground."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li><Link className="text-accent" href="/dashboard/api-docs">/dashboard/api-docs</Link> renders live OpenAPI spec.</li>
            <li><Link className="text-accent" href="/dashboard/api-playground">/dashboard/api-playground</Link> executes with current session token.</li>
            <li>Raw spec: <code>GET /v1/openapi.json</code>.</li>
          </ul>
          <pre className="rounded-sx border border-border bg-muted/30 p-3 text-[11px] font-mono overflow-x-auto">{`# 1. Login
curl -X POST http://127.0.0.1:8080/v1/auth/login \\
  -H 'Content-Type: application/json' \\
  -H 'X-Forwarded-For: 8.8.8.8' \\
  -d '{"tenant_id":"01010101-...","email":"admin@sentinelx.dev","password":"devpw2026"}'
# → { "data": { "access_token": "...", "refresh_token": "..." } }

# 2. List findings
curl -H "Authorization: Bearer $ACCESS_TOKEN" \\
  http://127.0.0.1:8080/v1/findings?limit=50`}</pre>
        </Section>

        <Section
          id="soar"
          title="SOAR Workflow Builder (P3-005)"
          icon={GitBranch}
          summary="DAG (trigger / action / condition / parallel) with topological scheduling."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Workflow defined as JSON DAG; nodes: trigger, action, condition, parallel.</li>
            <li><code>ActionExecutor</code> registry: HTTP request, sx-remediation play, sx-webhooks emit, condition branch.</li>
            <li>Cycle detection at start.</li>
            <li>API: <code>POST /v1/soar/workflows</code>, <code>POST /v1/soar/workflows/{`{id}`}/run</code>, <code>GET /v1/soar/runs/{`{id}`}</code>, <code>GET /v1/soar/workflows</code>.</li>
            <li>Per-tenant <code>soar_workflows</code> + <code>soar_runs</code>.</li>
          </ul>
        </Section>

        <Section
          id="plugins"
          title="Plugin SDK & Marketplace (P3-007)"
          icon={Cpu}
          summary="Stable Plugin trait + capability-scoped host functions + HMAC webhook dispatcher."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Manifest: <code>name, version, vendor, supported_events, required_scopes, webhook_url</code>.</li>
            <li>Capability-scoped host functions: <code>findings:read</code>, <code>findings:annotate</code>, <code>http:fetch</code> (with allow-list).</li>
            <li>HMAC-SHA256 dispatcher signs every webhook call.</li>
            <li>API: <code>GET /v1/plugins</code>, <code>POST /v1/plugins/install</code>, <code>DELETE /v1/plugins/{`{id}`}</code>, <code>GET /v1/plugins/{`{id}`}/dispatches</code>.</li>
            <li>Audit log per install/uninstall and every host-function call.</li>
          </ul>
        </Section>

        <Section
          id="chatops"
          title="Chat-ops — Slack / Teams (P3-002)"
          icon={Send}
          summary="Outbound Block Kit / Adaptive Card; inbound slash commands."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Outbound: Slack incoming-webhook, Teams power-automate-webhook.</li>
            <li>Inbound (Slack): <code>/sentinelx ack &lt;finding_id&gt;</code>, <code>/sentinelx assign</code>, <code>/sentinelx mute</code>.</li>
            <li>Slack signing-secret verification with HMAC-SHA256 + <b>constant-time compare</b> (<code>subtle::ConstantTimeEq</code>).</li>
            <li>Per-tenant config + signing-secret encrypted via sx-secrets.</li>
            <li>Rate-limit: 1 msg/sec/channel; coalesce duplicates in 60s window.</li>
          </ul>
        </Section>

        <Section
          id="mobile-push"
          title="Mobile Push — APNs + FCM (P3-008)"
          icon={Bell}
          summary="Critical-finding fan-out to escalation contacts' devices."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>APNs via HTTP/2 + ES256-signed JWT bearer (<code>jsonwebtoken</code> v0.5).</li>
            <li>FCM via HTTP/1.1 + OAuth2 service-account bearer.</li>
            <li>Per-user device registration: <code>POST /v1/notifications/devices</code> · <code>DELETE …/{`{id}`}</code> · <code>GET /v1/notifications/devices</code>.</li>
            <li>Severity ≥ CRITICAL fans out to tenant's escalation contacts' registered devices.</li>
            <li>Per-tenant APNs/FCM credentials encrypted via sx-secrets.</li>
            <li>Rate-limit 5 notif/min/device; 60s dedupe window.</li>
          </ul>
        </Section>

        <Section
          id="bug-bounty"
          title="Bug Bounty Bridge (P3-010)"
          icon={Bug}
          summary="HackerOne + Bugcrowd outbound + inbound webhook with TF-IDF dedupe."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Outbound: push triaged finding (severity ≥ HIGH) as draft internal note to HackerOne (api.hackerone.com/v1) or Bugcrowd (api.bugcrowd.com/v2).</li>
            <li>Inbound webhook: <code>POST /v1/integrations/bugbounty/inbound/{`{platform}`}</code> with HMAC signature verification (constant-time).</li>
            <li>Inbound dedupe: TF-IDF cosine ≥ 0.85 against existing findings.</li>
            <li>Per-tenant per-platform credentials encrypted via sx-secrets.</li>
          </ul>
        </Section>

        <Section
          id="chaos"
          title="Chaos Engineering Hooks (P2-012)"
          icon={Zap}
          summary="Latency / error-rate / dependency-down injection. Off by default."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Opt-in via <code>SX_CHAOS_ENABLED=1</code> + per-fault fractions.</li>
            <li><b>Refuses to enable</b> when <code>APP_ENV=production</code> — hard error at boot.</li>
            <li>Kinds: latency (p50/p99), error-rate (fraction), dependency unavailable / timeout.</li>
            <li>HTTP middleware + DB/Redis wrappers honour injection.</li>
            <li>Admin API: <code>GET/PUT /v1/chaos/config</code> with admin RBAC + non-prod gate.</li>
            <li>Prometheus counter: <code>sx_chaos_injections_total{`{kind,outcome}`}</code>.</li>
          </ul>
          <Tip>
            Combine with the kill-switch — if a chaos config trips a runaway
            cascade, hit <code>POST /v1/safety/kill-switch</code> to abort
            every running technique.
          </Tip>
        </Section>

        <Section
          id="risk-tuning"
          title="Per-Tenant Risk Model Tuning (P1-014)"
          icon={Activity}
          summary="Override weights + thresholds per tenant; sparse merge with global defaults."
        >
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li>Per-tenant override of risk weights (impact, exploitability, exposure, asset-criticality, blast-radius) + threshold cutoffs (low/med/high/crit).</li>
            <li>Validation: weights sum to 1.0 ±0.01; thresholds monotonic ascending.</li>
            <li>Effective config = global defaults ⊕ sparse override.</li>
            <li>API: <code>GET /v1/risk/config</code> · <code>PUT /v1/risk/config</code> (admin RBAC) · <code>GET /v1/risk/config/effective</code>.</li>
            <li>PUT enqueues idempotent recompute of all findings' risk for the tenant; audit log records diff old→new.</li>
          </ul>
        </Section>

        {/* ========== SECURITY MODEL ========== */}
        <Section
          id="security-model"
          title="Security Model"
          icon={Lock}
          summary="Tenant isolation, RLS, hash-chained audit, TSA anchoring, kill switches."
        >
          <ul className="list-disc pl-5 text-sm space-y-2">
            <li>
              <b>Tenant isolation via Postgres FORCE-RLS.</b> Every read inside a tenant-context tx with <code>SET LOCAL app.current_tenant_id</code>. No <code>BYPASSRLS</code>.
            </li>
            <li>
              <b>Hash-chained audit.</b> Every state change emits a row hash-chained from the previous row's hash. Tampering breaks the chain. <b>Anchored periodically to RFC 3161 TSA</b> (P1-015) for external non-repudiation.
            </li>
            <li>
              <b>Audit replay</b> (P3-009) reconstructs any entity's state history; chain integrity verified before serving.
            </li>
            <li>
              <b>Kill switch.</b> A single trip aborts every running technique / simulation / SOAR run. Channel: <code>sentinelx.killswitch</code>.
            </li>
            <li>
              <b>Two-person rule.</b> <code>safe_interactive</code> and above require 2 distinct approvers; <code>active_exploit</code> additionally needs RoE + change window + 3+ approvals.
            </li>
            <li>
              <b>Multi-cloud KMS</b> for DEK wrapping — AWS KMS, GCP Cloud KMS, Azure Key Vault. Encryption context binds <code>{`{tenant_id, dek_version}`}</code>.
            </li>
            <li>
              <b>RBA</b> at login (P1-003) — adaptive denial / step-up MFA based on IP-geo, velocity, business-hours.
            </li>
            <li>
              <b>Device posture</b> (P2-008) — failing tenant policy forces re-auth.
            </li>
            <li>
              <b>Plugin sandbox</b> — capability-scoped host functions, HMAC-signed webhooks, per-call audit log.
            </li>
            <li>
              <b>No unsafe code.</b> Entire Rust workspace is <code>#![forbid(unsafe_code)]</code>; clippy is run with <code>-D warnings</code> across all targets.
            </li>
          </ul>
        </Section>

        {/* ========== OPERATIONAL REFERENCE ========== */}
        <Section
          id="ops-ref"
          title="Operational Reference"
          icon={BookOpen}
          summary="Ports, env vars, dev quirks. Copy-paste ready."
        >
          <p className="text-sm font-medium mt-2">Ports</p>
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li><code>8080</code> — sx-monolith default bind.</li>
            <li><code>3000</code> — Next.js dashboard (dev + prod).</li>
            <li><code>9090</code> — Prometheus metrics (when <code>prometheus_bind</code> set).</li>
            <li><code>9080</code> + <code>5353</code> — collab DNS/HTTP secondaries (opt-in).</li>
          </ul>

          <p className="text-sm font-medium mt-2">Essential env vars</p>
          <pre className="rounded-sx border border-border bg-muted/30 p-3 text-[11px] font-mono overflow-x-auto">{`SENTINELX_CONFIG=/path/to/config.yaml
SENTINELX__SERVER__BIND_ADDR=127.0.0.1:8080
SENTINELX__DATABASE__ENABLED=false      # use in-memory repos
SENTINELX__REDIS__ENABLED=false
SENTINELX__JWT__SIGNING_KEY=<base64-hs256-32+ bytes>
SENTINELX__BOOTSTRAP__ENABLED=true
SENTINELX__BOOTSTRAP__ADMIN_TENANT_ID=<uuid>
SENTINELX__BOOTSTRAP__ADMIN_EMAIL=admin@sentinelx.dev
SENTINELX__BOOTSTRAP__ADMIN_PASSWORD_PHC=<argon2id PHC>
# Chaos: opt-in, refuses in production
SX_CHAOS_ENABLED=0
APP_ENV=development                     # set to production in prod
RUST_LOG=warn,sx_iam=info`}</pre>

          <p className="text-sm font-medium mt-2">Argon2id PHC generation</p>
          <pre className="rounded-sx border border-border bg-muted/30 p-3 text-[11px] font-mono overflow-x-auto">{`echo -n "devpw2026" | argon2 "TGl0ZXJhbFNhbHQxMjM0" -id -t 2 -m 14 -p 1 -e`}</pre>

          <p className="text-sm font-medium mt-2">Dev login (RBA bypass via XFF)</p>
          <pre className="rounded-sx border border-border bg-muted/30 p-3 text-[11px] font-mono overflow-x-auto">{`curl -X POST http://127.0.0.1:8080/v1/auth/login \\
  -H 'Content-Type: application/json' \\
  -H 'X-Forwarded-For: 8.8.8.8' \\
  -d '{"tenant_id":"01010101-0101-0101-0101-010101010101",
       "email":"admin@sentinelx.dev",
       "password":"devpw2026"}'`}</pre>

          <p className="text-sm font-medium mt-2">Workspace crates (covers P0-P3 backlog)</p>
          <p className="text-xs font-mono text-muted-foreground">
            sx-core · sx-config · sx-telemetry · sx-iam · sx-audit · sx-storage
            · sx-engagement · sx-risk · sx-discovery · sx-api · sx-graph ·
            sx-report · sx-remediation · sx-compliance · sx-bas · sx-chaos ·
            sx-collab · sx-ml · sx-cloud · sx-autonomy · sx-intel-ioc ·
            sx-intel-feeds · sx-secrets · sx-dlp · sx-policy · sx-twin ·
            sx-integrations · sx-mtls · sx-soc · sx-log-ingest · sx-webhooks
            · sx-vuln-ingest · sx-scim · sx-rba · sx-device-trust · sx-soar ·
            sx-plugins · sx-ir-playbooks · sx-runtime · sx-hunt
          </p>

          <p className="text-sm font-medium mt-2">Production runbooks</p>
          <ul className="list-disc pl-5 text-sm space-y-1">
            <li><code>docs/runbooks/multi-region-deployment.md</code> (P2-010) — active-active topology, GeoDNS, Patroni, MRK.</li>
            <li><code>docs/runbooks/disaster-recovery.md</code> (P2-011) — T0/T1/T2 RPO/RTO, PITR, drill template.</li>
            <li><code>docs/runbooks/disaster-recovery-drill-template.md</code> — fill-in-the-blanks operator checklist.</li>
          </ul>
        </Section>

        <footer className="pt-6 border-t border-border text-xs text-muted-foreground space-y-1">
          <p>SentinelX Handbook · Version 1.1 · Last updated 2026-06-14.</p>
          <p>
            Covers P0-001 … P3-010 (46/47 — P3-001 Mobile App excluded by
            scoping). Feedback: file a finding against the <code>handbook</code> asset
            in your tenant, or open an issue on the repo.
          </p>
        </footer>
      </div>
    </div>
  );
}

/** Visual divider for a sidebar module. */
function ModuleHeader({
  id,
  title,
  icon: Icon,
}: {
  id: string;
  title: string;
  icon: React.ComponentType<{ className?: string; "aria-hidden"?: boolean }>;
}) {
  return (
    <div id={id} className="scroll-mt-4 pt-2">
      <div className="flex items-center gap-2 border-b border-border pb-2">
        <Icon className="h-5 w-5 text-accent" aria-hidden />
        <h2 className="text-base font-semibold uppercase tracking-wider">{title}</h2>
      </div>
    </div>
  );
}

function Section({
  id,
  title,
  icon: Icon,
  summary,
  children,
}: {
  id: string;
  title: string;
  icon: React.ComponentType<{ className?: string; "aria-hidden"?: boolean }>;
  summary: string;
  children: React.ReactNode;
}) {
  return (
    <Card id={id} className="scroll-mt-4">
      <CardHeader>
        <div className="flex items-start gap-3">
          <div className="mt-0.5">
            <Icon className="h-5 w-5 text-accent" aria-hidden />
          </div>
          <div className="flex-1">
            <CardTitle className="text-base flex items-center gap-2">
              {title}
              <a
                href={`#${id}`}
                className="text-muted-foreground hover:text-foreground"
                aria-label={`Link to ${title}`}
              >
                <ChevronRight className="h-3 w-3" aria-hidden />
              </a>
            </CardTitle>
            <CardDescription>{summary}</CardDescription>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">{children}</CardContent>
    </Card>
  );
}

function Tip({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-sx border border-accent/40 bg-accent/10 px-3 py-2 text-xs text-accent flex gap-2">
      <span className="font-medium uppercase tracking-wider">tip</span>
      <span className="text-foreground/90">{children}</span>
    </div>
  );
}
