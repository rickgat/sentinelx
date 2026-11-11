"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { signOut } from "next-auth/react";
import { useState } from "react";
import {
  ShieldCheck,
  LayoutDashboard,
  ClipboardList,
  AlertTriangle,
  ShieldAlert,
  ShieldHalf,
  ClipboardCheck,
  Network,
  Crosshair,
  Bug,
  Users,
  LogOut,
  FileBarChart,
  Palette,
  Siren,
  Building2,
  Cloud,
  MessageSquareCode,
  KeyRound,
  FolderArchive,
  Library,
  BookOpen,
  Send,
  Target,
  TrendingUp,
  GraduationCap,
  ScrollText,
  FileUp,
  UsersRound,
  CheckCircle2,
  UserCheck,
  Laptop,
  ChevronDown,
  Compass,
  Sword,
  Eye,
  Fingerprint,
  Gavel,
  Bot,
  Code2,
  HelpCircle,
} from "lucide-react";

import { cn } from "@/lib/utils";
import { hasPermission } from "@/lib/permissions";
import type { NavBadges } from "@/lib/nav-badges";

type BadgeTone = "critical" | "warning" | "info";

interface NavItem {
  href: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  requiresPermission?: string;
  badgeKey?: keyof NavBadges;
  badgeTone?: BadgeTone;
}

interface NavModule {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
  items: ReadonlyArray<NavItem>;
}

/**
 * Menu organised into 8 process-flow modules. Each module groups menus
 * that operators reach for during the same phase of the security workflow.
 */
const MODULES: ReadonlyArray<NavModule> = [
  {
    id: "operations",
    label: "Operations",
    icon: Compass,
    description: "Daily landing, alerts, approvals, kill switch",
    items: [
      { href: "/dashboard", label: "Overview", icon: LayoutDashboard },
      { href: "/dashboard/reporting", label: "Comprehensive Report", icon: FileBarChart },
      { href: "/dashboard/soc", label: "SOC Alerts", icon: Siren, badgeKey: "socAlertsOpen", badgeTone: "critical" },
      { href: "/dashboard/approvals", label: "Approvals", icon: ShieldCheck, badgeKey: "approvalsPending", badgeTone: "warning" },
      { href: "/dashboard/copilot-approvals", label: "Copilot Approvals", icon: ClipboardCheck, badgeKey: "copilotApprovalsPending", badgeTone: "warning" },
      { href: "/dashboard/safety", label: "Safety / Kill-switch", icon: ShieldAlert },
    ],
  },
  {
    id: "engagement",
    label: "Engagement & Findings",
    icon: ClipboardList,
    description: "Pentest engagements, findings triage, remediation, reports",
    items: [
      { href: "/dashboard/engagements", label: "Engagements", icon: ClipboardList },
      { href: "/dashboard/findings", label: "Findings", icon: AlertTriangle, badgeKey: "findingsCritical", badgeTone: "critical" },
      { href: "/dashboard/remediation", label: "Remediation", icon: CheckCircle2 },
      { href: "/dashboard/reports", label: "Reports", icon: FileBarChart },
      { href: "/dashboard/branding", label: "Report Branding", icon: Palette, requiresPermission: "report:read" },
      { href: "/dashboard/copilot", label: "Copilot", icon: MessageSquareCode },
    ],
  },
  {
    id: "discovery",
    label: "Discovery & Inventory",
    icon: ShieldAlert,
    description: "Asset & vuln intake, cloud inventory, logs, tenants",
    items: [
      { href: "/dashboard/scans", label: "Scans", icon: ShieldAlert },
      { href: "/dashboard/vuln-import", label: "Vuln Import", icon: FileUp },
      { href: "/dashboard/cloud", label: "Cloud Inventory", icon: Cloud },
      { href: "/dashboard/logs", label: "Logs (OCSF)", icon: ScrollText },
      { href: "/dashboard/tenants", label: "Tenants", icon: Building2 },
    ],
  },
  {
    id: "offensive",
    label: "Offensive Simulation",
    icon: Sword,
    description: "BAS, red team, graphs, blast radius, digital twin",
    items: [
      { href: "/dashboard/pentest", label: "Pentest", icon: Bug, requiresPermission: "pentest:read" },
      { href: "/dashboard/bas", label: "BAS Runs", icon: Crosshair },
      { href: "/dashboard/bas/techniques", label: "Techniques", icon: Library },
      { href: "/dashboard/redteam", label: "Red Team", icon: Sword },
      { href: "/dashboard/graph", label: "Attack Graph", icon: Network },
      { href: "/dashboard/blast-radius", label: "Blast Radius", icon: Target },
      { href: "/dashboard/twin", label: "Digital Twin", icon: Network },
    ],
  },
  {
    id: "detection",
    label: "Detection & Behavior",
    icon: Eye,
    description: "UEBA, device posture, risk analytics",
    items: [
      { href: "/dashboard/ueba", label: "UEBA", icon: UserCheck },
      { href: "/dashboard/device-trust", label: "Device Trust", icon: Laptop },
      { href: "/dashboard/analytics", label: "Risk Analytics", icon: TrendingUp },
    ],
  },
  {
    id: "iam",
    label: "Identity & Access",
    icon: Fingerprint,
    description: "Users, roles, MFA, adaptive auth, secrets",
    items: [
      { href: "/dashboard/iam", label: "IAM (Users & Roles)", icon: Users, requiresPermission: "admin:users" },
      { href: "/dashboard/scim", label: "SCIM Provisioning", icon: UsersRound, requiresPermission: "admin:users" },
      { href: "/dashboard/mfa", label: "MFA", icon: KeyRound },
      { href: "/dashboard/rba", label: "Adaptive Auth (RBA)", icon: ShieldHalf, requiresPermission: "admin:users" },
      { href: "/dashboard/admin/secrets", label: "Secrets / KMS", icon: KeyRound, requiresPermission: "admin:secrets" },
    ],
  },
  {
    id: "governance",
    label: "Compliance & Governance",
    icon: Gavel,
    description: "Controls, evidence bundles, audit chain",
    items: [
      { href: "/dashboard/compliance", label: "Controls", icon: ClipboardCheck },
      { href: "/dashboard/compliance/evidence", label: "Evidence Bundles", icon: FolderArchive },
      { href: "/dashboard/ai-audit", label: "AI Security Audit", icon: Bot, requiresPermission: "ai_audit:read" },
    ],
  },
  {
    id: "developer",
    label: "Developer & Docs",
    icon: Code2,
    description: "Handbook, API reference, playground",
    items: [
      { href: "/dashboard/handbook", label: "Handbook", icon: GraduationCap },
      { href: "/dashboard/api-docs", label: "API Docs", icon: BookOpen },
      { href: "/dashboard/api-playground", label: "API Playground", icon: Send },
    ],
  },
];

interface SidebarProps {
  permissions?: ReadonlyArray<string>;
  badges?: NavBadges;
}

const BADGE_TONE_CLASSES: Record<BadgeTone, string> = {
  critical: "bg-critical/15 text-critical border-critical/40",
  warning: "bg-medium/15 text-medium border-medium/40",
  info: "bg-info/15 text-info border-info/40",
};

function NavBadge({ count, tone }: { count: number; tone: BadgeTone }) {
  const label = count > 99 ? "99+" : String(count);
  return (
    <span
      className={cn(
        "ml-auto inline-flex min-w-[1.375rem] items-center justify-center rounded-full border px-1.5 py-px",
        "font-mono text-[10px] font-semibold leading-none tabular-nums",
        BADGE_TONE_CLASSES[tone],
      )}
      aria-label={`${count} pending`}
    >
      {label}
    </span>
  );
}

export function Sidebar({ permissions = [], badges = {} }: SidebarProps) {
  const pathname = usePathname();
  const [openModules, setOpenModules] = useState<Set<string>>(() => {
    // Lazy initializer: runs ONCE on first mount. Auto-expands module
    // that owns the current route + Operations as default landing.
    const open = new Set<string>();
    for (const m of MODULES) {
      if (m.items.some((i) => pathname === i.href || pathname.startsWith(`${i.href}/`))) {
        open.add(m.id);
      }
    }
    open.add("operations");
    return open;
  });

  const toggle = (id: string) =>
    setOpenModules((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  async function handleLogout() {
    await signOut({ callbackUrl: "/login" });
  }

  const visibleModules = MODULES
    .map((m) => ({
      ...m,
      items: m.items.filter(
        (item) => item.requiresPermission === undefined || hasPermission(permissions, item.requiresPermission),
      ),
    }))
    .filter((m) => m.items.length > 0);

  return (
    <aside
      className={cn(
        "fixed left-0 top-0 z-30 flex h-screen w-sidebar flex-col border-r border-border bg-card",
      )}
    >
      <div className="flex h-topbar items-center gap-2 border-b border-border px-4 shrink-0">
        <ShieldCheck className="h-5 w-5 text-accent" aria-hidden />
        <span className="text-sm font-semibold tracking-tight">SentinelX</span>
      </div>

      {/* Scrollable nav region — fixes the "sidebar can't scroll" bug. */}
      <nav
        className="flex-1 overflow-y-auto overflow-x-hidden px-2 py-3 space-y-2"
        aria-label="Main navigation"
      >
        {visibleModules.map((m) => {
          const ModIcon = m.icon;
          const open = openModules.has(m.id);
          const headerId = `mod-${m.id}-header`;
          const listId = `mod-${m.id}-list`;
          return (
            <section key={m.id} className="rounded-sx">
              <button
                type="button"
                id={headerId}
                onClick={() => toggle(m.id)}
                aria-expanded={open}
                aria-controls={listId}
                className={cn(
                  "flex w-full items-center justify-between gap-2 rounded-sx px-2 py-1.5",
                  "text-[11px] font-semibold uppercase tracking-wider text-muted-foreground",
                  "hover:bg-muted hover:text-foreground transition-colors",
                )}
                title={m.description}
              >
                <span className="flex items-center gap-2">
                  <ModIcon className="h-3.5 w-3.5 opacity-80" aria-hidden />
                  {m.label}
                </span>
                <ChevronDown
                  className={cn(
                    "h-3.5 w-3.5 transition-transform",
                    open ? "rotate-0" : "-rotate-90",
                  )}
                  aria-hidden
                />
              </button>
              {open && (
                <ul id={listId} role="group" aria-labelledby={headerId} className="mt-1 space-y-0.5">
                  {m.items.map((item) => {
                    const Icon = item.icon;
                    const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
                    const badgeCount = item.badgeKey !== undefined ? badges[item.badgeKey] : undefined;
                    const showBadge = badgeCount !== undefined && badgeCount > 0;
                    return (
                      <li key={item.href}>
                        <Link
                          href={item.href}
                          prefetch={false}
                          aria-current={active ? "page" : undefined}
                          className={cn(
                            "flex items-center gap-2 rounded-sx pl-7 pr-2 py-1.5 text-sm transition-colors",
                            active
                              ? "bg-muted text-foreground"
                              : "text-muted-foreground hover:bg-muted hover:text-foreground",
                          )}
                        >
                          <Icon className="h-4 w-4 shrink-0" aria-hidden />
                          <span className="truncate">{item.label}</span>
                          {showBadge ? (
                            <NavBadge
                              count={badgeCount}
                              tone={item.badgeTone ?? "info"}
                            />
                          ) : null}
                        </Link>
                      </li>
                    );
                  })}
                </ul>
              )}
            </section>
          );
        })}
      </nav>

      <div className="border-t border-border p-2 shrink-0 space-y-1">
        <Link
          href="/dashboard/help"
          prefetch={false}
          aria-current={
            pathname === "/dashboard/help" || pathname.startsWith("/dashboard/help/")
              ? "page"
              : undefined
          }
          className={cn(
            "flex items-center gap-2 rounded-sx px-3 py-2 text-sm transition-colors",
            pathname === "/dashboard/help" || pathname.startsWith("/dashboard/help/")
              ? "bg-muted text-foreground"
              : "text-muted-foreground hover:bg-muted hover:text-foreground",
          )}
        >
          <HelpCircle className="h-4 w-4" aria-hidden />
          <span>Help</span>
        </Link>
        <button
          type="button"
          onClick={handleLogout}
          className="flex w-full items-center gap-2 rounded-sx px-3 py-2 text-sm text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
        >
          <LogOut className="h-4 w-4" aria-hidden />
          <span>Logout</span>
        </button>
      </div>
    </aside>
  );
}
