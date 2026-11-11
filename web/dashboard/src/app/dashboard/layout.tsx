import { auth } from "@/lib/auth";
import { getNavBadges, type NavBadges } from "@/lib/nav-badges";
import { Sidebar } from "@/components/sidebar";
import { Topbar, type TopbarNotification } from "@/components/topbar";

/**
 * Derive a lightweight notification set from the same signals that drive
 * the sidebar badges. Once we ship a dedicated notification store on the
 * backend, swap in a real fetch to `/v1/notifications`.
 */
function deriveNotifications(badges: NavBadges): TopbarNotification[] {
  const notes: TopbarNotification[] = [];
  if ((badges.findingsCritical ?? 0) > 0) {
    notes.push({
      id: "n-critical-findings",
      title: `${badges.findingsCritical} critical finding${badges.findingsCritical === 1 ? "" : "s"} open`,
      timeAgo: "now",
      href: "/dashboard/findings?severity=critical",
      tone: "critical",
    });
  }
  if ((badges.socAlertsOpen ?? 0) > 0) {
    notes.push({
      id: "n-soc-alerts",
      title: `${badges.socAlertsOpen} SOC alert${badges.socAlertsOpen === 1 ? "" : "s"} awaiting triage`,
      timeAgo: "now",
      href: "/dashboard/soc",
      tone: "warning",
    });
  }
  if ((badges.approvalsPending ?? 0) > 0) {
    notes.push({
      id: "n-approvals",
      title: `${badges.approvalsPending} approval${badges.approvalsPending === 1 ? "" : "s"} pending`,
      timeAgo: "now",
      href: "/dashboard/approvals",
      tone: "warning",
    });
  }
  if ((badges.copilotApprovalsPending ?? 0) > 0) {
    notes.push({
      id: "n-copilot",
      title: `${badges.copilotApprovalsPending} copilot action${badges.copilotApprovalsPending === 1 ? "" : "s"} to review`,
      timeAgo: "now",
      href: "/dashboard/copilot-approvals",
      tone: "info",
    });
  }
  return notes;
}

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const session = await auth();
  const permissions = session?.user?.permissions ?? [];
  const token = session?.accessToken;

  const badges: NavBadges = token !== undefined ? await getNavBadges(token) : {};
  const notifications = deriveNotifications(badges);

  const userName = session?.user?.name ?? undefined;
  const userEmail = session?.user?.email ?? undefined;

  return (
    <div className="min-h-screen bg-background text-foreground">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-sx focus:bg-accent focus:px-3 focus:py-2 focus:text-sm focus:text-accent-foreground focus:shadow-lg focus:outline-none"
      >
        Skip to main content
      </a>
      <Sidebar permissions={permissions} badges={badges} />
      <Topbar userName={userName} userEmail={userEmail} notifications={notifications} />
      <main id="main-content" className="ml-sidebar pt-topbar" tabIndex={-1}>
        <div className="p-6">{children}</div>
      </main>
    </div>
  );
}
