"use client";

import * as React from "react";
import Link from "next/link";
import { signOut } from "next-auth/react";
import { Bell, LogOut, Search, Settings, User, UserCircle } from "lucide-react";

import { cn } from "@/lib/utils";
import { SearchDialog } from "@/components/search-dialog";
import { useCmdk } from "@/hooks/use-cmdk";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

interface TopbarProps {
  title?: string;
  userName?: string | undefined;
  userEmail?: string | undefined;
  notifications?: ReadonlyArray<TopbarNotification>;
}

export interface TopbarNotification {
  id: string;
  title: string;
  timeAgo: string;
  href?: string;
  tone?: "critical" | "warning" | "info";
}

/**
 * The topbar's search trigger uses the platform-appropriate modifier glyph
 * (⌘ on macOS, Ctrl elsewhere) so the hint matches what `useCmdk` listens
 * for. We detect once on mount because `navigator` is unavailable during
 * SSR — the first paint shows the safe fallback ("Ctrl").
 */
function useShortcutHint(): string {
  const [mac, setMac] = React.useState(false);
  React.useEffect(() => {
    if (typeof navigator === "undefined") {
      return;
    }
    setMac(/Mac|iPhone|iPad|iPod/i.test(navigator.platform));
  }, []);
  return mac ? "⌘K" : "Ctrl K";
}

const TONE_DOT: Record<NonNullable<TopbarNotification["tone"]>, string> = {
  critical: "bg-critical",
  warning: "bg-medium",
  info: "bg-info",
};

export function Topbar({
  title = "Dashboard",
  userName,
  userEmail,
  notifications = [],
}: TopbarProps) {
  const { open, setOpen } = useCmdk();
  const hint = useShortcutHint();
  const unreadCount = notifications.length;
  const initials = React.useMemo(() => {
    const source = (userName ?? userEmail ?? "").trim();
    if (source.length === 0) return "";
    const parts = source.split(/\s+/);
    const first = parts[0]?.[0] ?? "";
    const second = parts.length > 1 ? (parts[parts.length - 1]?.[0] ?? "") : "";
    return `${first}${second}`.toUpperCase();
  }, [userName, userEmail]);

  async function handleLogout() {
    await signOut({ callbackUrl: "/login" });
  }

  return (
    <>
      <header
        className={cn(
          "fixed left-sidebar right-0 top-0 z-20 flex h-topbar items-center justify-between border-b border-border bg-background/80 px-6 backdrop-blur",
        )}
      >
        <h1 className="text-sm font-semibold tracking-tight">{title}</h1>
        <div className="flex items-center gap-3 text-muted-foreground">
          <button
            type="button"
            onClick={() => setOpen(true)}
            aria-label="Open global search"
            aria-keyshortcuts="Meta+K Control+K"
            className="flex items-center gap-2 rounded-sx border border-border bg-muted/40 px-2 py-1 text-xs text-muted-foreground transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <Search className="h-3.5 w-3.5" aria-hidden />
            <span>Search…</span>
            <kbd
              aria-hidden
              className="ml-2 rounded border border-border bg-background px-1 font-mono text-[10px] tracking-tight"
            >
              {hint}
            </kbd>
          </button>

          {/* Notifications dropdown */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                aria-label={
                  unreadCount > 0
                    ? `Notifications, ${unreadCount} unread`
                    : "Notifications"
                }
                className="relative rounded-sx p-1 transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                <Bell className="h-4 w-4" aria-hidden />
                {unreadCount > 0 ? (
                  <span
                    aria-hidden
                    className="absolute -right-0.5 -top-0.5 inline-flex h-4 min-w-[1rem] items-center justify-center rounded-full bg-critical px-1 font-mono text-[9px] font-semibold leading-none text-white"
                  >
                    {unreadCount > 9 ? "9+" : unreadCount}
                  </span>
                ) : null}
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-80">
              <DropdownMenuLabel className="flex items-center justify-between">
                <span>Notifications</span>
                {unreadCount > 0 ? (
                  <span className="font-mono text-[10px] normal-case tracking-normal text-muted-foreground">
                    {unreadCount} unread
                  </span>
                ) : null}
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              {notifications.length === 0 ? (
                <div className="px-3 py-6 text-center text-xs text-muted-foreground">
                  You&rsquo;re all caught up.
                </div>
              ) : (
                notifications.slice(0, 5).map((n) => (
                  <DropdownMenuItem key={n.id} asChild>
                    {n.href !== undefined ? (
                      <Link
                        href={n.href}
                        prefetch={false}
                        className="flex items-start gap-2"
                      >
                        <span
                          aria-hidden
                          className={cn(
                            "mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full",
                            TONE_DOT[n.tone ?? "info"],
                          )}
                        />
                        <span className="flex min-w-0 flex-1 flex-col">
                          <span className="truncate text-sm text-foreground">
                            {n.title}
                          </span>
                          <span className="font-mono text-[10px] text-muted-foreground">
                            {n.timeAgo}
                          </span>
                        </span>
                      </Link>
                    ) : (
                      <div className="flex items-start gap-2">
                        <span
                          aria-hidden
                          className={cn(
                            "mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full",
                            TONE_DOT[n.tone ?? "info"],
                          )}
                        />
                        <span className="flex min-w-0 flex-1 flex-col">
                          <span className="truncate text-sm text-foreground">
                            {n.title}
                          </span>
                          <span className="font-mono text-[10px] text-muted-foreground">
                            {n.timeAgo}
                          </span>
                        </span>
                      </div>
                    )}
                  </DropdownMenuItem>
                ))
              )}
              <DropdownMenuSeparator />
              <DropdownMenuItem asChild>
                <Link
                  href="/dashboard/soc"
                  prefetch={false}
                  className="justify-center text-xs text-accent"
                >
                  View all alerts
                </Link>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          {/* Account dropdown */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                aria-label="Account menu"
                className="flex items-center gap-2 rounded-sx p-1 transition-colors hover:bg-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                {initials.length > 0 ? (
                  <span
                    aria-hidden
                    className="grid h-6 w-6 place-items-center rounded-full bg-muted text-[10px] font-semibold text-foreground"
                  >
                    {initials}
                  </span>
                ) : (
                  <UserCircle className="h-5 w-5" aria-hidden />
                )}
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-64">
              <DropdownMenuLabel className="flex flex-col items-start gap-0.5">
                <span className="text-sm font-medium normal-case tracking-normal text-foreground">
                  {userName ?? "Signed in"}
                </span>
                {userEmail !== undefined ? (
                  <span className="font-mono text-[11px] normal-case tracking-normal text-muted-foreground">
                    {userEmail}
                  </span>
                ) : null}
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem asChild>
                <Link href="/dashboard/profile" prefetch={false}>
                  <User className="h-4 w-4" aria-hidden />
                  Profile
                </Link>
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <Link href="/dashboard/settings" prefetch={false}>
                  <Settings className="h-4 w-4" aria-hidden />
                  Settings
                </Link>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onSelect={handleLogout} className="text-critical focus:text-critical">
                <LogOut className="h-4 w-4" aria-hidden />
                Sign out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </header>
      {open ? <SearchDialog open={open} onOpenChange={setOpen} /> : null}
    </>
  );
}
