"use client";

import * as React from "react";
import Link from "next/link";
import {
  Rocket,
  ClipboardList,
  Compass,
  Fingerprint,
  Siren,
  Sword,
  Gavel,
  Send,
  ArrowRight,
  Search,
  Sparkles,
  HelpCircle,
} from "lucide-react";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";

import { HELP_CATEGORIES } from "./help-categories";

const ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  Rocket,
  ClipboardList,
  Compass,
  Fingerprint,
  Siren,
  Sword,
  Gavel,
  Send,
};

/**
 * Help index — the "front door" for self-service onboarding.
 *
 * Two interactive affordances live on this page:
 *   1. A quick-start featured card pinning the most common "first day"
 *      tutorial.
 *   2. A search input that filters the 8 category cards by string match
 *      against title + summary. Filtering is purely client-side because
 *      the card set is small and the input is debounce-free.
 */
export function HelpIndexClient() {
  const [query, setQuery] = React.useState("");
  const normalised = query.trim().toLowerCase();
  const filtered = HELP_CATEGORIES.filter((c) => {
    if (c.slug === "getting-started") return false; // pinned separately
    if (normalised === "") return true;
    return (
      c.title.toLowerCase().includes(normalised) ||
      c.summary.toLowerCase().includes(normalised)
    );
  });

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="space-y-1">
          <CardTitle className="flex items-center gap-2 text-base">
            <HelpCircle className="h-4 w-4 text-accent" aria-hidden />
            Help and tutorials
          </CardTitle>
          <CardDescription className="text-sm">
            Self-serve onboarding for analysts, admins, and auditors. Each
            category groups the dashboard menus that solve a single phase of
            the workflow. The Handbook covers process and policy; this section
            covers per-menu how-to.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <label htmlFor="help-search" className="sr-only">
            Search Help categories
          </label>
          <div className="relative">
            <Search
              className="pointer-events-none absolute left-2 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
              aria-hidden
            />
            <Input
              id="help-search"
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search categories (e.g. findings, MFA, SARIF, Jira) …"
              className="pl-8"
            />
          </div>
        </CardContent>
      </Card>

      <QuickStartCard />

      <div>
        <h2 className="mb-2 text-xs font-semibold uppercase tracking-wider text-muted-foreground">
          Browse by category
        </h2>
        {filtered.length === 0 ? (
          <Card>
            <CardContent className="py-6 text-center text-sm text-muted-foreground">
              No categories match &ldquo;{query}&rdquo;. Try a broader term —
              every dashboard menu is covered in one of the eight categories.
            </CardContent>
          </Card>
        ) : (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {filtered.map((c) => {
              const Icon = ICONS[c.icon] ?? HelpCircle;
              return (
                <Link
                  key={c.slug}
                  href={`/dashboard/help/${c.slug}`}
                  prefetch={false}
                  className="group"
                >
                  <Card className="h-full transition-colors hover:bg-muted/40">
                    <CardHeader className="space-y-2">
                      <div className="flex items-center gap-2">
                        <Icon className="h-4 w-4 text-accent" aria-hidden />
                        <CardTitle className="text-sm">{c.title}</CardTitle>
                      </div>
                      <CardDescription className="text-xs">
                        {c.summary}
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <span className="inline-flex items-center gap-1 text-xs font-medium text-accent transition-colors group-hover:underline">
                        Explore
                        <ArrowRight className="h-3 w-3" aria-hidden />
                      </span>
                    </CardContent>
                  </Card>
                </Link>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function QuickStartCard() {
  return (
    <Link href="/dashboard/help/getting-started" prefetch={false} className="block">
      <Card className="border-accent/40 bg-card transition-colors hover:bg-muted/40">
        <CardHeader>
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-accent" aria-hidden />
            <CardTitle className="text-sm">Quick start (5 minutes)</CardTitle>
          </div>
          <CardDescription className="text-xs">
            Log in, run your first HTTP header scan, triage the findings,
            export a SARIF bundle. The minimum loop that proves the platform
            works for your tenant.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <span className="inline-flex items-center gap-1 text-xs font-medium text-accent">
            Start here
            <ArrowRight className="h-3 w-3" aria-hidden />
          </span>
        </CardContent>
      </Card>
    </Link>
  );
}
