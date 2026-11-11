"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import * as Dialog from "@radix-ui/react-dialog";
import { Search, ClipboardList, AlertTriangle, Box } from "lucide-react";

import { cn } from "@/lib/utils";
import type { Asset, Engagement, Finding, Page } from "@/lib/types";

/**
 * Global command-palette style search dialog.
 *
 * Loads engagements / findings / assets on first open via three parallel
 * client-side fetches (each capped at 200 rows), then filters locally as
 * the user types. The input is debounced 150 ms so cheap keystrokes
 * don't thrash the filter pass.
 *
 * Keyboard model:
 *  • Up / Down — move the active option
 *  • Enter    — navigate to the active option
 *  • Esc      — close (Radix-built-in)
 *
 * Accessibility follows the WAI-ARIA combobox + listbox pattern:
 * the input owns `role="combobox"` with `aria-controls`, `aria-expanded`,
 * `aria-activedescendant`. Each result option carries `role="option"` and
 * a stable id so screen readers track the active row.
 */

interface SearchDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

type ResultKind = "engagement" | "finding" | "asset";

interface SearchResult {
  kind: ResultKind;
  id: string;
  primary: string;
  secondary: string;
  href: string;
}

interface ResultGroup {
  kind: ResultKind;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  results: ReadonlyArray<SearchResult>;
}

interface Envelope<T> {
  data?: T;
}

const LIST_ID = "cmdk-results";
const MAX_PER_GROUP = 10;
const DEBOUNCE_MS = 150;

function optionId(kind: ResultKind, id: string): string {
  return `cmdk-opt-${kind}-${id}`;
}

async function fetchPage<T>(path: string): Promise<ReadonlyArray<T>> {
  const res = await fetch(path, { cache: "no-store" });
  if (!res.ok) {
    return [];
  }
  const body = (await res.json().catch(() => ({}))) as Envelope<Page<T>>;
  return body.data?.items ?? [];
}

function matches(haystack: string, needle: string): boolean {
  return haystack.toLowerCase().includes(needle);
}

function buildGroups(
  engagements: ReadonlyArray<Engagement>,
  findings: ReadonlyArray<Finding>,
  assets: ReadonlyArray<Asset>,
  query: string,
): ReadonlyArray<ResultGroup> {
  const q = query.trim().toLowerCase();

  const engagementResults: SearchResult[] = [];
  for (const e of engagements) {
    if (q.length === 0 || matches(e.name, q) || matches(e.id, q)) {
      engagementResults.push({
        kind: "engagement",
        id: e.id,
        primary: e.name,
        secondary: e.status,
        href: `/dashboard/engagements/${e.id}`,
      });
      if (engagementResults.length >= MAX_PER_GROUP) break;
    }
  }

  const findingResults: SearchResult[] = [];
  for (const f of findings) {
    if (q.length === 0 || matches(f.title, q) || matches(f.id, q)) {
      findingResults.push({
        kind: "finding",
        id: f.id,
        primary: f.title,
        secondary: `${f.severity} · ${f.status}`,
        href: `/dashboard/findings/${f.id}`,
      });
      if (findingResults.length >= MAX_PER_GROUP) break;
    }
  }

  const assetResults: SearchResult[] = [];
  for (const a of assets) {
    if (q.length === 0 || matches(a.identifier, q) || matches(a.id, q)) {
      assetResults.push({
        kind: "asset",
        id: a.id,
        primary: a.identifier,
        secondary: a.kind,
        href: `/dashboard/assets/${a.id}`,
      });
      if (assetResults.length >= MAX_PER_GROUP) break;
    }
  }

  return [
    { kind: "engagement", label: "Engagements", icon: ClipboardList, results: engagementResults },
    { kind: "finding", label: "Findings", icon: AlertTriangle, results: findingResults },
    { kind: "asset", label: "Assets", icon: Box, results: assetResults },
  ];
}

function flatten(groups: ReadonlyArray<ResultGroup>): ReadonlyArray<SearchResult> {
  const out: SearchResult[] = [];
  for (const g of groups) {
    for (const r of g.results) {
      out.push(r);
    }
  }
  return out;
}

export function SearchDialog({ open, onOpenChange }: SearchDialogProps): React.ReactElement {
  const router = useRouter();
  const [query, setQuery] = React.useState("");
  const [debounced, setDebounced] = React.useState("");
  const [engagements, setEngagements] = React.useState<ReadonlyArray<Engagement>>([]);
  const [findings, setFindings] = React.useState<ReadonlyArray<Finding>>([]);
  const [assets, setAssets] = React.useState<ReadonlyArray<Asset>>([]);
  const [loading, setLoading] = React.useState(false);
  const [loaded, setLoaded] = React.useState(false);
  const [errored, setErrored] = React.useState(false);
  const [activeIndex, setActiveIndex] = React.useState(0);
  const listRef = React.useRef<HTMLDivElement>(null);

  // Debounce the query → debounced filter token.
  React.useEffect(() => {
    const t = window.setTimeout(() => setDebounced(query), DEBOUNCE_MS);
    return () => window.clearTimeout(t);
  }, [query]);

  // Reset transient state on close.
  React.useEffect(() => {
    if (!open) {
      setQuery("");
      setDebounced("");
      setActiveIndex(0);
    }
  }, [open]);

  // Lazy-load all three lists in parallel the first time the dialog opens.
  React.useEffect(() => {
    if (!open || loaded || loading) {
      return;
    }
    let cancelled = false;
    setLoading(true);
    setErrored(false);
    Promise.all([
      fetchPage<Engagement>("/api/engagements?limit=200"),
      fetchPage<Finding>("/api/findings?limit=200"),
      fetchPage<Asset>("/api/assets?limit=200"),
    ])
      .then(([eng, fnd, ast]) => {
        if (cancelled) return;
        setEngagements(eng);
        setFindings(fnd);
        setAssets(ast);
        setLoaded(true);
      })
      .catch(() => {
        if (cancelled) return;
        setErrored(true);
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, loaded, loading]);

  const groups = React.useMemo(
    () => buildGroups(engagements, findings, assets, debounced),
    [engagements, findings, assets, debounced],
  );
  const flat = React.useMemo(() => flatten(groups), [groups]);

  // Clamp the active index whenever the result set changes.
  React.useEffect(() => {
    if (flat.length === 0) {
      setActiveIndex(0);
      return;
    }
    setActiveIndex((prev) => (prev >= flat.length ? 0 : prev));
  }, [flat]);

  const active = flat[activeIndex];

  // Keep the active option scrolled into view.
  React.useEffect(() => {
    if (active === undefined || listRef.current === null) {
      return;
    }
    const el = listRef.current.querySelector<HTMLElement>(
      `#${CSS.escape(optionId(active.kind, active.id))}`,
    );
    if (el !== null) {
      el.scrollIntoView({ block: "nearest" });
    }
  }, [active]);

  function navigate(result: SearchResult) {
    onOpenChange(false);
    router.push(result.href);
  }

  function handleKeyDown(event: React.KeyboardEvent<HTMLInputElement>) {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      if (flat.length === 0) return;
      setActiveIndex((prev) => (prev + 1) % flat.length);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      if (flat.length === 0) return;
      setActiveIndex((prev) => (prev - 1 + flat.length) % flat.length);
    } else if (event.key === "Enter") {
      event.preventDefault();
      if (active !== undefined) {
        navigate(active);
      }
    }
  }

  const activeId = active !== undefined ? optionId(active.kind, active.id) : undefined;
  const hasAnyResults = flat.length > 0;

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm" />
        <Dialog.Content
          className="fixed left-1/2 top-[15%] z-50 w-full max-w-xl -translate-x-1/2 overflow-hidden rounded-sx border border-border bg-card shadow-xl"
          aria-describedby="cmdk-desc"
        >
          <Dialog.Title className="sr-only">Search</Dialog.Title>
          <Dialog.Description id="cmdk-desc" className="sr-only">
            Search engagements, findings, and assets. Use the up and down arrow keys to navigate
            results and press Enter to open.
          </Dialog.Description>

          <div className="flex items-center gap-2 border-b border-border px-3">
            <Search className="h-4 w-4 text-muted-foreground" aria-hidden />
            <input
              type="text"
              role="combobox"
              aria-expanded
              aria-controls={LIST_ID}
              aria-autocomplete="list"
              {...(activeId !== undefined ? { "aria-activedescendant": activeId } : {})}
              placeholder="Search engagements, findings, assets…"
              value={query}
              onChange={(event) => setQuery(event.currentTarget.value)}
              onKeyDown={handleKeyDown}
              autoFocus
              className="h-11 w-full bg-transparent text-sm text-foreground placeholder:text-muted-foreground focus:outline-none"
            />
          </div>

          <div
            ref={listRef}
            id={LIST_ID}
            role="listbox"
            aria-label="Search results"
            className="max-h-[60vh] overflow-y-auto py-2"
          >
            {loading && !loaded ? (
              <p className="px-4 py-6 text-center text-xs text-muted-foreground">Loading…</p>
            ) : null}
            {errored ? (
              <p className="px-4 py-6 text-center text-xs text-critical" role="alert">
                Search index unavailable — please retry.
              </p>
            ) : null}
            {!loading && loaded && !hasAnyResults ? (
              <p className="px-4 py-6 text-center text-xs text-muted-foreground">No results.</p>
            ) : null}

            {groups.map((group) =>
              group.results.length === 0 ? null : (
                <div key={group.kind} className="px-2 pb-2">
                  <div
                    className="px-2 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground"
                    aria-hidden
                  >
                    {group.label}
                  </div>
                  <ul className="space-y-0.5">
                    {group.results.map((r) => {
                      const isActive = active?.kind === r.kind && active.id === r.id;
                      const Icon = group.icon;
                      return (
                        <li key={r.id}>
                          <button
                            type="button"
                            id={optionId(r.kind, r.id)}
                            role="option"
                            aria-selected={isActive}
                            tabIndex={-1}
                            onMouseEnter={() => {
                              const idx = flat.findIndex(
                                (x) => x.kind === r.kind && x.id === r.id,
                              );
                              if (idx >= 0) {
                                setActiveIndex(idx);
                              }
                            }}
                            onClick={() => navigate(r)}
                            className={cn(
                              "flex w-full items-center gap-2 rounded-sx px-2 py-1.5 text-left text-sm",
                              isActive
                                ? "bg-muted text-foreground"
                                : "text-muted-foreground hover:bg-muted hover:text-foreground",
                            )}
                          >
                            <Icon className="h-4 w-4 shrink-0" aria-hidden />
                            <span className="truncate text-foreground">{r.primary}</span>
                            <span className="ml-auto truncate pl-2 text-xs text-muted-foreground">
                              {r.secondary}
                            </span>
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              ),
            )}
          </div>

          <div className="flex items-center justify-between border-t border-border px-3 py-2 text-[10px] text-muted-foreground">
            <span>
              <kbd className="rounded border border-border px-1">↑</kbd>{" "}
              <kbd className="rounded border border-border px-1">↓</kbd> navigate
            </span>
            <span>
              <kbd className="rounded border border-border px-1">↵</kbd> open
              <span className="px-1">·</span>
              <kbd className="rounded border border-border px-1">esc</kbd> close
            </span>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
