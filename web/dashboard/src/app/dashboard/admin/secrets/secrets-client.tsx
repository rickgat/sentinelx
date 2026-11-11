"use client";

import * as React from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { Eye, KeyRound, Loader2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/components/toast";

/**
 * Vault secret browser (client).
 *
 * - Fetches the canned path list once on mount via `/api/admin/secrets/list`.
 * - Groups rows by their Vault mount (the first two path segments, e.g.
 *   `secret/sentinelx`).
 * - Each row exposes a "Reveal" action that opens a Radix Dialog asking the
 *   operator to acknowledge that the reveal will be audit-logged. On confirm
 *   we POST to `/api/admin/secrets/reveal` and display the masked value in
 *   place; the raw value is NEVER routed through `console.*` or any other
 *   logging sink. The reveal is also held only in component state, so a page
 *   reload wipes it.
 */

interface SecretPath {
  /** Full Vault path, e.g. `secret/sentinelx/jwt`. */
  path: string;
  /** Mount + namespace prefix, e.g. `secret/sentinelx`. */
  mount: string;
  /** Trailing leaf segment, e.g. `jwt`. */
  leaf: string;
}

interface ListResponse {
  data?: {
    paths?: ReadonlyArray<string>;
    /**
     * Active envelope-encryption KEK provider, e.g. `disabled`,
     * `aws_kms`, `gcp_kms`, `azure_kv`. Mirrors the snake_case
     * identifiers emitted by
     * `sx_monolith::adapters::secrets::KekKind::as_str` so the label
     * does not need translating between API and UI.
     */
    kek_provider?: string;
  };
  error?: { code?: string; message?: string };
}

/**
 * Human-readable label for the KEK provider identifier returned by the
 * backend. Unknown values fall through to the raw identifier so any
 * provider added later still renders something meaningful.
 */
function renderKekProvider(id: string | undefined): string {
  switch (id) {
    case undefined:
    case "":
    case "disabled":
      return "Disabled (Vault Transit fallback)";
    case "aws_kms":
      return "AWS Key Management Service";
    case "gcp_kms":
      return "GCP Cloud KMS";
    case "azure_kv":
      return "Azure Key Vault";
    default:
      return id;
  }
}

interface RevealResponse {
  data?: {
    value?: string;
  };
  error?: { code?: string; message?: string };
}

function splitPath(path: string): SecretPath {
  const parts = path.split("/");
  if (parts.length <= 2) {
    return { path, mount: path, leaf: path };
  }
  const leaf = parts[parts.length - 1] ?? path;
  const mount = parts.slice(0, 2).join("/");
  return { path, mount, leaf };
}

function groupByMount(
  paths: ReadonlyArray<SecretPath>,
): ReadonlyArray<{ mount: string; rows: ReadonlyArray<SecretPath> }> {
  const map = new Map<string, SecretPath[]>();
  for (const p of paths) {
    const bucket = map.get(p.mount);
    if (bucket === undefined) {
      map.set(p.mount, [p]);
    } else {
      bucket.push(p);
    }
  }
  return Array.from(map.entries()).map(([mount, rows]) => ({ mount, rows }));
}

export function SecretsClient() {
  const toast = useToast();
  const [paths, setPaths] = React.useState<ReadonlyArray<SecretPath>>([]);
  const [loading, setLoading] = React.useState(true);
  const [loadError, setLoadError] = React.useState<string | null>(null);
  // Revealed values indexed by path. Held only in memory; never logged.
  const [revealed, setRevealed] = React.useState<Readonly<Record<string, string>>>({});
  const [pendingReveal, setPendingReveal] = React.useState<string | null>(null);
  const [revealing, setRevealing] = React.useState(false);
  const [kekProvider, setKekProvider] = React.useState<string | undefined>(undefined);

  React.useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const res = await fetch("/api/admin/secrets/list", { cache: "no-store" });
        const parsed: ListResponse = await res.json().catch(() => ({}));
        if (cancelled) {
          return;
        }
        if (!res.ok) {
          setLoadError(parsed.error?.message ?? `List failed (${res.status})`);
          return;
        }
        const rawPaths = parsed.data?.paths ?? [];
        setPaths(rawPaths.map(splitPath));
        setKekProvider(parsed.data?.kek_provider);
      } catch {
        if (!cancelled) {
          setLoadError("Network error — please refresh.");
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  async function confirmReveal() {
    if (pendingReveal === null) {
      return;
    }
    const targetPath = pendingReveal;
    setRevealing(true);
    try {
      const res = await fetch("/api/admin/secrets/reveal", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path: targetPath }),
      });
      const parsed: RevealResponse = await res.json().catch(() => ({}));
      if (!res.ok) {
        toast.push({
          kind: "error",
          message: parsed.error?.message ?? `Reveal failed (${res.status})`,
        });
        return;
      }
      const value = parsed.data?.value;
      if (typeof value !== "string" || value.length === 0) {
        toast.push({ kind: "error", message: "Backend returned an empty value." });
        return;
      }
      // Important: do NOT log `value` anywhere. Hold only in state.
      setRevealed((current) => ({ ...current, [targetPath]: value }));
      toast.push({ kind: "success", message: "Reveal recorded in audit log." });
      setPendingReveal(null);
    } catch {
      toast.push({ kind: "error", message: "Network error — please retry." });
    } finally {
      setRevealing(false);
    }
  }

  const grouped = React.useMemo(() => groupByMount(paths), [paths]);

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-accent" aria-hidden />
            Vault Secrets
          </CardTitle>
          <CardDescription>
            Browse the secrets the SentinelX platform proxies through Vault.
            Reveals are audit-logged; values are held in memory only and
            cleared on reload.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div
            data-testid="kek-provider-banner"
            className="mb-4 rounded-sx border border-border bg-muted/40 px-3 py-2 text-xs text-muted-foreground"
          >
            <span className="font-medium text-foreground">Envelope KEK provider:</span>{" "}
            <span data-testid="kek-provider-value">
              {renderKekProvider(kekProvider)}
            </span>
          </div>
          {loading ? (
            <div className="flex items-center gap-2 py-8 text-xs text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
              Loading secret paths…
            </div>
          ) : loadError !== null ? (
            <p role="alert" className="text-xs text-critical">
              {loadError}
            </p>
          ) : paths.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              No secrets are currently registered.
            </p>
          ) : (
            <div className="space-y-6">
              {grouped.map((group) => (
                <section key={group.mount} className="space-y-2">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                    {group.mount}
                  </h4>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-1/3">Path</TableHead>
                        <TableHead>Value</TableHead>
                        <TableHead className="w-32 text-right">Actions</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {group.rows.map((row) => {
                        const value = revealed[row.path];
                        return (
                          <TableRow key={row.path}>
                            <TableCell className="font-mono text-xs">
                              {row.path}
                            </TableCell>
                            <TableCell className="font-mono text-xs">
                              {value === undefined ? (
                                <span className="text-muted-foreground">••••••••</span>
                              ) : (
                                <span className="break-all text-foreground">{value}</span>
                              )}
                            </TableCell>
                            <TableCell className="text-right">
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => setPendingReveal(row.path)}
                                disabled={value !== undefined}
                              >
                                <Eye className="h-3.5 w-3.5" aria-hidden />
                                {value === undefined ? "Reveal" : "Revealed"}
                              </Button>
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                </section>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog.Root
        open={pendingReveal !== null}
        onOpenChange={(next) => {
          if (!next) {
            setPendingReveal(null);
          }
        }}
      >
        <Dialog.Portal>
          <Dialog.Overlay className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm" />
          <Dialog.Content
            className="fixed left-1/2 top-1/2 z-50 w-full max-w-md -translate-x-1/2 -translate-y-1/2 rounded-sx border border-border bg-card p-6 shadow-xl"
            aria-describedby="reveal-desc"
          >
            <Dialog.Title className="text-base font-semibold text-foreground">
              Reveal secret
            </Dialog.Title>
            <Dialog.Description
              id="reveal-desc"
              className="mt-1 text-xs text-muted-foreground"
            >
              This action will be recorded in the audit log. Proceed?
            </Dialog.Description>
            {pendingReveal !== null ? (
              <p className="mt-3 break-all rounded-sx border border-border bg-muted/50 px-3 py-2 font-mono text-xs text-foreground">
                {pendingReveal}
              </p>
            ) : null}
            <div className="mt-6 flex justify-end gap-2">
              <Dialog.Close asChild>
                <Button variant="outline" disabled={revealing}>
                  Cancel
                </Button>
              </Dialog.Close>
              <Button onClick={confirmReveal} disabled={revealing}>
                {revealing ? "Revealing…" : "Reveal"}
              </Button>
            </div>
          </Dialog.Content>
        </Dialog.Portal>
      </Dialog.Root>
    </div>
  );
}
