"use client";

import * as React from "react";
import { Building2 } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/components/toast";

export interface TenantSummaryView {
  id: string;
  name: string;
  slug: string;
  is_active: boolean;
}

const STORAGE_KEY = "sx.activeTenant";

interface Props {
  current: TenantSummaryView | null;
  apiAvailable: boolean;
}

export function TenantsClient({ current, apiAvailable }: Props) {
  const toast = useToast();
  const [override, setOverride] = React.useState<string | null>(null);
  const [draft, setDraft] = React.useState("");

  React.useEffect(() => {
    try {
      const stored = window.sessionStorage.getItem(STORAGE_KEY);
      if (stored !== null && stored.length > 0) {
        setOverride(stored);
      }
    } catch {
      // sessionStorage may be unavailable (e.g. SSR rehydrate in private mode);
      // we surface the active tenant only.
    }
  }, []);

  function switchTenant() {
    const id = draft.trim();
    if (id.length === 0) {
      toast.push({ kind: "error", message: "Tenant id is required." });
      return;
    }
    try {
      window.sessionStorage.setItem(STORAGE_KEY, id);
    } catch {
      toast.push({
        kind: "error",
        message: "sessionStorage is unavailable in this browser.",
      });
      return;
    }
    toast.push({
      kind: "success",
      message: "Active tenant updated. Reloading…",
    });
    window.setTimeout(() => {
      window.location.reload();
    }, 300);
  }

  function clearOverride() {
    try {
      window.sessionStorage.removeItem(STORAGE_KEY);
    } catch {
      // Ignored — the toast still tells the user we tried.
    }
    setOverride(null);
    toast.push({ kind: "success", message: "Override cleared. Reloading…" });
    window.setTimeout(() => {
      window.location.reload();
    }, 300);
  }

  return (
    <div className="max-w-2xl space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Building2 className="h-4 w-4 text-accent" aria-hidden />
            Tenants
          </CardTitle>
          <CardDescription>
            The active tenant determines which scopes, findings, and reports the
            dashboard renders.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {!apiAvailable ? (
            <div
              role="alert"
              className="rounded-sx border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical"
            >
              API unavailable — current tenant could not be resolved.
            </div>
          ) : null}
          {current !== null ? (
            <div className="rounded-sx border border-border bg-background/40 px-3 py-3">
              <div className="flex items-center justify-between gap-2">
                <div>
                  <p className="text-sm font-semibold text-foreground">
                    {current.name}
                  </p>
                  <p className="text-xs text-muted-foreground font-mono">
                    {current.slug} · {current.id}
                  </p>
                </div>
                <Badge variant={current.is_active ? "success" : "outline"}>
                  {current.is_active ? "active" : "inactive"}
                </Badge>
              </div>
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">
              No current tenant available.
            </p>
          )}
          {override !== null ? (
            <div className="flex items-center justify-between rounded-sx border border-medium/40 bg-medium/10 px-3 py-2 text-xs text-medium">
              <span>
                Session override: <code className="font-mono">{override}</code>
              </span>
              <Button size="sm" variant="outline" onClick={clearOverride}>
                Clear
              </Button>
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Switch tenant</CardTitle>
          <CardDescription>
            Multi-tenant listing is not yet exposed by sx-api. Paste a tenant
            UUID to override the active tenant for this browser session — the
            override is stored in <code>sessionStorage</code> and applied on
            reload.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-[1fr_auto] md:items-end">
            <div className="space-y-1.5">
              <Label htmlFor="tenant-id">Tenant id</Label>
              <Input
                id="tenant-id"
                value={draft}
                onChange={(event) => setDraft(event.currentTarget.value)}
                placeholder="00000000-0000-0000-0000-000000000000"
              />
            </div>
            <Button onClick={switchTenant}>Switch</Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
