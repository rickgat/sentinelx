"use client";

import * as React from "react";
import { Cloud } from "lucide-react";

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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/components/toast";

type Provider = "aws" | "gcp" | "azure";

const PROVIDERS: ReadonlyArray<Provider> = ["aws", "gcp", "azure"];

interface CloudResource {
  kind: string;
  identifier: string;
  region: string;
  tags?: Record<string, string>;
}

interface InventoryEnvelope {
  data?: {
    items?: ReadonlyArray<CloudResource>;
    resources?: ReadonlyArray<CloudResource>;
  };
  error?: { code?: string; message?: string; request_id?: string };
}

function extractItems(envelope: InventoryEnvelope): ReadonlyArray<CloudResource> {
  if (envelope.data === undefined) {
    return [];
  }
  if (Array.isArray(envelope.data.items)) {
    return envelope.data.items;
  }
  if (Array.isArray(envelope.data.resources)) {
    return envelope.data.resources;
  }
  return [];
}

export function CloudClient() {
  const toast = useToast();
  const [provider, setProvider] = React.useState<Provider>("aws");
  const [region, setRegion] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [items, setItems] = React.useState<ReadonlyArray<CloudResource>>([]);
  const [hasSearched, setHasSearched] = React.useState(false);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    try {
      const params = new URLSearchParams({ provider });
      const regionTrimmed = region.trim();
      if (regionTrimmed.length > 0) {
        params.set("region", regionTrimmed);
      }
      const res = await fetch(`/api/cloud/inventory?${params.toString()}`, {
        cache: "no-store",
      });
      const parsed: InventoryEnvelope = await res.json().catch(() => ({}));
      if (!res.ok) {
        const message = parsed.error?.message ?? `List failed (${res.status})`;
        toast.push({ kind: "error", message });
        setItems([]);
      } else {
        setItems(extractItems(parsed));
      }
    } catch {
      toast.push({ kind: "error", message: "Network error — please retry." });
      setItems([]);
    } finally {
      setHasSearched(true);
      setLoading(false);
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Cloud className="h-4 w-4 text-accent" aria-hidden />
            Cloud inventory
          </CardTitle>
          <CardDescription>
            List discovered resources for the selected cloud connector. Backed
            by <code>GET /v1/cloud/inventory</code>.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            onSubmit={submit}
            className="grid grid-cols-1 gap-3 md:grid-cols-[160px_1fr_auto] md:items-end"
          >
            <div className="space-y-1.5">
              <Label htmlFor="cloud-provider">Provider</Label>
              <select
                id="cloud-provider"
                value={provider}
                onChange={(event) =>
                  setProvider(event.currentTarget.value as Provider)
                }
                className="h-9 w-full rounded-sx border border-border bg-transparent px-2 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                {PROVIDERS.map((p) => (
                  <option key={p} value={p} className="bg-card text-foreground">
                    {p}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="cloud-region">Region</Label>
              <Input
                id="cloud-region"
                value={region}
                onChange={(event) => setRegion(event.currentTarget.value)}
                placeholder="us-east-1"
              />
            </div>
            <Button type="submit" disabled={loading}>
              {loading ? "Listing…" : "List"}
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Resources</CardTitle>
          <CardDescription>
            Submit the form to populate the inventory. Cloud connectors must be
            enabled per-tenant on the backend.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Kind</TableHead>
                <TableHead>Identifier</TableHead>
                <TableHead>Region</TableHead>
                <TableHead>Tags</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.length === 0 ? (
                <TableRow>
                  <TableCell
                    colSpan={4}
                    className="py-8 text-center text-xs text-muted-foreground"
                  >
                    {hasSearched
                      ? "Cloud connector for the selected provider is not enabled or returned no resources."
                      : "No query submitted yet — pick a provider and region above."}
                  </TableCell>
                </TableRow>
              ) : (
                items.map((row, idx) => (
                  <TableRow key={`${row.kind}-${row.identifier}-${idx}`}>
                    <TableCell className="text-xs font-mono">{row.kind}</TableCell>
                    <TableCell className="text-xs font-mono">
                      {row.identifier}
                    </TableCell>
                    <TableCell className="text-xs">{row.region}</TableCell>
                    <TableCell className="flex flex-wrap gap-1">
                      {row.tags !== undefined
                        ? Object.entries(row.tags).map(([k, v]) => (
                            <Badge key={`${k}=${v}`} variant="outline">
                              {k}={v}
                            </Badge>
                          ))
                        : null}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
