"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { Plus, X } from "lucide-react";
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
import type { Engagement, EngagementStatus } from "@/lib/types";

const statusVariant: Record<EngagementStatus, "info" | "success" | "medium" | "outline"> = {
  draft: "outline",
  scheduled: "info",
  active: "success",
  paused: "medium",
  completed: "outline",
  aborted: "outline",
  cancelled: "outline",
};

const columnHelper = createColumnHelper<Engagement>();

const columns = [
  columnHelper.accessor("name", { header: "Name", cell: (info) => info.getValue() }),
  columnHelper.accessor("status", {
    header: "Status",
    cell: (info) => {
      const status = info.getValue();
      const variant = statusVariant[status] ?? "outline";
      return <Badge variant={variant}>{status}</Badge>;
    },
  }),
  columnHelper.accessor((row) => row.scopes.length, {
    id: "scope_count",
    header: "Scope",
  }),
  columnHelper.accessor("created_at", {
    header: "Created",
    cell: (info) => info.getValue().slice(0, 10),
  }),
];

interface Props {
  initialData: ReadonlyArray<Engagement>;
  apiAvailable: boolean;
}

export function EngagementsClient({ initialData, apiAvailable }: Props) {
  const router = useRouter();
  const toast = useToast();
  const [open, setOpen] = React.useState(false);

  const data = React.useMemo(() => [...initialData], [initialData]);
  const table = useReactTable({
    data,
    columns,
    getCoreRowModel: getCoreRowModel(),
  });

  const isEmpty = initialData.length === 0;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0">
        <CardTitle>Engagements</CardTitle>
        <Button size="sm" className="gap-1" onClick={() => setOpen(true)}>
          <Plus className="h-4 w-4" aria-hidden />
          New engagement
        </Button>
        <NewEngagementDialog
          open={open}
          onOpenChange={setOpen}
          onCreated={() => {
            toast.push({ kind: "success", message: "Engagement created." });
            router.refresh();
          }}
          onError={(message) => toast.push({ kind: "error", message })}
        />
      </CardHeader>
      <CardContent>
        {!apiAvailable ? (
          <div
            role="alert"
            className="mb-4 rounded-sx border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical"
          >
            API unavailable — engagement list could not be loaded.
          </div>
        ) : null}
        {isEmpty ? (
          <div className="flex flex-col items-center justify-center gap-3 py-12 text-center">
            <p className="text-sm text-muted-foreground">No engagements yet.</p>
            <Button onClick={() => setOpen(true)}>
              Create your first engagement →
            </Button>
          </div>
        ) : (
          <Table>
            <TableHeader>
              {table.getHeaderGroups().map((group) => (
                <TableRow key={group.id}>
                  {group.headers.map((header) => (
                    <TableHead key={header.id}>
                      {flexRender(header.column.columnDef.header, header.getContext())}
                    </TableHead>
                  ))}
                </TableRow>
              ))}
            </TableHeader>
            <TableBody>
              {table.getRowModel().rows.map((row) => (
                <TableRow
                  key={row.id}
                  className="cursor-pointer hover:bg-muted/30"
                  onClick={() => router.push(`/dashboard/engagements/${row.original.id}`)}
                >
                  {row.getVisibleCells().map((cell) => (
                    <TableCell key={cell.id}>
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  ))}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: () => void;
  onError: (message: string) => void;
}

function NewEngagementDialog({ open, onOpenChange, onCreated, onError }: DialogProps) {
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [scopesText, setScopesText] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);

  function reset() {
    setName("");
    setDescription("");
    setScopesText("");
  }

  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (name.trim().length === 0) {
      onError("Name is required.");
      return;
    }
    const scopes = scopesText
      .split("\n")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    setSubmitting(true);
    try {
      const body: Record<string, unknown> = { name: name.trim(), scopes };
      if (description.trim().length > 0) {
        body.description = description.trim();
      }
      const res = await fetch("/api/engagements/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const parsed: { data?: Engagement; error?: { message?: string } } = await res
        .json()
        .catch(() => ({}));
      if (!res.ok) {
        onError(parsed.error?.message ?? `Create failed (${res.status})`);
        return;
      }
      reset();
      onOpenChange(false);
      onCreated();
    } catch {
      onError("Network error — please retry.");
    } finally {
      setSubmitting(false);
    }
  }

  React.useEffect(() => {
    if (!open) return;
    function handleKey(event: KeyboardEvent) {
      if (event.key === "Escape" && !submitting) {
        onOpenChange(false);
      }
    }
    window.addEventListener("keydown", handleKey);
    return () => window.removeEventListener("keydown", handleKey);
  }, [open, submitting, onOpenChange]);

  if (!open) {
    return null;
  }

  return (
    <div
      role="presentation"
      onClick={() => {
        if (!submitting) onOpenChange(false);
      }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="new-engagement-title"
        aria-describedby="new-engagement-desc"
        onClick={(event) => event.stopPropagation()}
        className="w-full max-w-md rounded-sx border border-border bg-card p-6 shadow-xl"
      >
        <div className="flex items-start justify-between">
          <div>
            <h2 id="new-engagement-title" className="text-base font-semibold">
              New engagement
            </h2>
            <p id="new-engagement-desc" className="mt-1 text-xs text-muted-foreground">
              Define a new engagement scope. Scopes go one per line.
            </p>
          </div>
          <button
            type="button"
            aria-label="Close"
            onClick={() => onOpenChange(false)}
            disabled={submitting}
            className="rounded-sx p-1 text-muted-foreground hover:bg-muted disabled:opacity-50"
          >
            <X className="h-4 w-4" aria-hidden />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="mt-4 space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="engagement-name">Name</Label>
            <Input
              id="engagement-name"
              value={name}
              onChange={(event) => setName(event.currentTarget.value)}
              placeholder="Q2 external pentest"
              required
              autoFocus
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="engagement-description">Description</Label>
            <Input
              id="engagement-description"
              value={description}
              onChange={(event) => setDescription(event.currentTarget.value)}
              placeholder="Optional — short context"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="engagement-scopes">Scopes (one per line)</Label>
            <textarea
              id="engagement-scopes"
              value={scopesText}
              onChange={(event) => setScopesText(event.currentTarget.value)}
              placeholder={"example.com\n10.0.0.0/24"}
              rows={4}
              className="flex w-full rounded-sx border border-border bg-transparent px-3 py-2 text-sm text-foreground shadow-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            />
          </div>
          <div className="mt-2 flex justify-end gap-2">
            <Button
              type="button"
              variant="outline"
              disabled={submitting}
              onClick={() => onOpenChange(false)}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={submitting}>
              {submitting ? "Creating…" : "Create"}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
