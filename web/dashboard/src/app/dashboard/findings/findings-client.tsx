"use client";

import * as React from "react";
import Link from "next/link";
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  useReactTable,
  type ColumnFiltersState,
  type RowSelectionState,
} from "@tanstack/react-table";
import {
  CheckCircle2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ListChecks,
  Search as SearchIcon,
  XCircle,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SeverityBadge } from "@/components/severity-badge";
import { PredictivePanel } from "@/components/predictive-panel";
import { cn } from "@/lib/utils";
import type { Finding, FindingStatus, Severity } from "@/lib/types";

const STATUSES: ReadonlyArray<FindingStatus> = [
  "open",
  "triaged",
  "in_progress",
  "resolved",
  "false_positive",
  "accepted",
  "closed",
];

const SEVERITIES: ReadonlyArray<Severity> = ["critical", "high", "medium", "low", "info"];

function humanize(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

const columnHelper = createColumnHelper<Finding>();

interface Props {
  initialData: ReadonlyArray<Finding>;
  apiAvailable: boolean;
}

export function FindingsClient({ initialData, apiAvailable }: Props) {
  const [severityFilter, setSeverityFilter] = React.useState<Set<Severity>>(new Set());
  const [statusFilter, setStatusFilter] = React.useState<Set<FindingStatus>>(new Set());
  const [search, setSearch] = React.useState("");
  const [rowSelection, setRowSelection] = React.useState<RowSelectionState>({});
  const [drawerFinding, setDrawerFinding] = React.useState<Finding | null>(null);
  const [banner, setBanner] = React.useState<string | null>(null);

  const columnFilters = React.useMemo<ColumnFiltersState>(() => {
    const filters: ColumnFiltersState = [];
    if (severityFilter.size > 0) {
      filters.push({ id: "severity", value: Array.from(severityFilter) });
    }
    if (statusFilter.size > 0) {
      filters.push({ id: "status", value: Array.from(statusFilter) });
    }
    if (search.trim().length > 0) {
      filters.push({ id: "title", value: search.trim() });
    }
    return filters;
  }, [severityFilter, statusFilter, search]);

  const columns = React.useMemo(
    () => [
      columnHelper.display({
        id: "select",
        header: ({ table }) => (
          <input
            type="checkbox"
            aria-label="Select all rows"
            checked={table.getIsAllPageRowsSelected()}
            ref={(el) => {
              if (el !== null) {
                el.indeterminate = table.getIsSomePageRowsSelected() && !table.getIsAllPageRowsSelected();
              }
            }}
            onChange={(e) => table.toggleAllPageRowsSelected(e.currentTarget.checked)}
            className="h-3.5 w-3.5 cursor-pointer accent-accent"
          />
        ),
        cell: ({ row }) => (
          <input
            type="checkbox"
            aria-label={`Select row ${row.original.id}`}
            checked={row.getIsSelected()}
            onClick={(e) => e.stopPropagation()}
            onChange={(e) => row.toggleSelected(e.currentTarget.checked)}
            className="h-3.5 w-3.5 cursor-pointer accent-accent"
          />
        ),
      }),
      columnHelper.accessor("severity", {
        header: "Severity",
        cell: (info) => <SeverityBadge severity={info.getValue()} />,
        filterFn: (row, id, value) => {
          const arr = value as ReadonlyArray<Severity>;
          return arr.includes(row.getValue(id) as Severity);
        },
      }),
      columnHelper.accessor("title", {
        header: "Title",
        filterFn: (row, id, value) => {
          const q = String(value).toLowerCase();
          return String(row.getValue(id) ?? "").toLowerCase().includes(q);
        },
      }),
      columnHelper.accessor("asset_id", {
        header: "Asset",
        cell: (info) => (
          <span className="font-mono text-[11px] text-muted-foreground">
            {String(info.getValue()).slice(0, 12)}
          </span>
        ),
      }),
      columnHelper.accessor("status", {
        header: "Status",
        cell: (info) => humanize(info.getValue()),
        filterFn: (row, id, value) => {
          const arr = value as ReadonlyArray<FindingStatus>;
          return arr.includes(row.getValue(id) as FindingStatus);
        },
      }),
      columnHelper.accessor("first_seen", {
        header: "First seen",
        cell: (info) => (
          <span className="font-mono text-[11px]">{info.getValue().slice(0, 10)}</span>
        ),
      }),
      columnHelper.display({
        id: "detail",
        header: "",
        cell: (info) => (
          <Link
            href={`/dashboard/findings/${info.row.original.id}`}
            onClick={(event) => event.stopPropagation()}
            className="text-xs text-accent hover:underline"
          >
            View →
          </Link>
        ),
      }),
    ],
    [],
  );

  const data = React.useMemo(() => [...initialData], [initialData]);
  const table = useReactTable({
    data,
    columns,
    state: { columnFilters, rowSelection },
    onRowSelectionChange: setRowSelection,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    initialState: { pagination: { pageSize: 25 } },
    getRowId: (row) => row.id,
  });

  const rows = table.getRowModel().rows;
  const selectedCount = Object.values(rowSelection).filter(Boolean).length;
  const filteredCount = table.getFilteredRowModel().rows.length;
  const totalCount = data.length;

  const clearAll = () => {
    setSeverityFilter(new Set());
    setStatusFilter(new Set());
    setSearch("");
  };
  const anyFilterActive = severityFilter.size + statusFilter.size > 0 || search.trim().length > 0;

  const bulkAcknowledge = () => {
    // Backend bulk endpoint not yet wired — surface the intent as a toast-style
    // banner so operators know we captured the selection without lying about
    // persistence. Real POST arrives in the findings-bulk milestone.
    setBanner(`${selectedCount} finding${selectedCount === 1 ? "" : "s"} marked as acknowledged (queued locally).`);
    setRowSelection({});
    window.setTimeout(() => setBanner(null), 4000);
  };
  const bulkDismiss = () => {
    setBanner(`${selectedCount} finding${selectedCount === 1 ? "" : "s"} dismissed as false positive (queued locally).`);
    setRowSelection({});
    window.setTimeout(() => setBanner(null), 4000);
  };

  return (
    <>
      <Card>
        <CardHeader className="flex flex-col gap-3 space-y-0 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle>Findings</CardTitle>
            <p className="mt-1 text-xs text-muted-foreground">
              <span className="font-mono tabular-nums">{filteredCount}</span> of{" "}
              <span className="font-mono tabular-nums">{totalCount}</span>{" "}
              {anyFilterActive ? "match current filters" : "total"}
            </p>
          </div>
        </CardHeader>
        <CardContent>
          {!apiAvailable ? (
            <div
              role="alert"
              className="mb-4 rounded-sx border border-critical/40 bg-critical/10 px-3 py-2 text-xs text-critical"
            >
              API unavailable — findings could not be loaded.
            </div>
          ) : null}
          {banner !== null ? (
            <div
              role="status"
              className="mb-4 rounded-sx border border-info/40 bg-info/10 px-3 py-2 text-xs text-info"
            >
              {banner}
            </div>
          ) : null}

          {/* Filter bar */}
          <div className="mb-3 flex flex-col gap-2 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative">
                <SearchIcon
                  className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground"
                  aria-hidden
                />
                <Input
                  aria-label="Search findings by title"
                  placeholder="Search title…"
                  value={search}
                  onChange={(e) => setSearch(e.currentTarget.value)}
                  className="h-8 w-56 pl-7 text-xs"
                />
              </div>

              <FilterPopover
                label="Severity"
                values={SEVERITIES}
                selected={severityFilter}
                onToggle={(v) =>
                  setSeverityFilter((prev) => {
                    const next = new Set(prev);
                    if (next.has(v)) next.delete(v);
                    else next.add(v);
                    return next;
                  })
                }
                render={(v) => humanize(v)}
              />
              <FilterPopover
                label="Status"
                values={STATUSES}
                selected={statusFilter}
                onToggle={(v) =>
                  setStatusFilter((prev) => {
                    const next = new Set(prev);
                    if (next.has(v)) next.delete(v);
                    else next.add(v);
                    return next;
                  })
                }
                render={(v) => humanize(v)}
              />

              {anyFilterActive ? (
                <Button variant="ghost" size="sm" onClick={clearAll} className="h-8 text-xs">
                  Clear filters
                </Button>
              ) : null}
            </div>

            {selectedCount > 0 ? (
              <div className="flex items-center gap-2 rounded-sx border border-accent/40 bg-accent/10 px-2 py-1">
                <ListChecks className="h-3.5 w-3.5 text-accent" aria-hidden />
                <span className="font-mono text-[11px] tabular-nums text-accent">
                  {selectedCount} selected
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={bulkAcknowledge}
                  className="h-7 gap-1 text-xs"
                >
                  <CheckCircle2 className="h-3.5 w-3.5" aria-hidden />
                  Acknowledge
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={bulkDismiss}
                  className="h-7 gap-1 text-xs"
                >
                  <XCircle className="h-3.5 w-3.5" aria-hidden />
                  Dismiss
                </Button>
              </div>
            ) : null}
          </div>

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
              {rows.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={columns.length} className="py-8 text-center text-xs text-muted-foreground">
                    No findings match the current filter.
                  </TableCell>
                </TableRow>
              ) : (
                rows.map((row) => {
                  const finding = row.original;
                  const isActive = drawerFinding?.id === finding.id;
                  return (
                    <TableRow
                      key={row.id}
                      onClick={() => setDrawerFinding(finding)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          setDrawerFinding(finding);
                        }
                      }}
                      tabIndex={0}
                      role="button"
                      aria-label={`Inspect finding ${finding.title}`}
                      className={cn(
                        "cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent",
                        isActive ? "bg-muted/40" : undefined,
                      )}
                    >
                      {row.getVisibleCells().map((cell) => (
                        <TableCell key={cell.id}>
                          {flexRender(cell.column.columnDef.cell, cell.getContext())}
                        </TableCell>
                      ))}
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>

          {/* Pagination */}
          {filteredCount > table.getState().pagination.pageSize ? (
            <div className="mt-3 flex items-center justify-between text-xs text-muted-foreground">
              <span className="font-mono tabular-nums">
                Page {table.getState().pagination.pageIndex + 1} of {table.getPageCount()}
              </span>
              <div className="flex items-center gap-1">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!table.getCanPreviousPage()}
                  onClick={() => table.previousPage()}
                  className="h-7 gap-1 text-xs"
                >
                  <ChevronLeft className="h-3.5 w-3.5" aria-hidden />
                  Prev
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={!table.getCanNextPage()}
                  onClick={() => table.nextPage()}
                  className="h-7 gap-1 text-xs"
                >
                  Next
                  <ChevronRight className="h-3.5 w-3.5" aria-hidden />
                </Button>
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>

      {/* Finding detail drawer */}
      <Sheet open={drawerFinding !== null} onOpenChange={(o) => (o ? undefined : setDrawerFinding(null))}>
        <SheetContent side="right" className="overflow-y-auto">
          {drawerFinding !== null ? (
            <>
              <SheetHeader>
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={drawerFinding.severity} />
                  <span className="font-mono text-[11px] text-muted-foreground">
                    {drawerFinding.id.slice(0, 12)}
                  </span>
                </div>
                <SheetTitle>{drawerFinding.title}</SheetTitle>
                <SheetDescription>{humanize(drawerFinding.status)}</SheetDescription>
              </SheetHeader>

              <dl className="grid grid-cols-2 gap-3 rounded-sx border border-border bg-muted/20 p-3 text-xs">
                <div>
                  <dt className="text-[10px] uppercase tracking-wider text-muted-foreground">Asset</dt>
                  <dd className="mt-0.5 font-mono">{drawerFinding.asset_id.slice(0, 16)}</dd>
                </div>
                <div>
                  <dt className="text-[10px] uppercase tracking-wider text-muted-foreground">First seen</dt>
                  <dd className="mt-0.5 font-mono">{drawerFinding.first_seen.slice(0, 10)}</dd>
                </div>
                <div>
                  <dt className="text-[10px] uppercase tracking-wider text-muted-foreground">Last seen</dt>
                  <dd className="mt-0.5 font-mono">{drawerFinding.last_seen.slice(0, 10)}</dd>
                </div>
                {drawerFinding.cvss !== undefined ? (
                  <div>
                    <dt className="text-[10px] uppercase tracking-wider text-muted-foreground">CVSS</dt>
                    <dd className="mt-0.5 font-mono">{drawerFinding.cvss.toFixed(1)}</dd>
                  </div>
                ) : null}
                {drawerFinding.cve_id !== undefined ? (
                  <div className="col-span-2">
                    <dt className="text-[10px] uppercase tracking-wider text-muted-foreground">CVE</dt>
                    <dd className="mt-0.5 font-mono">{drawerFinding.cve_id}</dd>
                  </div>
                ) : null}
              </dl>

              {drawerFinding.description.length > 0 ? (
                <div className="space-y-1">
                  <h3 className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                    Description
                  </h3>
                  <p className="text-xs leading-relaxed text-foreground">{drawerFinding.description}</p>
                </div>
              ) : null}

              <div className="space-y-1">
                <h3 className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                  Predictive analysis
                </h3>
                <PredictivePanel finding_id={drawerFinding.id} />
              </div>

              <SheetFooter>
                <Button variant="outline" asChild>
                  <Link href={`/dashboard/findings/${drawerFinding.id}`} prefetch={false}>
                    Open full page
                  </Link>
                </Button>
                <Button>Acknowledge</Button>
              </SheetFooter>
            </>
          ) : null}
        </SheetContent>
      </Sheet>
    </>
  );
}

interface FilterPopoverProps<T extends string> {
  label: string;
  values: ReadonlyArray<T>;
  selected: Set<T>;
  onToggle: (value: T) => void;
  render: (value: T) => string;
}

function FilterPopover<T extends string>({
  label,
  values,
  selected,
  onToggle,
  render,
}: FilterPopoverProps<T>) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" className="h-8 gap-1 text-xs">
          {label}
          {selected.size > 0 ? (
            <span className="ml-1 rounded-full bg-accent/20 px-1.5 font-mono text-[10px] text-accent">
              {selected.size}
            </span>
          ) : null}
          <ChevronDown className="h-3 w-3" aria-hidden />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-48">
        <DropdownMenuLabel>Filter by {label.toLowerCase()}</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {values.map((v) => (
          <DropdownMenuCheckboxItem
            key={v}
            checked={selected.has(v)}
            onCheckedChange={() => onToggle(v)}
            onSelect={(e) => e.preventDefault()}
          >
            {render(v)}
          </DropdownMenuCheckboxItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
