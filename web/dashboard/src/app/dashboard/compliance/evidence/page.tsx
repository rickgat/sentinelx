import Link from "next/link";
import { redirect } from "next/navigation";
import { FolderArchive } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { getAccessToken } from "@/lib/server-fetch";

import { EvidenceClient, type ShippedRow } from "./evidence-client";

/**
 * Compliance Evidence collector control room.
 *
 * Server-side: gate behind a valid sx-api session, seed the shipped-to-S3
 * status table with a deterministic 10-row stub. The interactive form lives
 * in the client island below.
 *
 * Once the sx-cli evidence collector is callable from the web tier, both the
 * "Run collectors" and "Ship to S3" actions will swap out their stubs for
 * real proxy calls — the wire format on this page already matches what we
 * expect the real proxy to return.
 */

const SHIPPED_STUB: ReadonlyArray<ShippedRow> = [
  {
    manifest_key: "evidence/2026/05/soc2-iam-001.json",
    framework: "soc2",
    artifact_count: 12,
    size_bytes: 184_320,
    shipped_at: "2026-05-30T14:02:11Z",
    status: "ok",
  },
  {
    manifest_key: "evidence/2026/05/iso27001-rbac-002.json",
    framework: "iso27001",
    artifact_count: 7,
    size_bytes: 92_160,
    shipped_at: "2026-05-30T11:48:03Z",
    status: "ok",
  },
  {
    manifest_key: "evidence/2026/05/soc2-mfa-003.json",
    framework: "soc2",
    artifact_count: 4,
    size_bytes: 36_864,
    shipped_at: "2026-05-30T09:22:48Z",
    status: "ok",
  },
  {
    manifest_key: "evidence/2026/05/iso27001-backup-004.json",
    framework: "iso27001",
    artifact_count: 9,
    size_bytes: 122_880,
    shipped_at: "2026-05-29T22:10:17Z",
    status: "ok",
  },
  {
    manifest_key: "evidence/2026/05/soc2-edr-005.json",
    framework: "soc2",
    artifact_count: 21,
    size_bytes: 327_680,
    shipped_at: "2026-05-29T18:55:02Z",
    status: "partial",
  },
  {
    manifest_key: "evidence/2026/05/iso27001-vuln-006.json",
    framework: "iso27001",
    artifact_count: 14,
    size_bytes: 204_800,
    shipped_at: "2026-05-29T13:34:51Z",
    status: "ok",
  },
  {
    manifest_key: "evidence/2026/05/soc2-vendor-007.json",
    framework: "soc2",
    artifact_count: 3,
    size_bytes: 24_576,
    shipped_at: "2026-05-28T20:18:09Z",
    status: "ok",
  },
  {
    manifest_key: "evidence/2026/05/iso27001-cloudtrail-008.json",
    framework: "iso27001",
    artifact_count: 11,
    size_bytes: 167_936,
    shipped_at: "2026-05-28T16:02:33Z",
    status: "failed",
  },
  {
    manifest_key: "evidence/2026/05/soc2-training-009.json",
    framework: "soc2",
    artifact_count: 6,
    size_bytes: 49_152,
    shipped_at: "2026-05-28T08:41:27Z",
    status: "ok",
  },
  {
    manifest_key: "evidence/2026/05/soc2-branch-010.json",
    framework: "soc2",
    artifact_count: 5,
    size_bytes: 40_960,
    shipped_at: "2026-05-27T23:11:55Z",
    status: "ok",
  },
];

export default async function EvidencePage() {
  const token = await getAccessToken();
  if (token === null) {
    redirect("/login");
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0">
          <div className="space-y-1.5">
            <CardTitle className="flex items-center gap-2">
              <FolderArchive className="h-4 w-4 text-accent" aria-hidden />
              Compliance evidence
            </CardTitle>
            <CardDescription>
              Run collectors for a framework and ship the manifest to S3. Backed by the
              sx-cli evidence pipeline. Both actions are currently stubbed pending the
              web-callable CLI binding.
            </CardDescription>
          </div>
          <Link
            href="/dashboard/compliance"
            className="text-xs text-muted-foreground hover:text-foreground"
          >
            All frameworks
          </Link>
        </CardHeader>
        <CardContent>
          <EvidenceClient initialShipped={SHIPPED_STUB} />
        </CardContent>
      </Card>
    </div>
  );
}
