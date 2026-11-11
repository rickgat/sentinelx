import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";

/**
 * Stub proxy for `POST /v1/compliance/evidence/run`.
 *
 * The real implementation will dispatch the sx-cli evidence collector for the
 * requested framework(s) and stream artifacts back through sx-api. Until the
 * CLI is callable from web, we return a deterministic fake artifact list so
 * the UI can be wired end-to-end against the dashboard proxy.
 *
 * Body shape:
 *   {
 *     framework: "soc2" | "iso27001" | "all",
 *     output_dir: string  // file-system-style path, e.g. "./evidence/"
 *   }
 *
 * Success envelope mirrors sx-api convention:
 *   { data: { artifacts: [...10 fake rows] }, meta: { ... } }
 */

const ALLOWED_FRAMEWORKS: ReadonlyArray<string> = ["soc2", "iso27001", "all"];

interface EvidenceRunBody {
  framework?: unknown;
  output_dir?: unknown;
}

interface ParsedBody {
  framework: string;
  output_dir: string;
}

interface FakeArtifact {
  artifact_id: string;
  framework: string;
  control_id: string;
  collector: string;
  filename: string;
  size_bytes: number;
  sha256: string;
  collected_at: string;
}

function parseBody(input: unknown): ParsedBody | null {
  if (input === null || typeof input !== "object") {
    return null;
  }
  const body = input as EvidenceRunBody;
  if (typeof body.framework !== "string" || !ALLOWED_FRAMEWORKS.includes(body.framework)) {
    return null;
  }
  if (typeof body.output_dir !== "string" || body.output_dir.trim().length === 0) {
    return null;
  }
  return {
    framework: body.framework,
    output_dir: body.output_dir.trim(),
  };
}

function buildFakeArtifacts(framework: string): ReadonlyArray<FakeArtifact> {
  const now = Date.now();
  const collectors = [
    { id: "aws_iam_inventory", file: "iam_users.json", framework: "soc2", control: "CC6.1" },
    { id: "okta_mfa_enrollment", file: "okta_mfa.json", framework: "soc2", control: "CC6.6" },
    { id: "gh_branch_protection", file: "branch_protection.json", framework: "soc2", control: "CC8.1" },
    { id: "aws_cloudtrail_status", file: "cloudtrail.json", framework: "iso27001", control: "A.12.4" },
    { id: "k8s_rbac_dump", file: "k8s_rbac.yaml", framework: "iso27001", control: "A.9.2" },
    { id: "vendor_soc_reports", file: "vendor_index.json", framework: "soc2", control: "CC9.1" },
    { id: "backup_verification", file: "backup_runs.json", framework: "iso27001", control: "A.12.3" },
    { id: "endpoint_edr_coverage", file: "edr_coverage.csv", framework: "soc2", control: "CC7.1" },
    { id: "vuln_scan_results", file: "scan_results.json", framework: "iso27001", control: "A.12.6" },
    { id: "training_completion", file: "training.csv", framework: "soc2", control: "CC1.4" },
  ];
  return collectors
    .filter((c) => framework === "all" || c.framework === framework)
    .slice(0, 10)
    .map((c, idx) => ({
      artifact_id: `art_${(now + idx).toString(36)}`,
      framework: c.framework,
      control_id: c.control,
      collector: c.id,
      filename: c.file,
      size_bytes: 4096 + idx * 1024,
      sha256: `fake_${(now + idx).toString(16).padStart(16, "0")}`,
      collected_at: new Date(now - idx * 1000).toISOString(),
    }));
}

export async function POST(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
      { status: 401 },
    );
  }

  let raw: unknown;
  try {
    raw = await req.json();
  } catch {
    return NextResponse.json(
      { error: { code: "BAD_REQUEST", message: "invalid JSON body" } },
      { status: 400 },
    );
  }

  const parsed = parseBody(raw);
  if (parsed === null) {
    return NextResponse.json(
      {
        error: {
          code: "BAD_REQUEST",
          message: "framework (soc2|iso27001|all) and a non-empty output_dir are required",
        },
      },
      { status: 400 },
    );
  }

  const artifacts = buildFakeArtifacts(parsed.framework);

  return NextResponse.json({
    data: {
      artifacts,
    },
    meta: {
      framework: parsed.framework,
      output_dir: parsed.output_dir,
      stub: true,
      ts: new Date().toISOString(),
    },
  });
}
