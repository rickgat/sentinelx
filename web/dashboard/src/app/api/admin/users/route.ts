import { NextResponse, type NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { apiGet, apiPost, ApiError } from "@/lib/api-client";

/**
 * Proxy for `GET /v1/admin/users` and `POST /v1/admin/users`.
 *
 * - `GET` returns a tenant-scoped page of users (powers the LOW-008
 *   "Known devices" user picker on `/dashboard/rba/devices`).
 * - `POST` provisions a new user.
 *
 * Both methods are gated server-side on `admin:users`. The backend
 * also validates POST payloads:
 *   - tenant_id is a canonical UUID,
 *   - email is RFC-valid,
 *   - password is 8..200 chars,
 *   - roles is a non-empty list (≤ 32).
 *
 * The dashboard intentionally tightens the password floor to 12
 * characters because the operator UI is the most common entry point
 * for newly-provisioned accounts.
 */

const PASSWORD_MIN = 12;
const ROLES_MAX = 32;

interface CreateUserBody {
  tenant_id?: unknown;
  email?: unknown;
  password?: unknown;
  roles?: unknown;
}

interface ParsedBody {
  tenant_id: string;
  email: string;
  password: string;
  roles: string[];
}

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/u;

function parseBody(input: unknown): ParsedBody | null {
  if (input === null || typeof input !== "object") {
    return null;
  }
  const body = input as CreateUserBody;
  if (typeof body.tenant_id !== "string" || body.tenant_id.trim().length === 0) {
    return null;
  }
  if (typeof body.email !== "string" || !EMAIL_RE.test(body.email)) {
    return null;
  }
  if (typeof body.password !== "string" || body.password.length < PASSWORD_MIN) {
    return null;
  }
  if (!Array.isArray(body.roles) || body.roles.length === 0 || body.roles.length > ROLES_MAX) {
    return null;
  }
  const roles: string[] = [];
  for (const r of body.roles) {
    if (typeof r !== "string") {
      return null;
    }
    const trimmed = r.trim();
    if (trimmed.length > 0) {
      roles.push(trimmed);
    }
  }
  if (roles.length === 0) {
    return null;
  }
  return {
    tenant_id: body.tenant_id.trim(),
    email: body.email.trim().toLowerCase(),
    password: body.password,
    roles,
  };
}

interface AdminUserSummary {
  id: string;
  tenant_id: string;
  email: string;
  is_active: boolean;
  role_count: number;
  created_at: string;
}

interface ListUsersBody {
  users: AdminUserSummary[];
}

const LIST_DEFAULT_LIMIT = 100;
const LIST_MAX_LIMIT = 500;

export async function GET(req: NextRequest): Promise<NextResponse> {
  const session = await auth();
  if (session?.accessToken === undefined) {
    return NextResponse.json(
      { error: { code: "UNAUTHORIZED", message: "unauthorized" } },
      { status: 401 },
    );
  }

  const url = new URL(req.url);
  const limitRaw = Number.parseInt(url.searchParams.get("limit") ?? "", 10);
  const offsetRaw = Number.parseInt(url.searchParams.get("offset") ?? "", 10);
  const limit =
    Number.isFinite(limitRaw) && limitRaw > 0
      ? Math.min(limitRaw, LIST_MAX_LIMIT)
      : LIST_DEFAULT_LIMIT;
  const offset = Number.isFinite(offsetRaw) && offsetRaw >= 0 ? offsetRaw : 0;

  try {
    const data = await apiGet<ListUsersBody>(
      `/v1/admin/users?limit=${limit.toString()}&offset=${offset.toString()}`,
      session.accessToken,
    );
    return NextResponse.json({ data });
  } catch (err) {
    if (err instanceof ApiError) {
      return NextResponse.json(
        { error: { code: err.code, message: err.message, request_id: err.requestId } },
        { status: err.status },
      );
    }
    return NextResponse.json(
      { error: { code: "UPSTREAM_ERROR", message: "Upstream request failed" } },
      { status: 502 },
    );
  }
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
          message:
            "tenant_id, email, password (>= 12 chars), and roles[] are required",
        },
      },
      { status: 400 },
    );
  }

  try {
    const data = await apiPost<unknown>(
      "/v1/admin/users",
      parsed,
      session.accessToken,
    );
    return NextResponse.json({ data, meta: { email: parsed.email, roles: parsed.roles } });
  } catch (err) {
    if (err instanceof ApiError) {
      return NextResponse.json(
        { error: { code: err.code, message: err.message, request_id: err.requestId } },
        { status: err.status },
      );
    }
    return NextResponse.json(
      { error: { code: "UPSTREAM_ERROR", message: "Upstream request failed" } },
      { status: 502 },
    );
  }
}
