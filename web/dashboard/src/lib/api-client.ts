import { publicEnv } from "@/lib/env";

/**
 * Typed sx-api client.
 *
 * Backend response envelope:
 *   success:  { data: T, meta: { request_id, ts, ... } }
 *   error:    { error: { code: string, message: string, request_id: string } }
 *
 * Helpers return the unwrapped `data` payload (or throw `ApiError`).
 *
 * SAFETY:
 *   - The bearer token is NEVER logged.
 *   - The request body for `POST /v1/auth/login` is NEVER logged.
 */

export class ApiError extends Error {
  public readonly code: string;
  public readonly status: number;
  public readonly requestId: string;

  public constructor(message: string, code: string, status: number, requestId: string) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.requestId = requestId;
  }
}

interface EnvelopeError {
  code?: string;
  message?: string;
  request_id?: string;
}

interface EnvelopeWrapper<T> {
  data?: T;
  error?: EnvelopeError;
}

function baseUrl(): string {
  return publicEnv.NEXT_PUBLIC_SX_API_URL.replace(/\/$/, "");
}

function joinPath(path: string): string {
  return `${baseUrl()}${path.startsWith("/") ? path : `/${path}`}`;
}

async function unwrap<T>(res: Response): Promise<T> {
  // The envelope shape is the only place a generic `any`-ish cast is acceptable —
  // we narrow it immediately into typed fields before returning to callers.
  const text = await res.text();
  let json: EnvelopeWrapper<T> = {};
  if (text.length > 0) {
    try {
      json = JSON.parse(text) as EnvelopeWrapper<T>;
    } catch {
      json = {};
    }
  }

  if (!res.ok) {
    throw new ApiError(
      json.error?.message ?? `Request failed with status ${res.status}`,
      json.error?.code ?? "UNKNOWN",
      res.status,
      json.error?.request_id ?? "",
    );
  }

  return json.data as T;
}

function buildHeaders(token: string, hasBody: boolean): HeadersInit {
  const headers: Record<string, string> = {
    Accept: "application/json",
    Authorization: `Bearer ${token}`,
  };
  if (hasBody) {
    headers["Content-Type"] = "application/json";
  }
  return headers;
}

export async function apiGet<T>(path: string, token: string): Promise<T> {
  const res = await fetch(joinPath(path), {
    method: "GET",
    headers: buildHeaders(token, false),
    cache: "no-store",
  });
  return unwrap<T>(res);
}

export async function apiPost<T>(path: string, body: unknown, token: string): Promise<T> {
  const res = await fetch(joinPath(path), {
    method: "POST",
    headers: buildHeaders(token, true),
    body: JSON.stringify(body),
    cache: "no-store",
  });
  return unwrap<T>(res);
}

/**
 * Unauthenticated POST for public sx-api endpoints (e.g. /v1/auth/signup,
 * /v1/auth/verify-email, /v1/auth/forgot-password, /v1/auth/reset-password).
 * Never sends an Authorization header.
 */
export async function apiPostPublic<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(joinPath(path), {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
    cache: "no-store",
  });
  return unwrap<T>(res);
}

export async function apiPatch<T>(path: string, body: unknown, token: string): Promise<T> {
  const res = await fetch(joinPath(path), {
    method: "PATCH",
    headers: buildHeaders(token, true),
    body: JSON.stringify(body),
    cache: "no-store",
  });
  return unwrap<T>(res);
}

export async function apiPut<T>(path: string, body: unknown, token: string): Promise<T> {
  const res = await fetch(joinPath(path), {
    method: "PUT",
    headers: buildHeaders(token, true),
    body: JSON.stringify(body),
    cache: "no-store",
  });
  return unwrap<T>(res);
}

export async function apiDelete(path: string, token: string): Promise<void> {
  const res = await fetch(joinPath(path), {
    method: "DELETE",
    headers: buildHeaders(token, false),
    cache: "no-store",
  });
  if (!res.ok) {
    // Drain so the connection can be reused, then surface a typed error.
    await unwrap<unknown>(res);
  }
}
