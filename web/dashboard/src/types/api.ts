/**
 * Mirrors the sx-api JSON envelope:
 *   { "data": T, "meta": { ... } }
 * or
 *   { "error": { "code": string, "message": string, "details": ... } }
 */

export interface ApiMeta {
  request_id?: string;
  page?: number;
  per_page?: number;
  total?: number;
}

export interface ApiResponse<T> {
  data: T;
  meta?: ApiMeta;
}

export interface ApiErrorBody {
  code: string;
  message: string;
  details?: unknown;
}
