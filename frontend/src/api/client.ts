import type { LoginResponse } from "./types";

const BASE = "/api/v1";

let accessToken: string | null = null;
let refreshing: Promise<LoginResponse | null> | null = null;
let sessionEpoch = 0;
let onSessionExpired: (() => void) | null = null;
const sessionListeners = new Set<(session: LoginResponse) => void>();

export function subscribeSession(listener: (session: LoginResponse) => void) {
  sessionListeners.add(listener);
  return () => { sessionListeners.delete(listener); };
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

export function setAccessToken(token: string | null) {
  accessToken = token;
  if (token === null) sessionEpoch += 1;
}

export function setSessionExpiredHandler(fn: (() => void) | null) {
  onSessionExpired = fn;
}

function detailMessage(body: unknown, fallback: string): string {
  if (body && typeof body === "object" && "detail" in body) {
    const d = (body as { detail: unknown }).detail;
    if (typeof d === "string") return d;
    if (Array.isArray(d))
      return d
        .map((e: { loc?: unknown[]; msg?: string }) => {
          const field = e.loc?.filter((p) => p !== "body" && p !== "query").join(".");
          return field ? `${field}: ${e.msg}` : e.msg;
        })
        .join("; ");
  }
  if (body && typeof body === "object" && "error" in body) return String((body as { error: unknown }).error);
  return fallback;
}

export function refreshSession(): Promise<LoginResponse | null> {
  if (refreshing) return refreshing;
  const epoch = sessionEpoch;
  const refresh = async () => {
    if (epoch !== sessionEpoch) return null;
    const res = await fetch(`${BASE}/auth/refresh`, { method: "POST", credentials: "same-origin" });
    if (!res.ok || epoch !== sessionEpoch) return null;
    const data = (await res.json()) as LoginResponse;
    if (epoch !== sessionEpoch) return null;
    accessToken = data.access_token;
    for (const listener of sessionListeners) listener(data);
    return data;
  };
  refreshing = (typeof navigator !== "undefined" && navigator.locks
    ? navigator.locks.request("guardiano-session", refresh).then((result) => result)
    : refresh()).finally(() => { refreshing = null; });
  return refreshing;
}

async function tryRefresh(): Promise<boolean> {
  return (await refreshSession()) !== null;
}

export async function endSession(): Promise<void> {
  setAccessToken(null);
  const logout = () => fetch(`${BASE}/auth/logout`, { method: "POST", credentials: "same-origin" });
  // Wait for in-flight refresh cookies before revoking the family they belong to.
  await refreshing?.catch(() => undefined);
  if (navigator.locks) await navigator.locks.request("guardiano-session", logout);
  else await logout();
}

/**
 * Where a 401 means "wrong credentials", not "session expired": refreshing would be pointless, and for
 * /auth/refresh itself, circular. Named one by one rather than as the /auth/ prefix, which also covered
 * authenticated endpoints -- /auth/mfa, /auth/preferences, /auth/change-password -- so an expired token
 * on the Settings page failed outright instead of refreshing like everywhere else.
 */
const NO_REFRESH = new Set([
  "/auth/login",
  "/auth/login/mfa",
  "/auth/refresh",
  "/auth/logout",
  "/auth/forgot-password",
  "/auth/reset-password",
]);

type Query = Record<string, string | number | boolean | (string | number)[] | null | undefined>;

export function buildQuery(params: Query = {}): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "") continue;
    if (Array.isArray(v)) v.forEach((x) => sp.append(k, String(x)));
    else sp.append(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  query?: Query;
  form?: FormData;
  raw?: boolean;
  /** react-query's, so leaving a page or changing a filter cancels the request it no longer needs. */
  signal?: AbortSignal;
}

export async function api<T>(path: string, opts: RequestOptions = {}, retried = false): Promise<T> {
  const headers: Record<string, string> = {};
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  let body: BodyInit | undefined;
  if (opts.form) body = opts.form;
  else if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.body);
  }
  const res = await fetch(`${BASE}${path}${buildQuery(opts.query)}`, {
    method: opts.method ?? (body ? "POST" : "GET"),
    headers,
    body,
    credentials: "same-origin",
    signal: opts.signal,
  });

  if (res.status === 401 && !NO_REFRESH.has(path.split("?")[0])) {
    if (!retried && (await tryRefresh())) return api<T>(path, opts, true);
    // Refresh failed, or the fresh token was refused too: either way the session is over.
    onSessionExpired?.();
  }
  if (!res.ok) {
    let parsed: unknown = null;
    try {
      parsed = await res.json();
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, detailMessage(parsed, `${res.status} ${res.statusText}`));
  }
  if (opts.raw) return res as unknown as T;
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export async function download(path: string, query: Query, filename: string) {
  const res = await api<Response>(path, { query, raw: true });
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoking synchronously can cancel the download in Safari and Firefox.
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
