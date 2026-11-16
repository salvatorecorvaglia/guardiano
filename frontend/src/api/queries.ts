import { type QueryClient, useQueries, useQuery } from "@tanstack/react-query";
import { request } from "./typed";


export function useMeta() {
  return useQuery({ queryKey: ["meta"], queryFn: ({ signal }) => request("get", "/api/v1/meta", { signal }), staleTime: Infinity });
}

/** Query keys whose data neither a scan nor an asset change can alter: who you are, your own settings,
 * and server configuration. The layout keeps several of them mounted on every page, so a blanket
 * invalidateQueries() refetched them after each upload for nothing. */
const UNAFFECTED_BY_INVENTORY = new Set(["meta", "users", "mfa", "preferences", "tokens", "sla", "license-policy", "triage-rules", "views", "teams"]);

/** After an upload or an asset is removed: everything derived from findings, scans and assets. */
export function invalidateInventory(qc: QueryClient) {
  return qc.invalidateQueries({ predicate: (q) => !UNAFFECTED_BY_INVENTORY.has(String(q.queryKey[0])) });
}

const asset = (id?: string | number | null) => (id ? Number(id) : null);

/**
 * Query keys for everything served under /analytics, all under the one "analytics" prefix, so that
 * invalidating it refreshes every figure. Reports and the Dashboard's OWASP panel used to key theirs
 * as ["compliance"], ["summary"] and ["top"], which no invalidation ever named: triage a finding and
 * those numbers stayed stale. The asset id is normalised, because "3" from a URL and 3 from a route
 * param would otherwise be two cache entries for one request.
 */
export const analyticsKeys = {
  all: ["analytics"] as const,
  summary: (assetId?: string | number | null) => ["analytics", "summary", asset(assetId)] as const,
  trends: (days: number, assetId?: string | number | null) => ["analytics", "trends", days, asset(assetId)] as const,
  top: (by: "assets" | "cwes" | "packages", limit: number, assetId?: string | number | null) =>
    ["analytics", "top", by, limit, asset(assetId)] as const,
  compliance: (assetId?: string | number | null, days?: number) =>
    ["analytics", "compliance", asset(assetId), days ?? null] as const,
  coverage: (staleDays: number) => ["analytics", "coverage", staleDays] as const,
};

/** What a change to a finding -- status, assignee, tags, due date -- can alter anywhere in the app:
 * the lists, the finding itself, the tag suggestions, every analytics figure, and the asset list's
 * open counts and risk scores. Each triage path used to list its own subset; bulk triage left the
 * asset list stale. */
export function invalidateAfterTriage(qc: QueryClient, { fresh }: { fresh?: readonly unknown[] } = {}) {
  // `fresh` is a key the caller has just filled from the mutation's own response; refetching it
  // would only fetch the same thing again.
  const same = (key: readonly unknown[]) => !!fresh && key.length === fresh.length && key.every((k, i) => k === fresh[i]);
  for (const key of ["findings", "finding", "finding-tags", "analytics", "assets", "asset", "vulnerability", "acceptance-requests", "products"]) {
    qc.invalidateQueries({ queryKey: [key], predicate: (q) => !same(q.queryKey) });
  }
}

/** Every product, with counts over the assets of it this person can see. */
export function useProducts() {
  return useQuery({ queryKey: ["products"], queryFn: ({ signal }) => request("get", "/api/v1/products", { signal }) });
}

/** The top endpoint has a union response. Check its query-dependent variant before exposing it. */
export async function getTopAssets(limit: number, signal?: AbortSignal) {
  const rows = await request("get", "/api/v1/analytics/top", { query: { by: "assets", limit }, signal });
  return rows.map((row) => { if ("id" in row) return row; throw new Error("Unexpected asset ranking response"); });
}
export async function getTopCwes(limit: number, assetId?: number, signal?: AbortSignal) {
  const rows = await request("get", "/api/v1/analytics/top", { query: { by: "cwes", limit, asset_id: assetId }, signal });
  return rows.map((row) => { if ("cwe" in row) return row; throw new Error("Unexpected CWE ranking response"); });
}
export async function getTopPackages(limit: number, assetId?: number, signal?: AbortSignal) {
  const rows = await request("get", "/api/v1/analytics/top", { query: { by: "packages", limit, asset_id: assetId }, signal });
  return rows.map((row) => { if ("package" in row) return row; throw new Error("Unexpected package ranking response"); });
}

/** Resolve only selected users, in bounded batches, for labels outside search result pages. */
export function useUserNames(ids: readonly number[]) {
  const unique = [...new Set(ids)].sort((a, b) => a - b);
  const chunks: number[][] = [];
  for (let index = 0; index < unique.length; index += 500) chunks.push(unique.slice(index, index + 500));
  const results = useQueries({ queries: chunks.map((chunk) => ({
    queryKey: ["users", "lookup", chunk], staleTime: 5 * 60_000,
    queryFn: ({ signal }: { signal: AbortSignal }) => request("get", "/api/v1/users/directory/lookup", { signal, query: { ids: chunk } }),
  })) });
  return { data: results.flatMap((result) => result.data ?? []), error: results.find((result) => result.isError)?.error,
    retry: () => Promise.all(results.filter((result) => result.isError).map((result) => result.refetch())) };
}
