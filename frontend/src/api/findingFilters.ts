import { SEVERITIES, STATUSES } from "../lib/format";
import { ApiError } from "./client";
import type { Query } from "./typed";

type RawFilters = Record<string, string | string[] | number | undefined>;

/** Decode URL state at the request boundary, so invalid filters become query errors instead of render errors. */
export function findingFilters(raw: RawFilters): Query<"/api/v1/findings"> {
  const text = (key: string) => typeof raw[key] === "string" ? raw[key] as string : undefined;
  const list = (key: string) => Array.isArray(raw[key]) ? raw[key] as string[] : undefined;
  const number = (key: string, integer = true) => {
    const value = raw[key];
    if (value === undefined || value === "") return undefined;
    const result = Number(value);
    if (!Number.isFinite(result) || (integer && !Number.isSafeInteger(result))) throw new ApiError(422, `Invalid numeric filter: ${key}`);
    return result;
  };
  const boolean = (key: string) => {
    const value = text(key)?.toLowerCase();
    if (!value) return undefined;
    if (["true", "1", "yes", "on"].includes(value)) return true;
    if (["false", "0", "no", "off"].includes(value)) return false;
    throw new ApiError(422, `Invalid boolean filter: ${key}`);
  };
  const choices = <T extends string>(key: string, allowed: readonly T[]) => list(key)?.map((value) => {
    const match = allowed.find((choice) => choice === value);
    if (match === undefined) throw new ApiError(422, `Invalid ${key} filter`);
    return match;
  });
  const assetIds = list("asset_id")?.map((id) => {
    const result = Number(id);
    if (!Number.isSafeInteger(result)) throw new ApiError(422, "Invalid asset filter");
    return result;
  });
  return {
    q: text("q"), severity: choices("severity", SEVERITIES), status: choices("status", STATUSES), tag: list("tag"), asset_id: assetIds,
    type: text("type"), tool: text("tool"), cwe: text("cwe"), cve: text("cve"), package: text("package"),
    product_id: number("product_id"), environment: text("environment"), assignee_id: number("assignee_id"),
    scan_id: number("scan_id"), not_in_scan_id: number("not_in_scan_id"),
    unassigned: boolean("unassigned"), overdue: boolean("overdue"), kev: boolean("kev"), ticket_done: boolean("ticket_done"),
    epss_min: number("epss_min", false), first_seen_from: text("first_seen_from"), first_seen_to: text("first_seen_to"),
  };
}
