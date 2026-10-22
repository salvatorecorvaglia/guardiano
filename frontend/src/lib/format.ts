import type { Finding, Severity, Status } from "../api/types";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export const CHART_SEVERITIES: Exclude<Severity, "info">[] = ["critical", "high", "medium", "low"];
export const STATUSES: Status[] = ["open", "in_progress", "false_positive", "risk_accepted", "resolved"];

export const STATUS_LABEL: Record<Status, string> = {
  open: "Open",
  in_progress: "In progress",
  false_positive: "False positive",
  risk_accepted: "Risk accepted",
  resolved: "Resolved",
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export const sevColor = (s: Severity) => `var(--sev-${s})`;

// Built once: an Intl formatter is expensive to construct, and relTime runs for every row of every
// table on every render -- it used to build a new one per call.
const nf = new Intl.NumberFormat();
const compactNf = new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 });
const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
export const fmtNum = (n: number | null | undefined) => (n == null ? "–" : nf.format(n));

export function compact(n: number): string {
  if (Math.abs(n) < 1000) return nf.format(n);
  return compactNf.format(n);
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "–";
  return new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

export function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return "–";
  return new Date(iso).toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function relTime(iso: string | null | undefined): string {
  if (!iso) return "never";
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ["year", 31536000],
    ["month", 2592000],
    ["week", 604800],
    ["day", 86400],
    ["hour", 3600],
    ["minute", 60],
  ];
  for (const [unit, secs] of units) {
    if (Math.abs(diff) >= secs) return rtf.format(-Math.round(diff / secs), unit);
  }
  return "just now";
}

export function shortDate(iso: string): string {
  return new Date(iso + (iso.length === 10 ? "T00:00:00" : "")).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
  });
}

type Located = Pick<Finding, "type" | "file_path" | "line_start" | "package_name" | "package_version"> &
  Partial<Pick<Finding, "resource" | "url" | "http_method" | "parameter">>;

/** Where a finding is, in one line: a package, a request, a resource, or a file and line. */
export function findingLocation(f: Located) {
  if (f.type === "sca") return f.package_name ? `${f.package_name}@${f.package_version ?? "?"}` : "";
  if (f.type === "dast") {
    const request = [f.http_method, f.url].filter(Boolean).join(" ");
    return f.parameter ? `${request} (${f.parameter})` : request;
  }
  const file = f.file_path ? `${f.file_path}${f.line_start ? `:${f.line_start}` : ""}` : "";
  if (f.type === "iac" && f.resource) return file ? `${f.resource} · ${file}` : f.resource;
  return file;
}

/** `YYYY-MM-DD` of an ISO timestamp in the user's timezone, for `<input type="date">`. */
export function toLocalDateInput(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** ISO timestamp of the last second of a `YYYY-MM-DD` day in the user's timezone. */
export function endOfLocalDay(date: string): string {
  const [y, m, d] = date.split("-").map(Number);
  return new Date(y, m - 1, d, 23, 59, 59).toISOString();
}
