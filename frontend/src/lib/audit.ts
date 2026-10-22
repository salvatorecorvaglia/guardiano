function fmtValue(v: unknown): string {
  if (v === null || v === undefined || v === "") return "–";
  if (Array.isArray(v)) return v.length ? v.map(fmtValue).join(", ") : "none";
  return String(v);
}

function isDiff(v: unknown): v is { from: unknown; to: unknown } {
  return typeof v === "object" && v !== null && !Array.isArray(v) && "from" in v && "to" in v;
}

/** Renders `{field: {from, to}}` as "field: from → to", and any other value as "field: value". */
export function describeChanges(changes: Record<string, unknown>): string[] {
  return Object.entries(changes).map(([k, v]) => (isDiff(v) ? `${k}: ${fmtValue(v.from)} → ${fmtValue(v.to)}` : `${k}: ${fmtValue(v)}`));
}
