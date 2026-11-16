/** Columns a viewer may hide. Severity, the finding itself and status always show. */
export const OPTIONAL_COLUMNS = [
  { key: "priority", label: "Priority" },
  { key: "asset", label: "Asset" },
  { key: "exploit", label: "Exploitability" },
  { key: "due", label: "Due" },
  { key: "tools", label: "Tools" },
  { key: "first_seen", label: "First seen" },
  { key: "assignee", label: "Assignee" },
] as const;
export type OptionalColumn = (typeof OPTIONAL_COLUMNS)[number]["key"];
const COLUMNS_KEY = "guardiano.findings.hidden-columns";

// A per-viewer convenience: storage can be missing or refuse (private windows), and then every column shows.
export function loadHidden(): ReadonlySet<OptionalColumn> {
  try {
    const raw = JSON.parse(localStorage.getItem(COLUMNS_KEY) ?? "[]");
    const known = new Set<string>(OPTIONAL_COLUMNS.map((c) => c.key));
    return new Set(Array.isArray(raw) ? raw.filter((k): k is OptionalColumn => known.has(k)) : []);
  } catch {
    return new Set();
  }
}

export function saveHidden(hidden: ReadonlySet<OptionalColumn>) {
  try {
    localStorage.setItem(COLUMNS_KEY, JSON.stringify([...hidden]));
  } catch {
    // Not remembered; the choice still applies until the page is left.
  }
}

