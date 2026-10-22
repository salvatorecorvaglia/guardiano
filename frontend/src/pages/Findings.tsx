import { findingFilters } from "../api/findingFilters";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { ArrowDown, ArrowUp, Bug, CalendarClock, Search, Tag, UserPlus, X } from "lucide-react";
import { type FormEvent, memo, type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { invalidateAfterTriage, useAssetOptions, useDirectory, useProducts } from "../api/queries";
import { download, request } from "../api/typed";
import type { BulkChange, Finding, Severity, Status } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import ExploitBadge from "../components/ExploitBadge";
import SavedViews from "../components/SavedViews";
import StatusDialog, { type StatusChange } from "../components/StatusDialog";
import { useToast } from "../components/Toaster";
import { EmptyState, ErrorBox, PageHeader, Pagination, SeverityBadge, Spinner, StatusBadge, TypeBadge } from "../components/ui";
import { useFindingSelection } from "../hooks/useFindingSelection";
import { endOfLocalDay, findingLocation, fmtDate, fmtNum, relTime, SEVERITIES, SEVERITY_LABEL, STATUS_LABEL, STATUSES, sevColor } from "../lib/format";
import { useClampPage, useDebouncedParam, useUrlParams, validCalendarDate } from "../lib/urlState";

const PAGE_SIZE = 50;
const LIST_KEYS = ["severity", "status", "asset_id", "tag"] as const;
const SCALAR_KEYS = [
  "q", "type", "tool", "cwe", "cve", "package", "overdue", "assignee_id", "unassigned", "scan_id", "not_in_scan_id",
  "kev", "epss_min", "ticket_done", "first_seen_from", "first_seen_to", "product_id", "environment",
] as const;

/** The URL keeps plain dates; the API wants instants, and "to" means the whole of that day. */
function localDayBounds(from: string | undefined, to: string | undefined) {
  const out: Record<string, string> = {};
  if (from && validCalendarDate(from)) {
    const [y, m, d] = from.split("-").map(Number);
    out.first_seen_from = new Date(y, m - 1, d).toISOString();
  }
  if (to && validCalendarDate(to)) out.first_seen_to = endOfLocalDay(to);
  return out;
}
const EXPORTS = [
  { ext: "csv", label: "CSV (spreadsheets)" },
  { ext: "json", label: "JSON" },
  { ext: "sarif", label: "SARIF 2.1.0" },
] as const;

/** Columns a viewer may hide. Severity, the finding itself and status always show. */
const OPTIONAL_COLUMNS = [
  { key: "priority", label: "Priority" },
  { key: "asset", label: "Asset" },
  { key: "exploit", label: "Exploitability" },
  { key: "due", label: "Due" },
  { key: "tools", label: "Tools" },
  { key: "first_seen", label: "First seen" },
  { key: "assignee", label: "Assignee" },
] as const;
type OptionalColumn = (typeof OPTIONAL_COLUMNS)[number]["key"];
const COLUMNS_KEY = "guardiano.findings.hidden-columns";

// A per-viewer convenience: storage can be missing or refuse (private windows), and then every column shows.
function loadHidden(): ReadonlySet<OptionalColumn> {
  try {
    const raw = JSON.parse(localStorage.getItem(COLUMNS_KEY) ?? "[]");
    const known = new Set<string>(OPTIONAL_COLUMNS.map((c) => c.key));
    return new Set(Array.isArray(raw) ? raw.filter((k): k is OptionalColumn => known.has(k)) : []);
  } catch {
    return new Set();
  }
}

function saveHidden(hidden: ReadonlySet<OptionalColumn>) {
  try {
    localStorage.setItem(COLUMNS_KEY, JSON.stringify([...hidden]));
  } catch {
    // Not remembered; the choice still applies until the page is left.
  }
}

function ColumnChooser({ hidden, onChange }: { hidden: ReadonlySet<OptionalColumn>; onChange: (h: ReadonlySet<OptionalColumn>) => void }) {
  return (
    <details className="relative">
      <summary className="btn-secondary cursor-pointer list-none">Columns</summary>
      <div className="absolute right-0 z-20 mt-1 w-44 space-y-1 rounded-lg border border-line bg-raised p-2 shadow-lg">
        {OPTIONAL_COLUMNS.map((c) => (
          <label key={c.key} className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={!hidden.has(c.key)}
              onChange={() => {
                const next = new Set(hidden);
                if (next.has(c.key)) next.delete(c.key);
                else next.add(c.key);
                onChange(next);
              }}
            />
            {c.label}
          </label>
        ))}
      </div>
    </details>
  );
}

function Chip({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      aria-pressed={active}
      className={clsx(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium transition-colors",
        active ? "border-accent bg-accent/10 text-ink" : "border-line bg-raised text-ink2 hover:text-ink",
      )}
    >
      {children}
    </button>
  );
}

function SortHeader({
  k,
  sort,
  onSort,
  children,
  className,
}: {
  k: string;
  sort: string;
  onSort: (k: string) => void;
  children: ReactNode;
  className?: string;
}) {
  return (
    <th className={clsx("th", className)} aria-sort={sort === k ? "ascending" : sort === `-${k}` ? "descending" : "none"}>
      <button className="inline-flex items-center gap-1 hover:text-ink" onClick={() => onSort(k)}>
        {children}
        {sort === k && <ArrowUp className="h-3 w-3" />}
        {sort === `-${k}` && <ArrowDown className="h-3 w-3" />}
      </button>
    </th>
  );
}

export default function Findings() {
  const { params, update, page } = useUrlParams();
  const navigate = useNavigate();
  const location = useLocation();
  const toast = useToast();
  const { can, user } = useAuth();
  const qc = useQueryClient();
  const assets = useAssetOptions();
  const products = useProducts();
  const directory = useDirectory();

  const sort = params.get("sort") || "-severity";
  const [q, setQ] = useDebouncedParam("q", params, update);
  const { selected, allMatching, setSelected, setAllMatching, toggleOne } = useFindingSelection(location.search);
  const [hidden, setHiddenState] = useState<ReadonlySet<OptionalColumn>>(loadHidden);
  const setHidden = (next: ReadonlySet<OptionalColumn>) => {
    setHiddenState(next);
    saveHidden(next);
  };
  const shown = (key: OptionalColumn) => !hidden.has(key);
  const [statusOpen, setStatusOpen] = useState(false);
  const [bulkTag, setBulkTag] = useState("");
  // Detail pages link back to this exact list (filters, sort and page).
  const backState = { from: `${location.pathname}${location.search}` };
  const canTriage = can("analyst");
  const [dateWarning, setDateWarning] = useState(false);
  useEffect(() => {
    const invalidDates = ["first_seen_from", "first_seen_to"].filter((key) => params.has(key) && !validCalendarDate(params.get(key)));
    if (invalidDates.length) { setDateWarning(true); update(Object.fromEntries(invalidDates.map((key) => [key, null]))); }
  }, [params, update]);
  // Read through a ref so the rows get one function for the life of the page, not a new one per render.
  const latest = useRef({ navigate, backState, params, toggleList });
  const openFinding = useCallback(
    (id: number) => latest.current.navigate(`/findings/${id}`, { state: latest.current.backState }),
    [],
  );
  const filterByTag = useCallback((tag: string) => {
    const { params, toggleList } = latest.current;
    if (!params.getAll("tag").includes(tag)) toggleList("tag", tag);
  }, []);

  const query = useMemo(() => {
    const out: Record<string, string | string[]> = {};
    for (const k of LIST_KEYS) {
      const v = params.getAll(k);
      if (v.length) out[k] = v;
    }
    for (const k of SCALAR_KEYS.filter((key) => !key.startsWith("first_seen_"))) {
      const v = params.get(k);
      if (v) out[k] = v;
    }
    return { ...out, ...localDayBounds(params.get("first_seen_from") ?? undefined, params.get("first_seen_to") ?? undefined) };
  }, [params]);

  const list = useQuery({
    queryKey: ["findings", query, sort, page],
    queryFn: ({ signal }) => request("get", "/api/v1/findings", { signal, query: { ...findingFilters(query), sort, page, page_size: PAGE_SIZE } }),
    placeholderData: keepPreviousData,
  });

  useClampPage(page, PAGE_SIZE, list.data?.total, update, list.isPlaceholderData);

  function toggleList(key: "severity" | "status" | "tag", value: string) {
    const cur = params.getAll(key);
    update({ [key]: cur.includes(value) ? cur.filter((x) => x !== value) : [...cur, value] });
  }

  latest.current = { navigate, backState, params, toggleList };

  function toggleSort(key: string) {
    // Back to page 1, as on Assets: page 7 of a different ordering is not where anybody meant to be.
    update({ sort: sort === `-${key}` ? key : `-${key}` });
  }

  const targetsReady = !list.isPlaceholderData && !list.isFetching && !list.isError;
  const bulk = useMutation({
    mutationFn: (body: BulkChange) => {
      if (!targetsReady) throw new Error("Wait for the current results before changing findings");
      const targets = { matching: allMatching, query: { ...query }, ids: [...selected] };
      return targets.matching
        ? request("post", "/api/v1/findings/bulk/matching", { body, query: findingFilters(targets.query) })
        : request("post", "/api/v1/findings/bulk", { body: { ids: targets.ids, ...body } });
    },
    onSuccess: (r) => {
      toast(`Updated ${r.updated} finding${r.updated === 1 ? "" : "s"}`);
      setStatusOpen(false);
      setSelected(new Set());
      setAllMatching(false);
      invalidateAfterTriage(qc);
    },
  });
  const exporter = useMutation({
    mutationFn: (ext: typeof EXPORTS[number]["ext"]) => download(`/api/v1/findings/export.${ext}`, { query: { ...findingFilters(query), sort } }, `guardiano-findings.${ext}`),
  });

  function addBulkTag(e: FormEvent) {
    e.preventDefault();
    const tag = bulkTag.trim().toLowerCase();
    if (tag) bulk.mutate({ add_tags: [tag] }, { onSuccess: () => setBulkTag("") });
  }

  function removeBulkTag() {
    const tag = bulkTag.trim().toLowerCase();
    if (tag) bulk.mutate({ remove_tags: [tag] }, { onSuccess: () => setBulkTag("") });
  }

  const items = list.data?.items ?? [];
  const allSelected = items.length > 0 && items.every((f) => selected.has(f.id));
  const total = list.data?.total ?? 0;
  const selectedCount = allMatching ? total : selected.size;
  const activeFilters = [...LIST_KEYS, ...SCALAR_KEYS].some((k) => params.has(k));
  const sevSel = params.getAll("severity") as Severity[];
  const statusSel = params.getAll("status") as Status[];

  return (
    <>
      {dateWarning && <p role="status" className="mb-3 text-sm text-warn">Invalid date filters were removed. Choose a valid calendar date.</p>}
      <PageHeader
        title="Findings"
        subtitle="Deduplicated SAST, SCA, IaC and DAST findings across all assets"
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <SavedViews search={location.search} />
            <ColumnChooser hidden={hidden} onChange={setHidden} />
            <select
              className="input w-auto"
              aria-label="Export findings"
              value=""
              disabled={exporter.isPending}
              onChange={(e) => e.target.value && exporter.mutate(e.target.value as typeof EXPORTS[number]["ext"])}
            >
              <option value="">{exporter.isPending ? "Exporting…" : "Export…"}</option>
              {EXPORTS.map((x) => (
                <option key={x.ext} value={x.ext}>
                  {x.label}
                </option>
              ))}
            </select>
          </div>
        }
      />

      <div className="card mb-4 space-y-3 p-3">
        <div className="flex flex-wrap gap-2">
          <div className="relative min-w-[240px] flex-1">
            <Search className="pointer-events-none absolute left-2.5 top-2 h-4 w-4 text-muted" />
            <input
              className="input pl-8"
              placeholder="Search title, CVE, package, file, rule…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              aria-label="Search findings"
            />
          </div>
          {!!products.data?.length && (
            <select className="input w-auto" value={params.get("product_id") ?? ""} onChange={(e) => update({ product_id: e.target.value || null })} aria-label="Product">
              <option value="">All products</option>
              {products.data.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          )}
          <select className="input w-auto" value={params.get("environment") ?? ""} onChange={(e) => update({ environment: e.target.value || null })} aria-label="Environment">
            <option value="">Any environment</option>
            {["production", "staging", "development", "test"].map((e) => (
              <option key={e} value={e}>
                {e}
              </option>
            ))}
          </select>
          <select className="input w-auto" value={params.get("asset_id") ?? ""} onChange={(e) => update({ asset_id: e.target.value || null })} aria-label="Asset">
            <option value="">All assets</option>
            {assets.data?.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
          <select className="input w-auto" value={params.get("type") ?? ""} onChange={(e) => update({ type: e.target.value || null })} aria-label="Type">
            <option value="">All types</option>
            <option value="sast">SAST (code)</option>
            <option value="sca">SCA (dependencies)</option>
            <option value="iac">IaC (infrastructure)</option>
            <option value="dast">DAST (running apps)</option>
          </select>
          <select
            className="input w-auto"
            value={params.get("unassigned") ? "none" : params.get("assignee_id") ?? ""}
            onChange={(e) => {
              const v = e.target.value;
              update({ unassigned: v === "none" ? "true" : null, assignee_id: v && v !== "none" ? v : null });
            }}
            aria-label="Assignee"
          >
            <option value="">Any assignee</option>
            <option value={String(user?.id)}>Assigned to me</option>
            <option value="none">Unassigned</option>
            {directory.data
              ?.filter((u) => u.id !== user?.id)
              .map((u) => (
                <option key={u.id} value={u.id}>
                  {u.full_name || u.email}
                </option>
              ))}
          </select>
        </div>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-xs text-muted">Severity</span>
            {SEVERITIES.map((s) => (
              <Chip key={s} active={sevSel.includes(s)} onClick={() => toggleList("severity", s)}>
                <span className="h-2 w-2 rounded-full" style={{ background: sevColor(s) }} />
                {SEVERITY_LABEL[s]}
              </Chip>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-xs text-muted">Status</span>
            {STATUSES.map((s) => (
              <Chip key={s} active={statusSel.includes(s)} onClick={() => toggleList("status", s)}>
                {STATUS_LABEL[s]}
              </Chip>
            ))}
          </div>
          <Chip active={params.get("overdue") === "true"} onClick={() => update({ overdue: params.get("overdue") ? null : "true" })}>
            Past SLA
          </Chip>
          <Chip active={params.get("kev") === "true"} onClick={() => update({ kev: params.get("kev") ? null : "true" })}>
            Known exploited
          </Chip>
          <Chip active={!!params.get("epss_min")} onClick={() => update({ epss_min: params.get("epss_min") ? null : "0.1" })}>
            EPSS ≥ 10%
          </Chip>
          <span title="Still open here, but the linked ticket was closed in the tracker">
            <Chip active={params.get("ticket_done") === "true"} onClick={() => update({ ticket_done: params.get("ticket_done") ? null : "true" })}>
              Ticket closed
            </Chip>
          </span>
          <label className="flex items-center gap-1 text-xs text-muted">
            First seen
            <input
              type="date"
              className="input w-auto px-2 py-0.5 text-xs"
              aria-label="First seen from"
              value={params.get("first_seen_from") ?? ""}
              onChange={(e) => update({ first_seen_from: e.target.value || null })}
            />
            –
            <input
              type="date"
              className="input w-auto px-2 py-0.5 text-xs"
              aria-label="First seen to"
              value={params.get("first_seen_to") ?? ""}
              onChange={(e) => update({ first_seen_to: e.target.value || null })}
            />
          </label>
          {params.getAll("tag").map((t) => (
            <Chip key={`tag-${t}`} active onClick={() => toggleList("tag", t)}>
              <Tag className="h-3 w-3" /> {t} <X className="h-3 w-3" />
            </Chip>
          ))}
          {params.get("scan_id") && (
            <Chip active onClick={() => update({ scan_id: null })}>
              In scan #{params.get("scan_id")} <X className="h-3 w-3" />
            </Chip>
          )}
          {params.get("not_in_scan_id") && (
            <Chip active onClick={() => update({ not_in_scan_id: null })}>
              Not in scan #{params.get("not_in_scan_id")} <X className="h-3 w-3" />
            </Chip>
          )}
          {(["cwe", "cve", "package", "tool"] as const).map(
            (k) =>
              params.get(k) && (
                <Chip key={k} active onClick={() => update({ [k]: null })}>
                  {k}: {params.get(k)} <X className="h-3 w-3" />
                </Chip>
              ),
          )}
          {activeFilters && (
            <button
              className="text-xs text-accent hover:underline"
              onClick={() => {
                setQ("");
                update(Object.fromEntries([...LIST_KEYS, ...SCALAR_KEYS].map((k) => [k, null])));
              }}
            >
              Clear all
            </button>
          )}
        </div>
      </div>

      {targetsReady && selected.size > 0 && can("analyst") && (
        <fieldset disabled={bulk.isPending} className="sticky top-0 z-10 mb-3 flex flex-wrap items-center gap-2 rounded-lg border border-accent/40 bg-raised px-3 py-2 shadow-sm">
          <span className="text-sm font-medium">
            {allMatching ? `All ${fmtNum(total)} matching selected` : `${selected.size} selected`}
          </span>
          {allSelected && !allMatching && total > items.length && (
            <button className="text-xs text-accent hover:underline" onClick={() => setAllMatching(true)}>
              Select all {fmtNum(total)} matching
            </button>
          )}
          <button className="btn-secondary py-1" onClick={() => setStatusOpen(true)}>
            Change status
          </button>
          <form className="flex items-center gap-1" onSubmit={addBulkTag}>
            <Tag className="h-4 w-4 text-muted" />
            <input
              className="input w-36 py-1"
              placeholder="Add tag…"
              aria-label="Add tag to selected"
              value={bulkTag}
              maxLength={64}
              onChange={(e) => setBulkTag(e.target.value)}
            />
            <button type="button" className="btn-ghost py-1 text-xs" disabled={!bulkTag.trim()} onClick={removeBulkTag}>
              Remove
            </button>
          </form>
          {can("manager") && (
            <div className="flex items-center gap-1">
              <CalendarClock className="h-4 w-4 text-muted" />
              <input
                className="input w-auto py-1"
                type="date"
                aria-label="Set due date for selected"
                value=""
                onChange={(e) => e.target.value && bulk.mutate({ due_at: endOfLocalDay(e.target.value) })}
              />
              <button className="btn-ghost py-1 text-xs" onClick={() => bulk.mutate({ clear_due_at: true })}>
                Reset to SLA
              </button>
            </div>
          )}
          <div className="flex items-center gap-1">
            <UserPlus className="h-4 w-4 text-muted" />
            <select
              className="input w-auto py-1"
              value=""
              onChange={(e) => {
                const v = e.target.value;
                if (v) bulk.mutate(v === "none" ? { unassign: true } : { assignee_id: Number(v) });
              }}
              aria-label="Assign selected"
            >
              <option value="">Assign to…</option>
              <option value="none">Unassign</option>
              {directory.data?.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.full_name || u.email}
                </option>
              ))}
            </select>
          </div>
          <button
            className="btn-ghost ml-auto py-1"
            onClick={() => {
              setSelected(new Set());
              setAllMatching(false);
            }}
          >
            Clear selection
          </button>
        </fieldset>
      )}

      <ErrorBox error={list.error || bulk.error || exporter.error} />

      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b border-line bg-page/50">
              <tr>
                {can("analyst") && (
                  <th className="th w-8">
                    <input
                      type="checkbox"
                      aria-label="Select all on page"
                      disabled={!targetsReady || bulk.isPending}
                      checked={allSelected}
                      onChange={() => {
                        setAllMatching(false);
                        setSelected(allSelected ? new Set() : new Set(items.map((f) => f.id)));
                      }}
                    />
                  </th>
                )}
                <SortHeader k="severity" sort={sort} onSort={toggleSort}>
                  Severity
                </SortHeader>
                {shown("priority") && (
                  <SortHeader k="priority" sort={sort} onSort={toggleSort}>
                    <span title="Severity weighted by exploitability (KEV, EPSS) and asset criticality">Priority</span>
                  </SortHeader>
                )}
                <SortHeader k="title" sort={sort} onSort={toggleSort}>
                  Finding
                </SortHeader>
                {shown("asset") && <th className="th">Asset</th>}
                <SortHeader k="status" sort={sort} onSort={toggleSort}>
                  Status
                </SortHeader>
                {shown("exploit") && (
                  <SortHeader k="epss" sort={sort} onSort={toggleSort}>
                    Exploitability
                  </SortHeader>
                )}
                {shown("due") && (
                  <SortHeader k="due" sort={sort} onSort={toggleSort}>
                    Due
                  </SortHeader>
                )}
                {shown("tools") && <th className="th">Tools</th>}
                {shown("first_seen") && (
                  <SortHeader k="first_seen" sort={sort} onSort={toggleSort}>
                    First seen
                  </SortHeader>
                )}
                {shown("assignee") && <th className="th">Assignee</th>}
              </tr>
            </thead>
            <tbody className={clsx("divide-y divide-line", list.isFetching && "opacity-70")}>
              {items.map((f) => (
                <FindingRow
                  key={f.id}
                  f={f}
                  from={backState.from}
                  selectable={canTriage}
                  selectionDisabled={!targetsReady || bulk.isPending}
                  checked={selected.has(f.id)}
                  onToggle={toggleOne}
                  onOpen={openFinding}
                  onTag={filterByTag}
                  hidden={hidden}
                />
              ))}
            </tbody>
          </table>
        </div>
        {list.isLoading && (
          <div className="flex justify-center py-12">
            <Spinner />
          </div>
        )}
        {list.data && items.length === 0 && (
          <EmptyState icon={<Bug className="h-8 w-8" />} title="No findings match these filters">
            Adjust the filters or upload a scan to get started.
          </EmptyState>
        )}
        {list.data && list.data.total > 0 && (
          <Pagination page={page} pageSize={PAGE_SIZE} total={list.data.total} onPage={(p) => update({ page: String(p) }, true)} />
        )}
      </div>
      {list.data && (
        <p className="mt-2 text-xs text-muted">
          {fmtNum(list.data.total)} finding{list.data.total === 1 ? "" : "s"}
        </p>
      )}

      {statusOpen && (
        <StatusDialog
          open
          count={selectedCount}
          onClose={() => setStatusOpen(false)}
          pending={bulk.isPending || !targetsReady}
          error={bulk.error}
          onSubmit={(c: StatusChange) => bulk.mutate({ ...c })}
        />
      )}
    </>
  );
}

/**
 * One row, memoised. Typing in the search box re-renders the page and ticking a checkbox changes the
 * selection; before this, both re-rendered all fifty rows and every badge and formatter in them. The
 * callbacks it receives never change identity, and react-query keeps unchanged findings the same
 * objects between fetches, so a row renders again only when its own finding or checkbox changes.
 */
const FindingRow = memo(function FindingRow({
  f,
  from,
  selectable,
  selectionDisabled,
  checked,
  onToggle,
  onOpen,
  onTag,
  hidden,
}: {
  f: Finding;
  from: string;
  selectable: boolean;
  selectionDisabled: boolean;
  checked: boolean;
  onToggle: (id: number) => void;
  onOpen: (id: number) => void;
  onTag: (tag: string) => void;
  hidden: ReadonlySet<OptionalColumn>;
}) {
  const back = { from };
  const shown = (key: OptionalColumn) => !hidden.has(key);
  return (
        <tr
          className="cursor-pointer hover:bg-ink/[0.03]"
          onClick={(e) => {
            if ((e.target as HTMLElement).closest("input,a,button")) return;
            onOpen(f.id);
          }}
        >
          {selectable && (
            <td className="td w-8">
              <input
                type="checkbox"
                aria-label={`Select finding ${f.id}`}
                disabled={selectionDisabled}
                checked={checked}
                onChange={() => onToggle(f.id)}
              />
            </td>
          )}
          <td className="td">
            <SeverityBadge severity={f.severity} score={f.cvss_score} />
          </td>
          {shown("priority") && <td className="td text-right font-mono text-xs tabular-nums text-ink2">{(f.priority ?? 0).toFixed(1)}</td>}
          <td className="td max-w-[480px]">
            <Link to={`/findings/${f.id}`} state={back} className="line-clamp-1 font-medium hover:text-accent">
              {f.title}
            </Link>
            <div className="mt-0.5 flex items-center gap-2 text-xs text-muted">
              <TypeBadge type={f.type} />
              <span className="truncate font-mono">{findingLocation(f)}</span>
              {f.cwe[0] && <span className="shrink-0">{f.cwe[0]}</span>}
              {f.cve_id && <span className="shrink-0">{f.cve_id}</span>}
              {f.tags?.map((t) => (
                <button
                  key={t}
                  className="shrink-0 rounded bg-ink/5 px-1.5 py-px text-[11px] text-ink2 hover:bg-accent/10 hover:text-ink"
                  title={`Filter by tag ${t}`}
                  onClick={() => onTag(t)}
                >
                  {t}
                </button>
              ))}
            </div>
          </td>
          {shown("asset") && <td className="td whitespace-nowrap text-ink2">{f.asset.name}</td>}
          <td className="td">
            <StatusBadge status={f.status} />
            {f.overdue && <div className="mt-0.5 text-[11px] font-medium text-danger">Past SLA</div>}
          </td>
          {shown("exploit") && (
            <td className="td whitespace-nowrap">
              <ExploitBadge finding={f} />
            </td>
          )}
          {shown("due") && (
            <td
              className={clsx("td whitespace-nowrap text-xs", f.overdue ? "font-medium text-danger" : "text-ink2")}
              title={f.due_at_override ? "Due date set manually" : "From the remediation SLA"}
            >
              {f.sla_due_at ? fmtDate(f.sla_due_at) : "–"}
              {f.due_at_override && <span className="ml-0.5">*</span>}
            </td>
          )}
          {shown("tools") && <td className="td text-xs text-ink2">{f.tools.join(", ")}</td>}
          {shown("first_seen") && (
            <td className="td whitespace-nowrap text-xs text-ink2" title={fmtDate(f.first_seen_at)}>
              {relTime(f.first_seen_at)}
            </td>
          )}
          {shown("assignee") && (
            <td className="td whitespace-nowrap text-xs text-ink2">{f.assignee ? f.assignee.full_name || f.assignee.email : "–"}</td>
          )}
        </tr>
  );
});
