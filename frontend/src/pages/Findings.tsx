import FilterControls from "../components/findings/FilterControls";
import BulkActions from "../components/findings/BulkActions";
import { findingFilters } from "../api/findingFilters";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { ArrowDown, ArrowUp, Bug } from "lucide-react";
import { type FormEvent, type ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { invalidateAfterTriage } from "../api/queries";
import { download, request } from "../api/typed";
import type { BulkChange } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import FindingRow from "../components/findings/FindingRow";
import { ColumnChooser } from "../components/findings/ColumnChooser";
import { loadHidden, saveHidden, type OptionalColumn } from "../components/findings/columns";
import SavedViews from "../components/SavedViews";
import StatusDialog, { type StatusChange } from "../components/StatusDialog";
import { useToast } from "../components/Toaster";
import { EmptyState, ErrorBox, PageHeader, Pagination, Spinner } from "../components/ui";
import { useFindingSelection } from "../hooks/useFindingSelection";
import { endOfLocalDay, fmtNum } from "../lib/format";
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
  const { can } = useAuth();
  const qc = useQueryClient();

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

      <FilterControls params={params} update={update} q={q} setQ={setQ} toggleList={toggleList}
        activeFilters={activeFilters} onClear={() => { setQ(""); update(Object.fromEntries([...LIST_KEYS, ...SCALAR_KEYS].map((key) => [key, null]))); }} />

      {targetsReady && selected.size > 0 && can("analyst") && (
        <BulkActions selection={{ count: selected.size, allMatching, allSelected, total, pageCount: items.length }}
          pending={bulk.isPending} canManage={can("manager")} tag={bulkTag} onTag={setBulkTag}
          onAddTag={addBulkTag} onRemoveTag={removeBulkTag} onChangeStatus={() => setStatusOpen(true)}
          onChange={(change) => bulk.mutate(change)} onSelectAll={() => setAllMatching(true)}
          onClear={() => { setSelected(new Set()); setAllMatching(false); }} />
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
