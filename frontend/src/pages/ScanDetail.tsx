import { findingFilters } from "../api/findingFilters";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ArrowRight } from "lucide-react";
import { useState } from "react";
import { Link, useLocation, useParams } from "react-router-dom";
import { buildQuery } from "../api/client";
import { request } from "../api/typed";
import type { Finding, Scan } from "../api/types";
import GateBadge from "../components/GateBadge";
import { BackLink, EmptyState, ErrorBox, Pagination, SeverityBadge, Spinner, StatTile, StatusBadge, Tabs, TypeBadge, tabPanel } from "../components/ui";
import { findingLocation, fmtDateTime, fmtNum } from "../lib/format";

const PAGE_SIZE = 25;

type Tab = "new" | "gone" | "all";

/** Findings filters for each tab; the same query opens the full Findings page. */
function tabQuery(tab: Tab, scan: Scan, against: Scan | null | undefined): Record<string, string> | null {
  if (tab === "all") return { scan_id: String(scan.id) };
  if (!against) return tab === "new" ? { scan_id: String(scan.id) } : null;
  return tab === "new"
    ? { scan_id: String(scan.id), not_in_scan_id: String(against.id) }
    : { scan_id: String(against.id), not_in_scan_id: String(scan.id) };
}

function FindingList({ query }: { query: Record<string, string> }) {
  const location = useLocation();
  const [page, setPage] = useState(1);
  const list = useQuery({
    queryKey: ["findings", query, "-severity", page, PAGE_SIZE],
    queryFn: ({ signal }) => request("get", "/api/v1/findings", { signal, query: { ...findingFilters(query), sort: "-severity", page, page_size: PAGE_SIZE } }),
    placeholderData: keepPreviousData,
  });
  if (list.isLoading)
    return (
      <div className="flex justify-center py-10">
        <Spinner />
      </div>
    );
  if (list.error) return <ErrorBox error={list.error} />;
  const items = list.data?.items ?? [];
  if (!items.length) return <EmptyState title="No findings" />;
  return (
    <>
      <ul className="divide-y divide-line">
        {items.map((f) => (
          <li key={f.id} className="flex items-center gap-3 px-4 py-2.5">
            <SeverityBadge severity={f.severity} score={f.cvss_score} />
            <div className="min-w-0 flex-1">
              <Link
                to={`/findings/${f.id}`}
                state={{ from: `${location.pathname}${location.search}` }}
                className="line-clamp-1 text-sm font-medium hover:text-accent"
              >
                {f.title}
              </Link>
              <div className="flex items-center gap-2 text-xs text-muted">
                <TypeBadge type={f.type} />
                <span className="truncate font-mono">{findingLocation(f)}</span>
              </div>
            </div>
            <StatusBadge status={f.status} />
          </li>
        ))}
      </ul>
      <Pagination page={page} pageSize={PAGE_SIZE} total={list.data?.total ?? 0} onPage={setPage} />
    </>
  );
}

/** Header shared by ingested scans and previews. */
function ScanHeader({ scan }: { scan: Scan }) {
  return (
    <div className="mb-5">
      <div className="mb-1 flex flex-wrap items-center gap-2">
        <TypeBadge type={scan.scan_type} />
        <h1 className="text-xl font-semibold tracking-tight">
          {scan.tool_name} {scan.tool_version && <span className="text-base font-normal text-ink2">{scan.tool_version}</span>}
        </h1>
        <span className="text-sm text-muted">#{scan.id}</span>
        <GateBadge gate={scan.gate} />
      </div>
      <p className="text-sm text-ink2">
        <Link className="hover:text-accent" to={`/assets/${scan.asset.id}`}>
          {scan.asset.name}
        </Link>{" "}
        · {fmtDateTime(scan.created_at)} · {scan.source === "api" ? "API" : scan.source === "preview" ? "Preview" : "Upload"}
        {scan.uploaded_by && ` by ${scan.uploaded_by.full_name || scan.uploaded_by.email}`}
        {scan.branch && ` · ${scan.branch}`}
        {scan.commit_sha && <span className="ml-1 font-mono text-muted">{scan.commit_sha.slice(0, 12)}</span>}
        {scan.file_name && ` · ${scan.file_name}`} · {scan.format}
      </p>
    </div>
  );
}

function GatePanel({ scan }: { scan: Scan }) {
  if (!scan.gate || scan.gate.passed) return null;
  return (
    <div className="mb-4 rounded-xl border border-danger/40 bg-danger/5 p-4">
      <h2 className="mb-1 text-sm font-semibold text-danger">Quality gate failed</h2>
      <ul className="list-inside list-disc text-sm text-ink2">
        {scan.gate.violations.map((v) => (
          <li key={v.rule + (v.severity ?? "")}>{v.message}</li>
        ))}
      </ul>
      <p className="mt-2 text-xs text-muted">
        From the {scan.gate.policy_scope === "asset" ? "asset's" : "global"} policy. CI pipelines read this as
        <code className="mx-1 font-mono">gate.passed</code> on the upload response.
      </p>
    </div>
  );
}

/** A preview reports what a branch would add; nothing was written to the inventory. */
function PreviewDetail({ scan }: { scan: Scan }) {
  const preview = scan.preview;
  return (
    <>
      <BackLink to="/scans">Scans</BackLink>
      <ScanHeader scan={scan} />
      <div className="mb-4 rounded-xl border border-line bg-raised p-4 text-sm">
        <h2 className="mb-1 font-semibold">Preview only</h2>
        <p className="text-ink2">
          This report was evaluated as a preview{preview?.branch ? ` for branch ${preview.branch}` : ""}.
          Nothing was added to the inventory, and no finding was resolved.
        </p>
      </div>
      <GatePanel scan={scan} />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile label="Findings in report" value={fmtNum(preview?.counts.total ?? 0)} />
        <StatTile label="Would be new" value={fmtNum(preview?.counts.new ?? 0)} tone={preview?.counts.new ? "high" : undefined} />
        <StatTile label="Already known" value={fmtNum(preview?.counts.known ?? 0)} />
        <StatTile label="Quality gate" value={scan.gate ? (scan.gate.passed ? "Passed" : "Failed") : "–"} tone={scan.gate && !scan.gate.passed ? "danger" : undefined} />
      </div>
      <section className="card mt-4 overflow-hidden">
        <h2 className="px-4 py-3 text-sm font-semibold">
          New findings this branch would add {preview?.truncated && <span className="text-xs font-normal text-muted">(first {preview.new.length})</span>}
        </h2>
        {preview?.new.length ? (
          <ul className="divide-y divide-line">
            {preview.new.map((f, i) => (
              <li key={i} className="flex items-center gap-3 px-4 py-2.5">
                <SeverityBadge severity={f.severity as Finding["severity"]} score={f.cvss_score as number | null} />
                <div className="min-w-0 flex-1">
                  <div className="line-clamp-1 text-sm font-medium">{String(f.title)}</div>
                  <div className="truncate font-mono text-xs text-muted">
                    {f.file_path ? `${f.file_path}${f.line_start ? `:${f.line_start}` : ""}` : [f.package_name, f.package_version].filter(Boolean).join("@")}
                    {f.cve_id ? ` · ${f.cve_id}` : ""}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <EmptyState title="Nothing new">Every finding in this report is already known on the asset.</EmptyState>
        )}
      </section>
    </>
  );
}

export default function ScanDetail() {
  const { id } = useParams();
  return <ScanDetailPage key={id} />;
}

function ScanDetailPage() {
  const { id } = useParams();
  const [tab, setTab] = useState<Tab>("new");
  const scanQuery = useQuery({ queryKey: ["scan", id], queryFn: ({ signal }) => request("get", "/api/v1/scans/{scan_id}", { params: { scan_id: Number(id) }, signal }) });
  const isPreview = scanQuery.data?.source === "preview";
  const diff = useQuery({
    queryKey: ["scan", id, "diff"],
    queryFn: ({ signal }) => request("get", "/api/v1/scans/{scan_id}/diff", { params: { scan_id: Number(id) }, signal }),
    // A preview stores no findings, so it has nothing to diff.
    enabled: !!scanQuery.data && !isPreview,
  });

  if (scanQuery.isLoading || (diff.isLoading && !isPreview))
    return (
      <div className="flex justify-center py-20">
        <Spinner />
      </div>
    );
  if (!scanQuery.data) return <ErrorBox error={scanQuery.error ?? "Scan not found"} />;
  const scan = scanQuery.data;
  if (isPreview) return <PreviewDetail scan={scan} />;
  if (!diff.data) return <ErrorBox error={diff.error} />;
  const { against } = diff.data;
  const tabs: { key: Tab; label: string; count: number }[] = against
    ? [
        { key: "new", label: "New since previous scan", count: diff.data.new },
        { key: "gone", label: "No longer reported", count: diff.data.no_longer_reported },
        { key: "all", label: "All in this scan", count: scan.total_count },
      ]
    : [{ key: "all", label: "All in this scan", count: scan.total_count }];
  const active = tabs.some((t) => t.key === tab) ? tab : tabs[0].key;
  const query = tabQuery(active, scan, against);

  return (
    <>
      <BackLink to="/scans">Scans</BackLink>
      <ScanHeader scan={scan} />
      <GatePanel scan={scan} />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile label="Findings in report" value={fmtNum(scan.total_count)} />
        <StatTile label="New to Guardiano" value={fmtNum(scan.new_count)} hint="Never seen on this asset before" />
        <StatTile label="Reopened" value={fmtNum(scan.reopened_count)} />
        <StatTile label="Auto-resolved" value={fmtNum(scan.auto_resolved_count)} hint="With close_missing" />
      </div>

      <section className="card mt-4 overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 pt-3">
          <Tabs
            id="scan-findings"
            label="Findings in this scan"
            tabs={tabs.map((t) => ({
              key: t.key,
              label: (
                <>
                  {t.label} <span className="tabular text-muted">{fmtNum(t.count)}</span>
                </>
              ),
            }))}
            active={active}
            onChange={setTab}
          />
          {query && (
            <Link to={`/findings${buildQuery(query)}`} className="mb-2 inline-flex items-center gap-1 text-xs text-accent hover:underline">
              Open in Findings <ArrowRight className="h-3 w-3" />
            </Link>
          )}
        </div>
        <p className="px-4 pt-2 text-xs text-muted">
          {against ? (
            <>
              Compared with{" "}
              <Link className="text-accent hover:underline" to={`/scans/${against.id}`}>
                scan #{against.id}
              </Link>{" "}
              ({against.tool_name}, {fmtDateTime(against.created_at)}). {fmtNum(diff.data.unchanged)} finding
              {diff.data.unchanged === 1 ? " is" : "s are"} in both.
            </>
          ) : (
            <>First {scan.tool_name} scan of this asset, so there is nothing to compare with.</>
          )}
        </p>
        <div {...tabPanel("scan-findings", active)}>{query && <FindingList key={active} query={query} />}</div>
      </section>
    </>
  );
}
