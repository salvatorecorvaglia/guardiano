import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Boxes, Plus, Search } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useProducts } from "../api/queries";
import { request } from "../api/typed";
import { useAuth } from "../auth/AuthContext";
import AssetForm from "../components/AssetForm";
import { CriticalityTag, EmptyState, ErrorBox, PageHeader, Pagination, SeverityBar, Spinner } from "../components/ui";
import { fmtNum, relTime } from "../lib/format";
import { optionalNumber, useClampPage, useDebouncedParam, useUrlParams } from "../lib/urlState";

const PAGE_SIZE = 25;

const SORTS = [
  ["-risk", "Highest risk"],
  ["-open", "Most open findings"],
  ["-last_scan", "Recently scanned"],
  ["name", "Name"],
] as const;

export default function Assets() {
  const { can } = useAuth();
  const navigate = useNavigate();
  const { params, update, page } = useUrlParams();
  const [search, setSearch] = useDebouncedParam("q", params, update);
  const q = params.get("q") ?? "";
  const sort = params.get("sort") || "-risk";
  const productId = params.get("product_id") ?? "";
  const environment = params.get("environment") ?? "";
  const products = useProducts();
  const [creating, setCreating] = useState(false);

  const list = useQuery({
    queryKey: ["assets", "list", q, sort, page, productId, environment],
    queryFn: ({ signal }) =>
      request("get", "/api/v1/assets", {
        signal,
        query: { q, sort, page, page_size: PAGE_SIZE, product_id: optionalNumber(productId), environment: environment || undefined },
      }),
    placeholderData: keepPreviousData,
  });
  useClampPage(page, PAGE_SIZE, list.data?.total, update, list.isPlaceholderData);

  return (
    <>
      <PageHeader
        title="Assets"
        subtitle="Applications, services and repositories under management"
        actions={
          can("manager") && (
            <button className="btn-primary" onClick={() => setCreating(true)}>
              <Plus className="h-4 w-4" /> New asset
            </button>
          )
        }
      />
      <div className="mb-4 flex flex-wrap gap-2">
        <div className="relative min-w-[220px] flex-1 sm:max-w-sm">
          <Search className="pointer-events-none absolute left-2.5 top-2 h-4 w-4 text-muted" />
          <input
            className="input pl-8"
            placeholder="Search name, owner or tag…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Search assets"
          />
        </div>
        {!!products.data?.length && (
          <select className="input w-auto" value={productId} onChange={(e) => update({ product_id: e.target.value || null })} aria-label="Product">
            <option value="">All products</option>
            {products.data.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        )}
        <select className="input w-auto" value={environment} onChange={(e) => update({ environment: e.target.value || null })} aria-label="Environment">
          <option value="">Any environment</option>
          {["production", "staging", "development", "test"].map((e) => (
              <option key={e} value={e}>
                {e}
              </option>
            ))}
        </select>
        <select className="input w-auto" value={sort} onChange={(e) => update({ sort: e.target.value === "-risk" ? null : e.target.value })} aria-label="Sort">
          {SORTS.map(([v, l]) => (
            <option key={v} value={v}>
              {l}
            </option>
          ))}
        </select>
      </div>
      <ErrorBox error={list.error} />
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-b border-line bg-page/50">
              <tr>
                <th className="th">Asset</th>
                <th className="th">Criticality</th>
                <th className="th w-[28%]">Open by severity</th>
                <th className="th text-right">Open</th>
                <th className="th text-right">Risk score</th>
                <th className="th">Last scan</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {list.data?.items.map((a) => (
                <tr key={a.id} className="cursor-pointer hover:bg-ink/[0.03]" onClick={() => navigate(`/assets/${a.id}`)}>
                  <td className="td">
                    <Link to={`/assets/${a.id}`} className="font-medium hover:text-accent">
                      {a.name}
                    </Link>
                    <div className="text-xs text-muted">
                      {a.type}
                      {a.owner && ` · ${a.owner}`}
                      {a.tags.length > 0 && ` · ${a.tags.join(", ")}`}
                    </div>
                  </td>
                  <td className="td">
                    <CriticalityTag value={a.criticality} />
                  </td>
                  <td className="td">
                    <SeverityBar counts={a.open_counts} />
                    <div className="tabular mt-1 text-[11px] text-muted">
                      {a.open_counts.critical} C · {a.open_counts.high} H · {a.open_counts.medium} M · {a.open_counts.low} L
                    </div>
                  </td>
                  <td className="td tabular text-right">{fmtNum(a.open_total)}</td>
                  <td className="td tabular text-right font-semibold">{a.risk_score}</td>
                  <td className="td whitespace-nowrap text-xs text-ink2">{relTime(a.last_scan_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {list.isLoading && (
          <div className="flex justify-center py-12">
            <Spinner />
          </div>
        )}
        {list.data?.items.length === 0 && (
          <EmptyState icon={<Boxes className="h-8 w-8" />} title={q ? "No assets match this search" : "No assets yet"}>
            {q ? "Try a different name, owner or tag." : "Assets are created automatically when you upload a scan, or manually by a Security Manager."}
          </EmptyState>
        )}
        {list.data && list.data.total > 0 && (
          <Pagination page={page} pageSize={PAGE_SIZE} total={list.data.total} onPage={(p) => update({ page: String(p) }, true)} />
        )}
      </div>
      {creating && <AssetForm onClose={() => setCreating(false)} onSaved={(a) => navigate(`/assets/${a.id}`)} />}
    </>
  );
}
