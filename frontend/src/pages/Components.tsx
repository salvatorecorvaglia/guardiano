import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Boxes, Search, X } from "lucide-react";
import { Link } from "react-router-dom";
import { request } from "../api/typed";

import { EmptyState, ErrorBox, PageHeader, Pagination, Spinner } from "../components/ui";
import { fmtNum, relTime } from "../lib/format";
import { useClampPage, useDebouncedParam, useUrlParams } from "../lib/urlState";

const PAGE_SIZE = 50;


export default function Components() {
  const { params, update, page } = useUrlParams();
  const [q, setQ] = useDebouncedParam("q", params, update);
  const ecosystem = params.get("ecosystem") ?? "";
  const license = params.get("license") ?? "";
  const unlicensed = params.get("unlicensed") === "true";
  const licenceRule = params.get("licence_rule") ?? "";

  const query = {
    q: params.get("q") ?? "",
    ecosystem,
    license,
    unlicensed: unlicensed || undefined,
    licence_rule: licenceRule,
    page,
    page_size: PAGE_SIZE,
  };
  const list = useQuery({
    queryKey: ["components", query],
    queryFn: ({ signal }) => request("get", "/api/v1/components", { signal, query }),
    placeholderData: keepPreviousData,
  });
  const licences = useQuery({ queryKey: ["components", "licenses"], queryFn: ({ signal }) => request("get", "/api/v1/components/licenses", { signal }) });
  const stats = useQuery({ queryKey: ["components", "stats"], queryFn: ({ signal }) => request("get", "/api/v1/components/stats", { signal }) });
  useClampPage(page, PAGE_SIZE, list.data?.total, update, list.isPlaceholderData);

  const ecosystems = [...new Set((list.data?.items ?? []).map((c) => c.ecosystem).filter(Boolean))] as string[];
  const empty = stats.data?.components === 0;

  return (
    <>
      <PageHeader
        title="Components"
        subtitle={
          stats.data && !empty
            ? `${fmtNum(stats.data.distinct)} package versions across ${fmtNum(stats.data.assets)} asset${stats.data.assets === 1 ? "" : "s"} · last SBOM ${relTime(stats.data.last_seen_at)}`
            : "What your assets ship, from the SBOMs you upload"
        }
      />
      <ErrorBox error={list.error} />

      {empty ? (
        <div className="card">
          <EmptyState icon={<Boxes className="h-8 w-8" />} title="No components yet">
            Upload a CycloneDX SBOM (Syft, cdxgen, Trivy <code className="font-mono">--format cyclonedx</code>) or a
            Trivy JSON report produced with <code className="font-mono">--list-all-pkgs</code>, and everything your
            assets ship shows up here — vulnerable or not.
          </EmptyState>
        </div>
      ) : (
        <>
          <div className="card mb-4 flex flex-wrap items-center gap-2 p-3">
            <div className="relative min-w-[240px] flex-1">
              <Search className="pointer-events-none absolute left-2.5 top-2 h-4 w-4 text-muted" />
              <input
                className="input pl-8"
                placeholder="Package name or purl, e.g. log4j-core"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                aria-label="Search components"
              />
            </div>
            <select className="input w-auto" value={ecosystem} onChange={(e) => update({ ecosystem: e.target.value || null })} aria-label="Ecosystem">
              <option value="">All ecosystems</option>
              {ecosystems.map((e) => (
                <option key={e} value={e}>
                  {e}
                </option>
              ))}
            </select>
            <select className="input w-auto" value={license} onChange={(e) => update({ license: e.target.value || null })} aria-label="Licence">
              <option value="">Any licence</option>
              {licences.data?.map((l) => (
                <option key={l.licence} value={l.licence}>
                  {l.licence} ({l.components})
                </option>
              ))}
            </select>
            <select className="input w-auto" value={licenceRule} onChange={(e) => update({ licence_rule: e.target.value || null })} aria-label="Licence policy">
              <option value="">Any licence policy</option>
              <option value="denied">Denied licence</option>
              <option value="review">Needs review</option>
              <option value="unknown">No licence recorded</option>
            </select>
            <button
              className={unlicensed ? "btn-secondary border-accent" : "btn-secondary"}
              aria-pressed={unlicensed}
              onClick={() => update({ unlicensed: unlicensed ? null : "true" })}
            >
              No licence recorded
            </button>
            {(params.get("q") || ecosystem || license || unlicensed || licenceRule) && (
              <button
                className="text-xs text-accent hover:underline"
                onClick={() => {
                  setQ("");
                  update({ q: null, ecosystem: null, license: null, unlicensed: null, licence_rule: null });
                }}
              >
                Clear <X className="inline h-3 w-3" />
              </button>
            )}
          </div>

          <div className="card overflow-hidden">
            {list.isLoading ? (
              <div className="flex justify-center py-12">
                <Spinner />
              </div>
            ) : !list.data?.items.length ? (
              <EmptyState icon={<Boxes className="h-6 w-6" />} title="Nothing matches these filters" />
            ) : (
              <>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead className="border-b border-line bg-page/50">
                      <tr>
                        <th className="th">Package</th>
                        <th className="th">Version</th>
                        <th className="th">Licence</th>
                        <th className="th">Used by</th>
                        <th className="th">Last seen</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line">
                      {list.data.items.map((c) => (
                        <tr key={`${c.ecosystem}:${c.name}@${c.version}`}>
                          <td className="td">
                            <div className="font-medium">{c.name}</div>
                            <div className="truncate font-mono text-xs text-muted" title={c.purl ?? undefined}>
                              {c.purl ?? c.ecosystem ?? ""}
                            </div>
                          </td>
                          <td className="td whitespace-nowrap font-mono text-xs">{c.version ?? "–"}</td>
                          <td className="td text-xs">
                            {c.licenses.length ? c.licenses.join(", ") : <span className="text-muted">not recorded</span>}
                            {c.licence_rule === "denied" && (
                              <span className="ml-1 rounded-full border border-danger/40 bg-danger/10 px-1.5 py-px text-[11px] font-medium text-danger">
                                denied
                              </span>
                            )}
                            {c.licence_rule === "review" && (
                              <span className="ml-1 rounded-full border border-line bg-ink/5 px-1.5 py-px text-[11px] text-ink2">
                                review
                              </span>
                            )}
                          </td>
                          <td className="td">
                            <div className="flex flex-wrap gap-1.5">
                              {c.assets.map((a) => (
                                <Link key={a.id} to={`/assets/${a.id}`} className="rounded bg-ink/5 px-1.5 py-0.5 text-xs hover:text-accent">
                                  {a.name}
                                </Link>
                              ))}
                            </div>
                          </td>
                          <td className="td whitespace-nowrap text-xs text-ink2">{relTime(c.last_seen_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <Pagination page={page} pageSize={PAGE_SIZE} total={list.data.total} onPage={(p) => update({ page: String(p) }, true)} />
              </>
            )}
          </div>
        </>
      )}
    </>
  );
}
