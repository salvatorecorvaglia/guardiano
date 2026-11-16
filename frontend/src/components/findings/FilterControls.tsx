import type { ReactNode } from "react";
import clsx from "clsx";
import { Search, Tag, X } from "lucide-react";
import { useProducts } from "../../api/queries";
import type { Severity, Status } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { SEVERITIES, SEVERITY_LABEL, STATUS_LABEL, STATUSES, sevColor } from "../../lib/format";
import type { useUrlParams } from "../../lib/urlState";
import AsyncPicker from "../AsyncPicker";

function Chip({ active, onClick, children }: { active: boolean; onClick: () => void; children: ReactNode }) {
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

export default function FilterControls({ params, update, q, setQ, toggleList, activeFilters, onClear }: {
  params: URLSearchParams; update: ReturnType<typeof useUrlParams>["update"];
  q: string; setQ: (value: string) => void; activeFilters: boolean; onClear: () => void;
  toggleList: (key: "severity" | "status" | "tag", value: string) => void;
}) {
  const products = useProducts();
  const { user } = useAuth();
  const sevSel = params.getAll("severity") as Severity[];
  const statusSel = params.getAll("status") as Status[];
  return (
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
          <AsyncPicker kind="assets" label="Asset" value={params.get("asset_id") ?? ""} emptyLabel="All assets"
            onChange={(value) => update({ asset_id: value || null })} />
          <select className="input w-auto" value={params.get("type") ?? ""} onChange={(e) => update({ type: e.target.value || null })} aria-label="Type">
            <option value="">All types</option>
            <option value="sast">SAST (code)</option>
            <option value="sca">SCA (dependencies)</option>
            <option value="iac">IaC (infrastructure)</option>
            <option value="dast">DAST (running apps)</option>
          </select>
          <AsyncPicker kind="users" label="Assignee" value={params.get("unassigned") ? "none" : params.get("assignee_id") ?? ""}
            emptyLabel="Any assignee" extraOptions={[{ value: String(user?.id), label: "Assigned to me" }, { value: "none", label: "Unassigned" }]}
            onChange={(value) => update({ unassigned: value === "none" ? "true" : null, assignee_id: value && value !== "none" ? value : null })} />
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
              onClick={onClear}
            >
              Clear all
            </button>
          )}
        </div>
      </div>
  );
}
