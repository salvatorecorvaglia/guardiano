import { memo } from "react";
import clsx from "clsx";
import { Link } from "react-router-dom";
import type { Finding } from "../../api/types";
import ExploitBadge from "../ExploitBadge";
import { SeverityBadge, StatusBadge, TypeBadge } from "../ui";
import { findingLocation, fmtDate, relTime } from "../../lib/format";
import type { OptionalColumn } from "./columns";

/**
 * One row, memoised. Typing in the search box re-renders the page and ticking a checkbox changes the
 * selection; before this, both re-rendered all fifty rows and every badge and formatter in them. The
 * callbacks it receives never change identity, and react-query keeps unchanged findings the same
 * objects between fetches, so a row renders again only when its own finding or checkbox changes.
 */
export default memo(function FindingRow({
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
