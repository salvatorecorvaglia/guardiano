import { Link } from "react-router-dom";
import type { Severity } from "../../api/types";
import { fmtNum, SEVERITIES, SEVERITY_LABEL, sevColor } from "../../lib/format";

/** Horizontal magnitude bars, one per severity; value at the tip; each row links to filtered findings. */
export default function SeverityBreakdown({ counts, assetId }: { counts: Record<Severity, number>; assetId?: number }) {
  const max = Math.max(1, ...SEVERITIES.map((s) => counts[s]));
  return (
    <ul className="space-y-2.5">
      {SEVERITIES.map((s) => (
        <li key={s}>
          <Link
            to={`/findings?severity=${s}&status=open&status=in_progress${assetId ? `&asset_id=${assetId}` : ""}`}
            className="group grid grid-cols-[72px_1fr] items-center gap-3 rounded-md focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
            title={`${counts[s]} open ${s} findings`}
          >
            <span className="text-xs text-ink2 group-hover:text-ink">{SEVERITY_LABEL[s]}</span>
            <span className="flex items-center gap-2">
              <span
                className="h-3 rounded-r-[4px] transition-opacity group-hover:opacity-80"
                style={{ width: `${(counts[s] / max) * 85}%`, minWidth: counts[s] ? 3 : 0, background: sevColor(s) }}
              />
              <span className="tabular text-xs font-medium">{fmtNum(counts[s])}</span>
            </span>
          </Link>
        </li>
      ))}
    </ul>
  );
}
