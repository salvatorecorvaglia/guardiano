import { Link } from "react-router-dom";
import type { Scan } from "../api/types";
import { fmtDateTime } from "../lib/format";
import GateBadge from "./GateBadge";
import { TypeBadge } from "./ui";

export default function ScanTable({ scans, showAsset }: { scans: Scan[]; showAsset?: boolean }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="border-y border-line bg-page/50">
          <tr>
            <th className="th">Date</th>
            {showAsset && <th className="th">Asset</th>}
            <th className="th">Tool</th>
            <th className="th">Branch / commit</th>
            <th className="th">Source</th>
            <th className="th">Gate</th>
            <th className="th text-right">Total</th>
            <th className="th text-right">New</th>
            <th className="th text-right">Reopened</th>
            <th className="th text-right">Auto-resolved</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {scans.map((s) => (
            <tr key={s.id}>
              <td className="td whitespace-nowrap text-xs">
                <Link className="text-ink2 hover:text-accent" to={`/scans/${s.id}`}>
                  {fmtDateTime(s.created_at)}
                </Link>
              </td>
              {showAsset && (
                <td className="td whitespace-nowrap">
                  <Link className="hover:text-accent" to={`/assets/${s.asset.id}`}>
                    {s.asset.name}
                  </Link>
                </td>
              )}
              <td className="td">
                <div className="flex items-center gap-2">
                  <TypeBadge type={s.scan_type} />
                  <span className="font-medium">{s.tool_name}</span>
                  {s.tool_version && <span className="text-xs text-muted">{s.tool_version}</span>}
                </div>
                <div className="text-xs text-muted">
                  {s.format}
                  {s.file_name && ` · ${s.file_name}`}
                </div>
              </td>
              <td className="td text-xs text-ink2">
                {s.branch ?? "–"}
                {s.commit_sha && <span className="ml-1 font-mono text-muted">{s.commit_sha.slice(0, 8)}</span>}
              </td>
              <td className="td text-xs text-ink2">
                {s.source === "preview" ? <span className="text-muted">Preview</span> : s.source === "api" ? "API" : "Upload"}
                {s.uploaded_by && <div className="text-muted">{s.uploaded_by.full_name || s.uploaded_by.email}</div>}
              </td>
              <td className="td">
                <GateBadge gate={s.gate} />
              </td>
              <td className="td tabular text-right">{s.total_count}</td>
              <td className="td tabular text-right font-medium" title={s.source === "preview" ? "Would be new; a preview changes nothing" : undefined}>
                {s.new_count}
                {s.source === "preview" && "*"}
              </td>
              <td className="td tabular text-right">{s.reopened_count}</td>
              <td className="td tabular text-right">{s.auto_resolved_count}</td>
            </tr>
          ))}
          {scans.length === 0 && (
            <tr>
              <td className="td py-8 text-center text-muted" colSpan={10}>
                No scans yet
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
