import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, Lock, Pencil, Trash2, Upload } from "lucide-react";
import { useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { analyticsKeys, invalidateInventory, useDirectory } from "../api/queries";

import { download, request } from "../api/typed";
import { useAuth } from "../auth/AuthContext";
import AssetForm from "../components/AssetForm";
import AsyncState from "../components/AsyncState";
import OpenTrendChart from "../components/charts/OpenTrendChart";
import SeverityBreakdown from "../components/charts/SeverityBreakdown";
import GatePolicyCard from "../components/GatePolicyCard";
import ScanTable from "../components/ScanTable";
import { useToast } from "../components/Toaster";
import UploadDialog from "../components/UploadDialog";
import { BackLink, ConfirmDialog, CriticalityTag, ErrorBox, StatTile } from "../components/ui";
import { fmtNum } from "../lib/format";

export default function AssetDetail() {
  const { id } = useParams();
  return <AssetDetailPage key={id} />;
}

function AssetDetailPage() {
  const { id } = useParams();
  const directory = useDirectory();
  const teams = useQuery({ queryKey: ["teams"], queryFn: ({ signal }) => request("get", "/api/v1/teams", { signal }), staleTime: 5 * 60_000 });
  const { can } = useAuth();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const toast = useToast();
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [uploading, setUploading] = useState(false);

  const asset = useQuery({ queryKey: ["asset", id], queryFn: ({ signal }) => request("get", "/api/v1/assets/{asset_id}", { params: { asset_id: Number(id) }, signal }) });
  const summary = useQuery({
    queryKey: analyticsKeys.summary(id),
    queryFn: ({ signal }) => request("get", "/api/v1/analytics/summary", { signal, query: { asset_id: Number(id) } }),
  });
  const trends = useQuery({
    queryKey: analyticsKeys.trends(90, id),
    queryFn: ({ signal }) => request("get", "/api/v1/analytics/trends", { signal, query: { days: 90, asset_id: Number(id) } }),
  });
  const scans = useQuery({
    queryKey: ["scans", "asset", id],
    queryFn: ({ signal }) => request("get", "/api/v1/scans", { signal, query: { asset_id: Number(id), page_size: 10 } }),
  });
  // "sbom:cyclonedx", "sbom:spdx", "vex:openvex" or "vex:cyclonedx"
  const exporter = useMutation({
    mutationFn: (choice: string) => {
      const [kind, format] = choice.split(":");
      const ext = { "sbom:cyclonedx": "cdx.json", "sbom:spdx": "spdx.json", "vex:openvex": "openvex.json", "vex:cyclonedx": "vex.cdx.json" }[choice];
      const params = { asset_id: Number(id) };
      const filename = `${asset.data?.name ?? "asset"}.${ext}`;
      return kind === "sbom"
        ? download("/api/v1/assets/{asset_id}/sbom", { params, query: { format: format as "cyclonedx" | "spdx" } }, filename)
        : download("/api/v1/assets/{asset_id}/vex", { params, query: { format: format as "cyclonedx" | "openvex" } }, filename);
    },
  });
  const vexInput = useRef<HTMLInputElement>(null);
  const importVex = useMutation({
    mutationFn: (file: File) => {
      return request("post", "/api/v1/assets/{asset_id}/vex", { params: { asset_id: Number(id) }, form: { file } });
    },
    onSuccess: (r) => {
      invalidateInventory(qc);
      toast(
        `VEX applied: ${r.changed} finding${r.changed === 1 ? "" : "s"} closed` +
          (r.unmatched.length ? `, ${r.unmatched.length} statement${r.unmatched.length === 1 ? "" : "s"} matched nothing` : ""),
      );
    },
  });
  const del = useMutation({
    mutationFn: () => request("delete", "/api/v1/assets/{asset_id}", { params: { asset_id: Number(id) } }),
    onSuccess: () => {
      invalidateInventory(qc);
      toast(`Deleted ${asset.data?.name}`);
      navigate("/assets");
    },
  });

  if (!asset.data) return <AsyncState queries={[asset]} label="Asset"><ErrorBox error="Asset not found" /></AsyncState>;
  const a = asset.data;
  const s = summary.data;
  const assignee = directory.data?.find((u) => u.id === a.default_assignee_id);
  // Teams you are not in are not listed to you, so a restricted asset you can see may show no name.
  const team = teams.data?.find((t) => t.id === a.team_id);

  return (
    <>
      <BackLink to="/assets">Assets</BackLink>
      <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">{a.name}</h1>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-ink2">
            <span className="capitalize">{a.type}</span>
            <CriticalityTag value={a.criticality} />
            {a.owner && <span>{a.owner}</span>}
            {assignee && <span>New findings → {assignee.full_name || assignee.email}</span>}
            {a.default_branch && (
              <span title="Scans of other branches are ingested as previews">default branch {a.default_branch}</span>
            )}
            {team && (
              <span className="inline-flex items-center gap-1" title="Only this team's members and administrators can see this asset">
                <Lock className="h-3 w-3" /> {team.name}
              </span>
            )}
            {a.repo_url && /^https?:\/\//.test(a.repo_url) && (
              <a href={a.repo_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-accent hover:underline">
                Repository <ExternalLink className="h-3 w-3" />
              </a>
            )}
            {a.tags.map((t) => (
              <span key={t} className="rounded bg-ink/5 px-1.5 py-0.5 text-xs">
                {t}
              </span>
            ))}
          </div>
          {a.description && <p className="mt-2 max-w-2xl text-sm text-ink2">{a.description}</p>}
        </div>
        <div className="flex flex-wrap gap-2">
          <select
            className="input w-auto"
            aria-label="Export"
            value=""
            disabled={exporter.isPending}
            onChange={(e) => e.target.value && exporter.mutate(e.target.value)}
          >
            <option value="">{exporter.isPending ? "Exporting…" : "Export…"}</option>
            <optgroup label="SBOM (components)">
              <option value="sbom:cyclonedx">CycloneDX 1.5</option>
              <option value="sbom:spdx">SPDX 2.3</option>
            </optgroup>
            <optgroup label="VEX (triage decisions)">
              <option value="vex:openvex">OpenVEX</option>
              <option value="vex:cyclonedx">CycloneDX VEX</option>
            </optgroup>
          </select>
          {can("manager") && (
            <>
              <input
                ref={vexInput}
                type="file"
                accept="application/json,.json"
                className="hidden"
                aria-label="VEX document"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) importVex.mutate(file);
                  e.target.value = "";
                }}
              />
              <button className="btn-secondary" disabled={importVex.isPending} onClick={() => vexInput.current?.click()}>
                {importVex.isPending ? "Importing…" : "Import VEX…"}
              </button>
            </>
          )}
          {can("analyst") && (
            <button className="btn-primary" onClick={() => setUploading(true)}>
              <Upload className="h-4 w-4" /> Upload scan
            </button>
          )}
          {can("manager") && (
            <>
              <button className="btn-secondary" onClick={() => setEditing(true)}>
                <Pencil className="h-4 w-4" /> Edit
              </button>
              <button className="btn-danger" onClick={() => setDeleting(true)} aria-label="Delete asset">
                <Trash2 className="h-4 w-4" />
              </button>
            </>
          )}
        </div>
      </div>

      <ErrorBox error={exporter.error || importVex.error || summary.error} />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile label="Risk score" value={a.risk_score} hint="Weighted severity × criticality" />
        <Link to={`/findings?asset_id=${a.id}&status=open&status=in_progress`}>
          <StatTile label="Open findings" value={fmtNum(a.open_total)} hint={s ? `${s.open_by_type.sast} SAST · ${s.open_by_type.sca} SCA · ${s.open_by_type.iac} IaC · ${s.open_by_type.dast} DAST` : undefined} />
        </Link>
        <Link to={`/findings?asset_id=${a.id}&overdue=true`}>
          <StatTile label="Past SLA" tone="danger" value={s ? fmtNum(s.overdue) : "–"} />
        </Link>
        <StatTile label="Mean time to remediate" value={s?.mttr_days_overall != null ? `${s.mttr_days_overall} d` : "–"} />
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <section className="card p-4 xl:col-span-2">
          <h2 className="text-sm font-semibold">Open findings by severity</h2>
          <p className="mb-3 text-xs text-muted">Daily snapshot · last 90 days</p>
          <AsyncState queries={[trends]} label="Trend">{trends.data && <OpenTrendChart data={trends.data.open_by_severity} />}</AsyncState>
        </section>
        <section className="card p-4">
          <h2 className="mb-3 text-sm font-semibold">Current open exposure</h2>
          <SeverityBreakdown counts={a.open_counts} assetId={a.id} />
        </section>
      </div>

      <div className="mt-4">
        <GatePolicyCard assetId={a.id} />
      </div>

      <section className="card mt-4 overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3">
          <h2 className="text-sm font-semibold">Scan history</h2>
          <Link to={`/scans?asset_id=${a.id}`} className="text-xs text-accent hover:underline">
            All scans
          </Link>
        </div>
        <AsyncState queries={[scans]} label="Scan history"><ScanTable scans={scans.data?.items ?? []} /></AsyncState>
      </section>

      {editing && <AssetForm asset={a} onClose={() => setEditing(false)} />}
      {/* keyed by asset so the default target never points at a previously viewed asset */}
      <UploadDialog key={a.id} open={uploading} onClose={() => setUploading(false)} defaultAssetId={a.id} />
      <ConfirmDialog
        open={deleting}
        title="Delete asset"
        confirmLabel="Delete permanently"
        pending={del.isPending}
        error={del.error}
        onConfirm={() => del.mutate()}
        onClose={() => setDeleting(false)}
      >
        This permanently deletes <span className="font-medium">{a.name}</span> with all its scans, findings and history.
      </ConfirmDialog>
    </>
  );
}
