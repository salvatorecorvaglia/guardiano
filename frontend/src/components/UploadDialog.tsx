import { useMutation, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { CheckCircle2, FileJson, UploadCloud } from "lucide-react";
import { type DragEvent, useState } from "react";
import { Link } from "react-router-dom";
import { invalidateInventory, useAssetOptions, useMeta } from "../api/queries";
import { request } from "../api/typed";
import { fmtNum } from "../lib/format";
import { ASSET_NAME_RE } from "./AssetForm";
import GateBadge from "./GateBadge";
import { ErrorBox, Field, Modal } from "./ui";

const FORMAT_LABEL: Record<string, string> = {
  sarif: "SARIF 2.1.0",
  cyclonedx: "CycloneDX JSON",
  trivy: "Trivy JSON",
  semgrep: "Semgrep JSON",
  guardiano: "Guardiano JSON",
  grype: "Grype JSON",
  osv: "OSV-Scanner JSON",
  "dependency-check": "OWASP Dependency-Check JSON",
  "npm-audit": "npm audit JSON",
  gitleaks: "Gitleaks JSON",
  checkov: "Checkov JSON",
  kics: "KICS JSON",
  zap: "OWASP ZAP JSON",
  nuclei: "Nuclei JSON / JSON Lines",
};

export default function UploadDialog({
  open,
  onClose,
  defaultAssetId,
}: {
  open: boolean;
  onClose: () => void;
  defaultAssetId?: number;
}) {
  const qc = useQueryClient();
  const assets = useAssetOptions();
  const meta = useMeta();
  const [file, setFile] = useState<File | null>(null);
  const [assetMode, setAssetMode] = useState<"existing" | "new">("existing");
  const [assetId, setAssetId] = useState<string>(defaultAssetId ? String(defaultAssetId) : "");
  const [assetName, setAssetName] = useState("");
  const [format, setFormat] = useState("");
  const [branch, setBranch] = useState("");
  const [commit, setCommit] = useState("");
  const [closeMissing, setCloseMissing] = useState(false);
  const [preview, setPreview] = useState(false);
  const [dragging, setDragging] = useState(false);

  const upload = useMutation({
    mutationFn: () => {
      return request("post", "/api/v1/scans", { form: {
        file: file!,
        asset_id: assetMode === "existing" ? Number(assetId) : undefined,
        asset_name: assetMode === "new" ? assetName.trim() : undefined,
        format: format || undefined, branch: branch || undefined, commit_sha: commit || undefined,
        close_missing: closeMissing, preview,
      } });
    },
    onSuccess: () => {
      invalidateInventory(qc);
    },
  });

  function reset() {
    setFile(null);
    setAssetName("");
    setFormat("");
    setBranch("");
    setCommit("");
    setCloseMissing(false);
    setPreview(false);
    setDragging(false);
    upload.reset();
  }

  function close() {
    if (upload.isPending) return;
    reset();
    onClose();
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setDragging(false);
    const f = e.dataTransfer.files?.[0];
    if (f) setFile(f);
  }

  const maxBytes = (meta.data?.max_upload_mb ?? 50) * 1024 * 1024;
  const tooBig = !!file && file.size > maxBytes;
  const nameInvalid = assetMode === "new" && assetName.trim().length > 0 && !ASSET_NAME_RE.test(assetName.trim());
  const assetOk = assetMode === "existing" ? !!assetId : assetName.trim().length > 0 && !nameInvalid;
  const result = upload.data;

  if (result) {
    return (
      <Modal
        open={open}
        onClose={close}
        title={result.source === "preview" ? "Scan previewed" : "Scan imported"}
        footer={
          <>
            <button className="btn-secondary" onClick={reset}>
              Upload another
            </button>
            <Link
              className="btn-primary"
              to={result.source === "preview" ? `/scans/${result.id}` : `/findings?asset_id=${result.asset.id}`}
              onClick={close}
            >
              {result.source === "preview" ? "View preview" : "View findings"}
            </Link>
          </>
        }
      >
        <div className="flex items-start gap-3">
          <CheckCircle2 className="mt-0.5 h-5 w-5 text-good" />
          <div className="text-sm">
            <p>
              <span className="font-medium">{result.tool_name}</span> ({result.format}, {result.scan_type.toUpperCase()})
              report {result.source === "preview" ? "previewed against" : "imported into"}{" "}
              <span className="font-medium">{result.asset.name}</span>.
            </p>
            {result.source === "preview" && (
              <p className="mt-1 text-xs text-muted">
                This scan was evaluated as a preview. Nothing was added to the inventory.
              </p>
            )}
            <div className="mt-2">
              <GateBadge gate={result.gate} />
            </div>
            {result.gate && !result.gate.passed && (
              <ul className="mt-1 list-inside list-disc text-xs text-danger">
                {result.gate.violations.map((v) => (
                  <li key={v.rule + (v.severity ?? "")}>{v.message}</li>
                ))}
              </ul>
            )}
          </div>
        </div>
        <dl className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          {(
            [
              [result.source === "preview" ? "Would be new" : "New", result.new_count],
              ["Already known", result.duplicate_count],
              ["Reopened", result.reopened_count],
              ["Auto-resolved", result.auto_resolved_count],
            ] as const
          ).map(([k, v]) => (
            <div key={k} className="rounded-lg border border-line p-3">
              <dt className="text-xs text-ink2">{k}</dt>
              <dd className="tabular mt-0.5 text-lg font-semibold">{fmtNum(v)}</dd>
            </div>
          ))}
        </dl>
      </Modal>
    );
  }

  return (
    <Modal
      open={open}
      onClose={close}
      title="Upload scan results"
      wide
      footer={
        <>
          <button className="btn-secondary" onClick={close}>
            Cancel
          </button>
          <button className="btn-primary" disabled={!file || tooBig || !assetOk || upload.isPending} onClick={() => upload.mutate()}>
            {upload.isPending ? "Importing…" : "Import"}
          </button>
        </>
      }
    >
      <label
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        className={clsx(
          "flex cursor-pointer flex-col items-center justify-center rounded-xl border-2 border-dashed px-4 py-8 text-center transition-colors",
          dragging ? "border-accent bg-accent/5" : "border-line hover:border-accent/60",
        )}
      >
        <input
          type="file"
          className="sr-only"
          accept=".json,.jsonl,.sarif,.cdx,application/json"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
        />
        {file ? (
          <>
            <FileJson className="h-8 w-8 text-accent" />
            <p className="mt-2 font-medium">{file.name}</p>
            <p className={tooBig ? "text-xs font-medium text-danger" : "text-xs text-muted"}>
              {file.size >= 1024 * 1024 ? `${(file.size / 1024 / 1024).toFixed(1)} MB` : `${(file.size / 1024).toFixed(1)} KB`}
              {tooBig ? ` · exceeds the ${meta.data?.max_upload_mb ?? 50} MB limit` : " · click to change"}
            </p>
          </>
        ) : (
          <>
            <UploadCloud className="h-8 w-8 text-muted" />
            <p className="mt-2 font-medium">Drop a report here or click to browse</p>
            <p className="mt-0.5 text-xs text-muted">
              Scanner JSON, JSON Lines, SARIF or CycloneDX · up to {meta.data?.max_upload_mb ?? 50} MB
            </p>
          </>
        )}
      </label>

      <div>
        <div className="mb-2 flex gap-4 text-sm">
          <label className="flex items-center gap-1.5">
            <input type="radio" checked={assetMode === "existing"} onChange={() => setAssetMode("existing")} />
            Existing asset
          </label>
          <label className="flex items-center gap-1.5">
            <input type="radio" checked={assetMode === "new"} onChange={() => setAssetMode("new")} />
            New asset
          </label>
        </div>
        {assetMode === "existing" ? (
          <select className="input" value={assetId} onChange={(e) => setAssetId(e.target.value)} aria-label="Asset">
            <option value="">Select an asset…</option>
            {assets.data?.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
        ) : (
          <input
            className="input"
            placeholder="e.g. payments-api"
            value={assetName}
            onChange={(e) => setAssetName(e.target.value)}
            aria-label="New asset name"
            aria-invalid={nameInvalid}
          />
        )}
        {nameInvalid && (
          <p className="mt-1 text-xs text-danger">Use letters, digits and . _ - / @ : or spaces.</p>
        )}
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <Field label="Format">
          <select className="input" value={format} onChange={(e) => setFormat(e.target.value)}>
            <option value="">Auto-detect</option>
            {(meta.data?.formats ?? Object.keys(FORMAT_LABEL)).map((f) => (
              <option key={f} value={f}>
                {FORMAT_LABEL[f] ?? f}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Branch">
          <input className="input" placeholder="main" value={branch} onChange={(e) => setBranch(e.target.value)} />
        </Field>
        <Field label="Commit">
          <input className="input font-mono" placeholder="sha" value={commit} onChange={(e) => setCommit(e.target.value)} />
        </Field>
      </div>

      <label className="flex items-start gap-2 text-sm">
        <input type="checkbox" className="mt-0.5" checked={preview} onChange={(e) => setPreview(e.target.checked)} />
        <span>
          Preview only
          <span className="block text-xs text-muted">
            Report what this scan would add and run its quality gate, without changing the inventory. Scans of a branch
            other than the asset's default branch are previews anyway.
          </span>
        </span>
      </label>
      <label className="flex items-start gap-2 text-sm">
        <input
          type="checkbox"
          className="mt-0.5"
          disabled={preview}
          checked={closeMissing && !preview}
          onChange={(e) => setCloseMissing(e.target.checked)}
        />
        <span>
          Resolve findings no longer reported
          <span className="block text-xs text-muted">
            Open findings from this tool on this asset that are missing from the report are marked Resolved. Use for full
            scans only.
          </span>
        </span>
      </label>
      <ErrorBox error={upload.error} />
    </Modal>
  );
}
