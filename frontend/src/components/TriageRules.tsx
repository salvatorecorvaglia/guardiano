import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ListChecks, Pencil, Plus, Sparkles, Trash2 } from "lucide-react";
import { useState } from "react";
import { useAssetOptions, useDirectory } from "../api/queries";
import { request } from "../api/typed";
import type { Criticality, RuleAction, RuleMatch, Severity, TriagePreview, TriageRule } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { fmtNum, SEVERITIES, SEVERITY_LABEL } from "../lib/format";
import { describeAction, describeMatch } from "../lib/triage";
import { useToast } from "./Toaster";
import { ConfirmDialog, EmptyState, ErrorBox, Field, Modal, Spinner } from "./ui";

type Draft = {
  name: string;
  asset_id: string;
  priority: string;
  match: RuleMatch;
  action: RuleAction;
};

const EMPTY_MATCH: RuleMatch = {
  type: null,
  severity: [],
  tool: null,
  rule_id: null,
  cwe: null,
  package: null,
  path_glob: null,
  title_contains: null,
  cve: null,
  ecosystem: null,
  kev: null,
  epss_min: null,
  asset_tags: [],
  asset_criticality: [],
};
const CRITICALITY_LEVELS: Criticality[] = ["low", "medium", "high", "critical"];
const EMPTY_ACTION: RuleAction = { status: null, justification: null, severity: null, assignee_id: null, tags: [] };
const EMPTY: Draft = { name: "", asset_id: "", priority: "100", match: EMPTY_MATCH, action: EMPTY_ACTION };

function toDraft(rule: TriageRule): Draft {
  return {
    name: rule.name,
    asset_id: rule.asset ? String(rule.asset.id) : "",
    priority: String(rule.priority),
    match: { ...EMPTY_MATCH, ...rule.match },
    action: { ...EMPTY_ACTION, ...rule.action },
  };
}

function RuleForm({ rule, onClose }: { rule?: TriageRule; onClose: () => void }) {
  const { can } = useAuth();
  // Mirrors api/v1/triage.py: a rule for every asset reaches every team, so only admins set one.
  const canGlobal = can("admin");
  const qc = useQueryClient();
  const toast = useToast();
  const assets = useAssetOptions();
  const directory = useDirectory();
  const [draft, setDraft] = useState<Draft>(rule ? toDraft(rule) : EMPTY);
  const [preview, setPreview] = useState<TriagePreview | null>(null);
  const setMatch = (patch: Partial<RuleMatch>) => setDraft({ ...draft, match: { ...draft.match, ...patch } });
  const setAction = (patch: Partial<RuleAction>) => setDraft({ ...draft, action: { ...draft.action, ...patch } });

  const body = () => ({
    name: draft.name.trim(),
    priority: Number(draft.priority) || 100,
    asset_id: draft.asset_id ? Number(draft.asset_id) : null,
    match: draft.match,
    action: draft.action,
  });

  const save = useMutation({
    mutationFn: () =>
      rule ? request("patch", "/api/v1/triage-rules/{rule_id}", { params: { rule_id: Number(rule.id) }, body: body() }) : request("post", "/api/v1/triage-rules", { body: body() }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["triage-rules"] });
      toast(rule ? "Rule saved" : "Rule created");
      onClose();
    },
  });
  const dryRun = useMutation({
    mutationFn: () =>
      request("post", "/api/v1/triage-rules/preview", {
        body: { match: draft.match, asset_id: draft.asset_id ? Number(draft.asset_id) : null },
      }),
    onSuccess: setPreview,
  });

  // Null-based, not truthiness: "not in KEV" is kev === false, and still a condition.
  const hasMatch = Object.entries(draft.match).some(([, v]) => (Array.isArray(v) ? v.length > 0 : v != null && v !== ""));
  const hasAction = !!(draft.action.status || draft.action.severity || draft.action.tags?.length || draft.action.assignee_id);
  const needsJustification = draft.action.status === "false_positive" && !draft.action.justification?.trim();
  const valid = draft.name.trim() && hasMatch && hasAction && !needsJustification && (canGlobal || draft.asset_id);

  return (
    <Modal
      open
      onClose={onClose}
      wide
      title={rule ? `Edit "${rule.name}"` : "New auto-triage rule"}
      footer={
        <>
          <button className="btn-ghost mr-auto" disabled={!hasMatch || dryRun.isPending} onClick={() => dryRun.mutate()}>
            {dryRun.isPending ? "Checking…" : "Preview matches"}
          </button>
          <button className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="btn-primary" disabled={!valid || save.isPending} onClick={() => save.mutate()}>
            Save rule
          </button>
        </>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name">
          <input className="input" value={draft.name} maxLength={200} onChange={(e) => setDraft({ ...draft, name: e.target.value })} placeholder="Ignore test fixtures" />
        </Field>
        <Field label="Applies to">
          <select className="input" value={draft.asset_id} onChange={(e) => setDraft({ ...draft, asset_id: e.target.value })}>
            <option value="" disabled={!canGlobal}>
              {canGlobal ? "Every asset" : "Every asset (administrators only)"}
            </option>
            {assets.data?.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
        </Field>
      </div>

      <fieldset className="rounded-lg border border-line p-3">
        <legend className="px-1 text-xs font-medium text-ink2">When a new finding matches all of</legend>
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="File path" hint="Glob, e.g. tests/* or */vendor/*">
            <input className="input" value={draft.match.path_glob ?? ""} onChange={(e) => setMatch({ path_glob: e.target.value || null })} />
          </Field>
          <Field label="CWE">
            <input className="input" value={draft.match.cwe ?? ""} onChange={(e) => setMatch({ cwe: e.target.value || null })} placeholder="89 or CWE-89" />
          </Field>
          <Field label="Tool">
            <input className="input" value={draft.match.tool ?? ""} onChange={(e) => setMatch({ tool: e.target.value || null })} placeholder="Semgrep" />
          </Field>
          <Field label="Rule id">
            <input className="input" value={draft.match.rule_id ?? ""} onChange={(e) => setMatch({ rule_id: e.target.value || null })} />
          </Field>
          <Field label="Package">
            <input className="input" value={draft.match.package ?? ""} onChange={(e) => setMatch({ package: e.target.value || null })} placeholder="lodash" />
          </Field>
          <Field label="Title contains">
            <input className="input" value={draft.match.title_contains ?? ""} onChange={(e) => setMatch({ title_contains: e.target.value || null })} />
          </Field>
          <Field label="CVE">
            <input className="input" value={draft.match.cve ?? ""} onChange={(e) => setMatch({ cve: e.target.value.trim() || null })} placeholder="CVE-2021-44228" />
          </Field>
          <Field label="Ecosystem">
            <input className="input" value={draft.match.ecosystem ?? ""} onChange={(e) => setMatch({ ecosystem: e.target.value.trim() || null })} placeholder="npm, pypi, maven" />
          </Field>
          <Field label="Known exploited" hint="CISA's Known Exploited Vulnerabilities catalogue">
            <select
              className="input"
              value={draft.match.kev == null ? "" : String(draft.match.kev)}
              onChange={(e) => setMatch({ kev: e.target.value === "" ? null : e.target.value === "true" })}
            >
              <option value="">Either</option>
              <option value="true">In KEV</option>
              <option value="false">Not in KEV</option>
            </select>
          </Field>
          <Field label="EPSS at least" hint="Probability of exploitation in the next 30 days, in %">
            <input
              className="input"
              type="number"
              min={0}
              max={100}
              value={draft.match.epss_min == null ? "" : Math.round(draft.match.epss_min * 100)}
              onChange={(e) => setMatch({ epss_min: e.target.value === "" ? null : Number(e.target.value) / 100 })}
            />
          </Field>
          <Field label="Asset tags" hint="Comma separated; the asset must carry all of them">
            <input
              className="input"
              value={draft.match.asset_tags?.join(", ") ?? ""}
              onChange={(e) => setMatch({ asset_tags: e.target.value.split(",").map((t) => t.trim()).filter(Boolean) })}
            />
          </Field>
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <span className="text-xs text-ink2">Asset criticality</span>
          {CRITICALITY_LEVELS.map((c) => (
            <label key={c} className="flex items-center gap-1 text-xs capitalize">
              <input
                type="checkbox"
                checked={draft.match.asset_criticality?.includes(c) ?? false}
                onChange={(e) =>
                  setMatch({
                    asset_criticality: e.target.checked
                      ? [...(draft.match.asset_criticality ?? []), c]
                      : (draft.match.asset_criticality ?? []).filter((x) => x !== c),
                  })
                }
              />
              {c}
            </label>
          ))}
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <span className="text-xs text-ink2">Severity</span>
          {SEVERITIES.map((s) => (
            <label key={s} className="flex items-center gap-1 text-xs">
              <input
                type="checkbox"
                checked={draft.match.severity?.includes(s) ?? false}
                onChange={(e) =>
                  setMatch({
                    severity: e.target.checked
                      ? [...(draft.match.severity ?? []), s]
                      : (draft.match.severity ?? []).filter((x) => x !== s),
                  })
                }
              />
              {SEVERITY_LABEL[s]}
            </label>
          ))}
          <label className="ml-2 flex items-center gap-1 text-xs">
            Type
            <select className="input w-auto px-2 py-0.5" value={draft.match.type ?? ""} onChange={(e) => setMatch({ type: (e.target.value || null) as RuleMatch["type"] })}>
              <option value="">any</option>
              <option value="sast">SAST</option>
              <option value="sca">SCA</option>
              <option value="iac">IaC</option>
              <option value="dast">DAST</option>
            </select>
          </label>
        </div>
      </fieldset>

      <fieldset className="rounded-lg border border-line p-3">
        <legend className="px-1 text-xs font-medium text-ink2">Then</legend>
        <label className="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            checked={draft.action.status === "false_positive"}
            onChange={(e) => setAction({ status: e.target.checked ? "false_positive" : null })}
          />
          Mark as false positive
        </label>
        {draft.action.status === "false_positive" && (
          <Field label="Justification" hint="Required, and recorded on every finding the rule suppresses">
            <textarea className="input min-h-[56px]" maxLength={2000} value={draft.action.justification ?? ""} onChange={(e) => setAction({ justification: e.target.value || null })} />
          </Field>
        )}
        <div className="mt-2 grid gap-3 sm:grid-cols-3">
          <Field label="Set severity">
            <select className="input" value={draft.action.severity ?? ""} onChange={(e) => setAction({ severity: (e.target.value || null) as Severity | null })}>
              <option value="">Leave as reported</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {SEVERITY_LABEL[s]}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Assign to">
            <select className="input" value={draft.action.assignee_id ?? ""} onChange={(e) => setAction({ assignee_id: e.target.value ? Number(e.target.value) : null })}>
              <option value="">Nobody</option>
              {directory.data?.map((u) => (
                <option key={u.id} value={u.id}>
                  {u.full_name || u.email}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Tags" hint="Comma separated">
            <input
              className="input"
              value={draft.action.tags?.join(", ") ?? ""}
              onChange={(e) => setAction({ tags: e.target.value.split(",").map((t) => t.trim().toLowerCase()).filter(Boolean) })}
            />
          </Field>
        </div>
      </fieldset>

      <p className="text-xs text-muted">
        Rules run in priority order (lowest first) on findings a scan creates. To apply a saved rule to the open
        findings that already match it, use <span className="font-medium">Apply to existing</span> in the rule list.
      </p>
      <Field label="Priority">
        <input className="input w-24" type="number" min={1} max={1000} value={draft.priority} onChange={(e) => setDraft({ ...draft, priority: e.target.value })} />
      </Field>

      {preview && (
        <div className="rounded-lg border border-line bg-page p-3 text-sm">
          <p className="font-medium">
            {fmtNum(preview.matched)} of the {fmtNum(preview.scanned)} findings checked match these conditions
            {preview.truncated && " (only the most recent were checked)"}.
          </p>
          <p className="text-xs text-muted">A dry run: nothing has been changed.</p>
          <ul className="mt-2 space-y-1 text-xs text-ink2">
            {preview.sample.map((f) => (
              <li key={f.id} className="truncate">
                <span className="font-medium">{f.severity}</span> · {f.title}
                <span className="ml-1 font-mono text-muted">{f.file_path ?? f.package_name}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      <ErrorBox error={save.error ?? dryRun.error} />
    </Modal>
  );
}

/** Auto-triage rules: suppress, retag or reassign findings as scans create them. */
export default function TriageRules() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const editable = can("manager");
  const [editing, setEditing] = useState<TriageRule | "new" | null>(null);
  const [deleting, setDeleting] = useState<TriageRule | null>(null);
  const [applying, setApplying] = useState<TriageRule | null>(null);
  const rules = useQuery({ queryKey: ["triage-rules"], queryFn: ({ signal }) => request("get", "/api/v1/triage-rules", { signal }) });

  const toggle = useMutation({
    mutationFn: (rule: TriageRule) => request("patch", "/api/v1/triage-rules/{rule_id}", { params: { rule_id: Number(rule.id) }, body: { enabled: !rule.enabled } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["triage-rules"] }),
  });
  const del = useMutation({
    mutationFn: (id: number) => request("delete", "/api/v1/triage-rules/{rule_id}", { params: { rule_id: Number(id) } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["triage-rules"] });
      toast(`Deleted "${deleting?.name}"`);
      setDeleting(null);
    },
  });

  const apply = useMutation({
    mutationFn: (id: number) => request("post", "/api/v1/triage-rules/{rule_id}/apply", { params: { rule_id: Number(id) } }),
    onSuccess: () => {
      toast(`Applying "${applying?.name}" to existing findings in the background`);
      setApplying(null);
    },
  });

  return (
    <section className="card overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold">Auto-triage rules</h2>
          <p className="text-xs text-muted">
            Applied to findings as a scan creates them, in priority order, and to existing findings when you ask.
          </p>
        </div>
        {editable && (
          <button className="btn-primary" onClick={() => setEditing("new")}>
            <Plus className="h-4 w-4" /> New rule
          </button>
        )}
      </div>
      <ErrorBox error={rules.error ?? toggle.error} />
      {rules.isLoading ? (
        <div className="flex justify-center py-10">
          <Spinner />
        </div>
      ) : !rules.data?.length ? (
        <EmptyState icon={<Sparkles className="h-6 w-6" />} title="No rules yet">
          A rule can suppress known-irrelevant findings (test fixtures, vendored code), raise the severity of
          findings that matter, or route them to a team.
        </EmptyState>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="border-y border-line bg-page/50">
              <tr>
                <th className="th">Rule</th>
                <th className="th">When</th>
                <th className="th">Then</th>
                <th className="th text-right">Applied</th>
                <th className="th" />
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {rules.data.map((r) => (
                <tr key={r.id} className={r.enabled ? undefined : "opacity-60"}>
                  <td className="td">
                    <div className="font-medium">{r.name}</div>
                    <div className="text-xs text-muted">
                      #{r.priority} · {r.asset ? r.asset.name : "every asset"}
                      {!r.enabled && " · disabled"}
                    </div>
                  </td>
                  <td className="td text-xs text-ink2">{describeMatch(r.match)}</td>
                  <td className="td text-xs text-ink2">{describeAction(r.action)}</td>
                  <td className="td tabular text-right">{fmtNum(r.applied_count)}</td>
                  <td className="td whitespace-nowrap text-right">
                    {editable && (
                      <>
                        {(r.asset || can("admin")) && (
                          <label className="mr-2 inline-flex items-center gap-1 text-xs text-ink2">
                            <input type="checkbox" checked={r.enabled} onChange={() => toggle.mutate(r)} aria-label={`Enable ${r.name}`} />
                            On
                          </label>
                        )}
                        <button className="btn-ghost p-1.5" aria-label={`Apply ${r.name} to existing findings`} title="Apply to existing" onClick={() => setApplying(r)}>
                          <ListChecks className="h-4 w-4" />
                        </button>
                        {(r.asset || can("admin")) && (
                          <>
                            <button className="btn-ghost p-1.5" aria-label={`Edit ${r.name}`} onClick={() => setEditing(r)}>
                              <Pencil className="h-4 w-4" />
                            </button>
                            <button className="btn-ghost p-1.5 hover:text-danger" aria-label={`Delete ${r.name}`} onClick={() => setDeleting(r)}>
                              <Trash2 className="h-4 w-4" />
                            </button>
                          </>
                        )}
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {editing && <RuleForm rule={editing === "new" ? undefined : editing} onClose={() => setEditing(null)} />}
      <ConfirmDialog
        open={!!deleting}
        title="Delete rule"
        confirmLabel="Delete rule"
        pending={del.isPending}
        error={del.error}
        onConfirm={() => deleting && del.mutate(deleting.id)}
        onClose={() => setDeleting(null)}
      >
        Delete <span className="font-medium">{deleting?.name}</span>? Findings it already triaged keep their status
        and tags.
      </ConfirmDialog>
      <ConfirmDialog
        open={!!applying}
        title="Apply to existing findings"
        confirmLabel="Apply rule"
        pending={apply.isPending}
        error={apply.error}
        onConfirm={() => applying && apply.mutate(applying.id)}
        onClose={() => setApplying(null)}
      >
        Apply <span className="font-medium">{applying?.name}</span> to the open and in-progress findings it matches
        now, on the assets you can see? Closed findings are left alone, and so is anyone already assigned. It runs
        in the background; use <span className="font-medium">Preview matches</span> in the rule first to see what it
        will touch.
      </ConfirmDialog>
    </section>
  );
}
