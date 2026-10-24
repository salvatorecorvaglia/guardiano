import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { request } from "../api/typed";
import type { GateConditions, GatePolicy } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useServerDraft } from "../lib/draft";
import { SEVERITY_LABEL, sevColor } from "../lib/format";
import { useToast } from "./Toaster";
import { ConfirmDialog, ErrorBox, Spinner } from "./ui";

const LIMIT_SEVERITIES = ["critical", "high", "medium", "low"] as const;
type Limits = Record<string, string>;

interface Draft {
  enabled: boolean;
  max_new: Limits;
  max_open: Limits;
  fail_on_overdue: boolean;
  fail_on_reopened: boolean;
  fail_on_kev: boolean;
  max_open_epss: string; // a percentage in the form, 0-1 in the API
  max_new_cvss: string;
  fail_on_new_secrets: boolean;
  fail_on_denied_license: boolean;
}

const EMPTY: Draft = {
  enabled: true,
  max_new: {},
  max_open: {},
  fail_on_overdue: false,
  fail_on_reopened: false,
  fail_on_kev: false,
  max_open_epss: "",
  max_new_cvss: "",
  fail_on_new_secrets: false,
  fail_on_denied_license: false,
};

function toDraft(policy: GatePolicy | undefined): Draft {
  if (!policy) return EMPTY;
  const limits = (v: GateConditions["max_new"] | undefined): Limits =>
    Object.fromEntries(Object.entries(v ?? {}).map(([k, n]) => [k, String(n)]));
  return {
    enabled: policy.enabled,
    max_new: limits(policy.conditions.max_new),
    max_open: limits(policy.conditions.max_open),
    fail_on_overdue: !!policy.conditions.fail_on_overdue,
    fail_on_reopened: !!policy.conditions.fail_on_reopened,
    fail_on_kev: !!policy.conditions.fail_on_kev,
    max_open_epss: policy.conditions.max_open_epss == null ? "" : String(Math.round(policy.conditions.max_open_epss * 1000) / 10),
    max_new_cvss: policy.conditions.max_new_cvss == null ? "" : String(policy.conditions.max_new_cvss),
    fail_on_new_secrets: !!policy.conditions.fail_on_new_secrets,
    fail_on_denied_license: !!policy.conditions.fail_on_denied_license,
  };
}

function toScore(v: string, scale = 1): number | null {
  return v.trim() === "" ? null : Number(v) / scale;
}

function ScoreInput({
  label, hint, value, onChange, editable, max, step, suffix,
}: {
  label: string;
  hint: string;
  value: string;
  onChange: (v: string) => void;
  editable: boolean;
  max: number;
  step: number;
  suffix?: string;
}) {
  return (
    <label className="flex items-center gap-2 text-sm" title={hint}>
      {label}
      <input
        className="input w-20 px-2 py-1 text-center tabular"
        type="number"
        min={0}
        max={max}
        step={step}
        placeholder="–"
        aria-label={label}
        disabled={!editable}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      {suffix && <span className="text-xs text-muted">{suffix}</span>}
    </label>
  );
}

function toLimits(v: Limits): Record<string, number> {
  return Object.fromEntries(
    Object.entries(v)
      .filter(([, n]) => n !== "")
      .map(([k, n]) => [k, Number(n)]),
  );
}

function LimitRow({
  label, hint, value, onChange, editable,
}: {
  label: string;
  hint: string;
  value: Limits;
  onChange: (v: Limits) => void;
  editable: boolean;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <div className="w-44">
        <div className="text-sm font-medium">{label}</div>
        <div className="text-xs text-muted">{hint}</div>
      </div>
      {LIMIT_SEVERITIES.map((s) => (
        <label key={s} className="flex items-center gap-1.5 text-xs text-ink2">
          <span className="inline-block h-2 w-2 rounded-full" style={{ background: sevColor(s) }} />
          {SEVERITY_LABEL[s]}
          <input
            className="input w-16 px-2 py-1 text-center tabular"
            type="number"
            min={0}
            placeholder="–"
            aria-label={`${label}: ${SEVERITY_LABEL[s]}`}
            disabled={!editable}
            value={value[s] ?? ""}
            onChange={(e) => onChange({ ...value, [s]: e.target.value })}
          />
        </label>
      ))}
    </div>
  );
}

/** Quality gate for one asset, or the global default (`assetId: null`). */
export default function GatePolicyCard({ assetId }: { assetId: number | null }) {
  return <GatePolicyForm key={assetId ?? "global"} assetId={assetId} />;
}

function GatePolicyForm({ assetId }: { assetId: number | null }) {
  const { can } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const canEdit = assetId === null ? can("admin") : can("manager");
  const policies = useQuery({ queryKey: ["gate-policies"], queryFn: ({ signal }) => request("get", "/api/v1/gate-policies", { signal }) });
  const policy = policies.data?.find((p) => (p.asset?.id ?? null) === assetId);
  const globalPolicy = policies.data?.find((p) => !p.asset);
  const form = useServerDraft<Draft>(policies.data ? toDraft(policy) : undefined);
  const draft = form.value ?? EMPTY;
  const setDraft = form.set;

  const save = useMutation({
    mutationFn: () =>
      request("put", "/api/v1/gate-policies", {
        body: {
          asset_id: assetId,
          enabled: draft.enabled,
          conditions: {
            max_new: toLimits(draft.max_new),
            max_open: toLimits(draft.max_open),
            fail_on_overdue: draft.fail_on_overdue,
            fail_on_reopened: draft.fail_on_reopened,
            fail_on_kev: draft.fail_on_kev,
            max_open_epss: toScore(draft.max_open_epss, 100),
            max_new_cvss: toScore(draft.max_new_cvss),
            fail_on_new_secrets: draft.fail_on_new_secrets,
            fail_on_denied_license: draft.fail_on_denied_license,
          },
        },
      }),
    onSuccess: async () => {
      // Hand the form back only once the saved policy is loaded, so it never flashes the old one.
      await qc.invalidateQueries({ queryKey: ["gate-policies"] });
      form.discard();
      toast("Quality gate saved");
    },
  });
  const [confirmRemove, setConfirmRemove] = useState(false);
  const remove = useMutation({
    mutationFn: () => request("delete", "/api/v1/gate-policies/{policy_id}", { params: { policy_id: Number(policy!.id) } }),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["gate-policies"] });
      form.discard();
      setConfirmRemove(false);
      toast("Quality gate removed");
    },
  });

  const dirty = form.dirty;
  const editable = canEdit && !save.isPending && !remove.isPending;

  return (
    <section className="card p-4">
      <h2 className="text-sm font-semibold">Quality gate{assetId === null ? " (global default)" : ""}</h2>
      <p className="mb-3 text-xs text-muted">
        Checked on every scan, including previews of other branches. The upload response carries the outcome, so a
        pipeline can fail the build. Empty means no limit.
        {assetId !== null &&
          (policy
            ? " This asset uses its own gate instead of the global one."
            : globalPolicy
              ? " This asset currently uses the global gate."
              : " No global gate is configured.")}
      </p>
      <ErrorBox error={policies.error} />
      {policies.isLoading ? (
        <Spinner />
      ) : (
        <div className="space-y-3">
          <LimitRow
            label="New findings"
            hint="Most this scan may introduce"
            value={draft.max_new}
            editable={editable}
            onChange={(v) => setDraft({ ...draft, max_new: v })}
          />
          <LimitRow
            label="Open findings"
            hint="Most the asset may carry"
            value={draft.max_open}
            editable={editable}
            onChange={(v) => setDraft({ ...draft, max_open: v })}
          />
          <div className="flex flex-wrap gap-4">
            <ScoreInput
              label="New finding with CVSS above"
              hint="Fail when this scan introduces a finding scored higher (0-10)"
              value={draft.max_new_cvss}
              max={10}
              step={0.1}
              editable={editable}
              onChange={(v) => setDraft({ ...draft, max_new_cvss: v })}
            />
            <ScoreInput
              label="Open finding with EPSS above"
              hint="Fail when the asset carries a vulnerability this likely to be exploited in the next 30 days"
              value={draft.max_open_epss}
              max={100}
              step={1}
              suffix="%"
              editable={editable}
              onChange={(v) => setDraft({ ...draft, max_open_epss: v })}
            />
          </div>
          <div className="flex flex-wrap gap-4 text-sm">
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                disabled={!editable}
                checked={draft.fail_on_overdue}
                onChange={(e) => setDraft({ ...draft, fail_on_overdue: e.target.checked })}
              />
              Fail when the asset has findings past their SLA
            </label>
            <label className="flex items-center gap-2">
              <input
                type="checkbox"
                disabled={!editable}
                checked={draft.fail_on_reopened}
                onChange={(e) => setDraft({ ...draft, fail_on_reopened: e.target.checked })}
              />
              Fail when a resolved finding comes back
            </label>
            <label className="flex items-center gap-2" title="CISA's Known Exploited Vulnerabilities catalogue">
              <input
                type="checkbox"
                disabled={!editable}
                checked={draft.fail_on_kev}
                onChange={(e) => setDraft({ ...draft, fail_on_kev: e.target.checked })}
              />
              Fail when the asset carries a known-exploited vulnerability
            </label>
            <label className="flex items-center gap-2" title="Hard-coded credentials, as Gitleaks and other secret scanners report them">
              <input
                type="checkbox"
                disabled={!editable}
                checked={draft.fail_on_new_secrets}
                onChange={(e) => setDraft({ ...draft, fail_on_new_secrets: e.target.checked })}
              />
              Fail when a new secret is committed
            </label>
            <label className="flex items-center gap-2" title="Checked against the licence policy, for the components this report lists">
              <input
                type="checkbox"
                disabled={!editable}
                checked={draft.fail_on_denied_license}
                onChange={(e) => setDraft({ ...draft, fail_on_denied_license: e.target.checked })}
              />
              Fail when a component has a denied licence
            </label>
            {policy && (
              <label className="flex items-center gap-2">
                <input
                  type="checkbox"
                  disabled={!editable}
                  checked={draft.enabled}
                  onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
                />
                Gate enabled
              </label>
            )}
          </div>
        </div>
      )}
      {canEdit && (
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <button className="btn-secondary" disabled={!dirty || save.isPending} onClick={() => save.mutate()}>
            {policy ? "Save gate" : "Create gate"}
          </button>
          {dirty && (
            <button className="text-xs text-ink2 hover:underline" onClick={form.discard}>
              Discard changes
            </button>
          )}
          {policy && (
            <button className="ml-auto text-xs text-danger hover:underline" onClick={() => setConfirmRemove(true)}>
              Remove this gate
            </button>
          )}
        </div>
      )}
      <ErrorBox error={save.error} />
      <ConfirmDialog
        open={confirmRemove}
        title="Remove quality gate"
        confirmLabel="Remove gate"
        pending={remove.isPending}
        error={remove.error}
        onConfirm={() => remove.mutate()}
        onClose={() => setConfirmRemove(false)}
      >
        {assetId === null
          ? "Scans of assets without a gate of their own will no longer be checked, and pipelines that rely on the gate will stop failing."
          : "This asset will fall back to the global gate, if there is one. Pipelines that rely on this gate's rules will stop failing on them."}
      </ConfirmDialog>
    </section>
  );
}
