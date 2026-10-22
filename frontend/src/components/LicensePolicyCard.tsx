import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import { request } from "../api/typed";
import type { LicenceRule } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useServerDraft } from "../lib/draft";
import { useToast } from "./Toaster";
import { ErrorBox, Spinner } from "./ui";

const RULES = [
  { value: "allowed", label: "Allowed" },
  { value: "review", label: "Needs review" },
  { value: "denied", label: "Denied" },
] as const;

/** Which licences are acceptable in the component inventory. Admins edit; everyone can read. */
export default function LicensePolicyCard() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const editable = can("admin");
  const policy = useQuery({ queryKey: ["license-policy"], queryFn: ({ signal }) => request("get", "/api/v1/components/license-policy", { signal }) });
  const inUse = useQuery({ queryKey: ["components", "licenses"], queryFn: ({ signal }) => request("get", "/api/v1/components/licenses", { signal }) });
  const form = useServerDraft<LicenceRule[]>(policy.data?.rules);
  const rules = form.value ?? [];
  const setRules = form.set;

  const save = useMutation({
    mutationFn: () => request("put", "/api/v1/components/license-policy", { body: { rules } }),
    onSuccess: (saved) => {
      qc.setQueryData(["license-policy"], saved);
      form.discard();
      qc.invalidateQueries({ queryKey: ["components"] });
      toast("Licence policy saved");
    },
  });

  const listed = new Set(rules.map((r) => r.licence.toLowerCase()));
  const unlisted = (inUse.data ?? []).filter((l) => !listed.has(l.licence.toLowerCase()));
  const dirty = form.dirty;

  function set(index: number, patch: Partial<LicenceRule>) {
    setRules(rules.map((r, i) => (i === index ? { ...r, ...patch } : r)));
  }

  return (
    <section className="card p-4">
      <h2 className="text-sm font-semibold">Licence policy</h2>
      <p className="mb-3 text-xs text-muted">
        Applies to the component inventory. Anything not listed counts as <strong>{policy.data?.default ?? "allowed"}</strong>;
        a component with no licence recorded shows as unknown. Matching is exact and case-insensitive, so list
        dual licences (“MIT OR Apache-2.0”) as they appear.
      </p>
      <ErrorBox error={policy.error ?? save.error} />
      {policy.isLoading ? (
        <Spinner />
      ) : (
        <>
          {rules.length === 0 && <p className="text-sm text-muted">No licence is restricted.</p>}
          <div className="space-y-2">
            {rules.map((rule, i) => (
              <div key={i} className="flex flex-wrap items-center gap-2">
                <input
                  className="input w-56"
                  aria-label="Licence"
                  value={rule.licence}
                  disabled={!editable}
                  onChange={(e) => set(i, { licence: e.target.value })}
                  list="licences-in-use"
                />
                <select
                  className="input w-40"
                  aria-label={`Rule for ${rule.licence}`}
                  value={rule.rule}
                  disabled={!editable}
                  onChange={(e) => set(i, { rule: e.target.value as LicenceRule["rule"] })}
                >
                  {RULES.map((r) => (
                    <option key={r.value} value={r.value}>
                      {r.label}
                    </option>
                  ))}
                </select>
                <input
                  className="input min-w-[160px] flex-1"
                  aria-label={`Note for ${rule.licence}`}
                  placeholder="Note (optional)"
                  value={rule.note ?? ""}
                  disabled={!editable}
                  onChange={(e) => set(i, { note: e.target.value || null })}
                />
                {editable && (
                  <button className="btn-ghost p-1.5 hover:text-danger" aria-label={`Remove ${rule.licence}`} onClick={() => setRules(rules.filter((_, x) => x !== i))}>
                    <Trash2 className="h-4 w-4" />
                  </button>
                )}
              </div>
            ))}
          </div>
          <datalist id="licences-in-use">
            {unlisted.map((l) => (
              <option key={l.licence} value={l.licence}>
                {l.components} component{l.components === 1 ? "" : "s"}
              </option>
            ))}
          </datalist>
          {editable && (
            <div className="mt-3 flex flex-wrap items-center gap-3">
              <button className="btn-secondary" onClick={() => setRules([...rules, { licence: "", rule: "denied", note: null }])}>
                <Plus className="h-4 w-4" /> Add licence
              </button>
              <button
                className="btn-secondary"
                disabled={!dirty || save.isPending || rules.some((r) => !r.licence.trim())}
                onClick={() => save.mutate()}
              >
                Save policy
              </button>
              {dirty && (
                <button className="text-xs text-ink2 hover:underline" onClick={form.discard}>
                  Discard changes
                </button>
              )}
            </div>
          )}
        </>
      )}
    </section>
  );
}
