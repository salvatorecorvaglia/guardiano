import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { request } from "../api/typed";
import type { SlaMatrix } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useServerDraft } from "../lib/draft";
import { SEVERITY_LABEL, sevColor } from "../lib/format";
import { useToast } from "./Toaster";
import { ErrorBox, Spinner } from "./ui";

type Draft = Record<string, Record<string, string>>;

const COLUMN_LABEL: Record<string, string> = { any: "Default", low: "Low", medium: "Medium", high: "High", critical: "Critical" };

function toDraft(m: SlaMatrix): Draft {
  return Object.fromEntries(
    m.severities.map((s) => [s, Object.fromEntries(m.criticalities.map((c) => [c, m.days[s]?.[c] != null ? String(m.days[s][c]) : ""]))]),
  );
}

/** Remediation SLA (days) by severity and asset criticality. Admins edit it; everyone can read it. */
export default function SlaCard() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const toast = useToast();
  const editable = can("admin");
  const matrix = useQuery({ queryKey: ["sla"], queryFn: ({ signal }) => request("get", "/api/v1/sla", { signal }) });
  const form = useServerDraft<Draft>(matrix.data ? toDraft(matrix.data) : undefined);
  const draft = form.value ?? null;
  const setDraft = form.set;

  const save = useMutation({
    mutationFn: (d: Draft) =>
      request("put", "/api/v1/sla", {
        body: {
          days: Object.fromEntries(
            Object.entries(d).map(([s, cols]) => [s, Object.fromEntries(Object.entries(cols).map(([c, v]) => [c, v ? Number(v) : null]))]),
          ),
        },
      }),
    onSuccess: (m) => {
      qc.setQueryData(["sla"], m);
      form.discard();
      // Due dates and "past SLA" counts everywhere depend on the policy.
      for (const key of ["findings", "finding", "analytics", "assets", "asset", "meta"]) qc.invalidateQueries({ queryKey: [key] });
      toast("Remediation SLAs saved");
    },
  });

  const m = matrix.data;
  const invalid = !!draft && Object.values(draft).some((cols) => Object.values(cols).some((v) => v !== "" && !(Number(v) >= 1 && Number(v) <= 3650 && Number.isInteger(Number(v)))));
  const dirty = form.dirty;

  return (
    <section className="card p-4">
      <h2 className="text-sm font-semibold">Remediation SLAs</h2>
      <p className="mb-3 text-xs text-muted">
        Days to fix a finding, from when it is first seen. Columns override the default for assets of that business criticality; leave a
        cell empty to use the default. Changes apply to every open finding right away.
      </p>
      <ErrorBox error={matrix.error} />
      {!m || !draft ? (
        <Spinner />
      ) : (
        <div className="overflow-x-auto">
          <table className="text-sm">
            <thead>
              <tr>
                <th className="th">Severity</th>
                {m.criticalities.map((c) => (
                  <th key={c} className="th text-center">
                    {c === "any" ? COLUMN_LABEL[c] : `${COLUMN_LABEL[c]} asset`}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {m.severities.map((s) => (
                <tr key={s}>
                  <td className="td whitespace-nowrap font-medium">
                    <span className="mr-2 inline-block h-2 w-2 rounded-full" style={{ background: sevColor(s as keyof typeof SEVERITY_LABEL) }} />
                    {SEVERITY_LABEL[s as keyof typeof SEVERITY_LABEL]}
                  </td>
                  {m.criticalities.map((c) => {
                    const fallback = c === "any" ? String(m.env_defaults[s]) : draft[s].any || String(m.env_defaults[s]);
                    return (
                      <td key={c} className="td py-1.5 text-center">
                        {editable ? (
                          <input
                            className="input w-20 text-center tabular"
                            type="number"
                            min={1}
                            max={3650}
                            inputMode="numeric"
                            aria-label={`${SEVERITY_LABEL[s as keyof typeof SEVERITY_LABEL]} SLA for ${COLUMN_LABEL[c].toLowerCase()} assets`}
                            placeholder={fallback}
                            value={draft[s][c]}
                            onChange={(e) => setDraft({ ...draft, [s]: { ...draft[s], [c]: e.target.value } })}
                          />
                        ) : (
                          <span className={m.days[s][c] == null ? "text-muted" : undefined}>{m.days[s][c] ?? fallback}</span>
                        )}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {editable && m && draft && (
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <button className="btn-secondary" disabled={!dirty || invalid || save.isPending} onClick={() => save.mutate(draft)}>
            Save SLAs
          </button>
          {dirty && (
            <button className="text-xs text-ink2 hover:underline" onClick={form.discard}>
              Discard changes
            </button>
          )}
          {invalid && <span className="text-xs text-danger">Use whole days between 1 and 3650.</span>}
          <span className="text-xs text-muted">
            Environment defaults: {m.severities.map((s) => `${s} ${m.env_defaults[s]}`).join(", ")} days.
          </span>
        </div>
      )}
      <ErrorBox error={save.error} />
    </section>
  );
}
