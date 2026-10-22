import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Copy, KeyRound, Plus, X } from "lucide-react";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { setAccessToken } from "../api/client";
import { useMeta } from "../api/queries";
import { request } from "../api/typed";
import type { ApiToken } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import GatePolicyCard from "../components/GatePolicyCard";
import Integrations from "../components/Integrations";
import LicensePolicyCard from "../components/LicensePolicyCard";
import MfaCard from "../components/MfaCard";
import NotificationPrefs from "../components/NotificationPrefs";
import Products from "../components/Products";
import ReportSchedules from "../components/ReportSchedules";
import SlaCard from "../components/SlaCard";
import Teams from "../components/Teams";
import { useToast } from "../components/Toaster";
import TriageRules from "../components/TriageRules";
import { ConfirmDialog, EmptyState, ErrorBox, Field, Modal, PageHeader, Tabs, tabPanel } from "../components/ui";
import Webhooks from "../components/Webhooks";
import { fmtDate, relTime } from "../lib/format";

/** navigator.clipboard only exists in a secure context, and this app is also served over plain HTTP
 * behind a proxy. Fall back to the older selection-based copy there, and say so if both fail. */
async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* permission denied: try the fallback */
  }
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  try {
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    area.remove();
  }
}

function CopyButton({ text }: { text: string }) {
  const [state, setState] = useState<"idle" | "done" | "failed">("idle");
  useEffect(() => {
    if (state === "idle") return;
    const timer = setTimeout(() => setState("idle"), state === "done" ? 1500 : 4000);
    return () => clearTimeout(timer);
  }, [state]);
  return (
    <button
      className="btn-ghost p-1.5"
      onClick={() => copyText(text).then((ok) => setState(ok ? "done" : "failed"))}
      aria-label={state === "failed" ? "Could not copy; select the text and copy it by hand" : "Copy"}
      title={state === "failed" ? "Could not copy; select the text and copy it by hand" : undefined}
    >
      {state === "done" ? (
        <Check className="h-4 w-4 text-good" />
      ) : state === "failed" ? (
        <X className="h-4 w-4 text-danger" />
      ) : (
        <Copy className="h-4 w-4" />
      )}
    </button>
  );
}

function Snippet({ code }: { code: string }) {
  return (
    <div className="relative">
      <pre className="overflow-x-auto rounded-lg border border-line bg-page p-3 pr-10 font-mono text-xs leading-relaxed">{code}</pre>
      <div className="absolute right-1 top-1">
        <CopyButton text={code} />
      </div>
    </div>
  );
}

function PasswordCard() {
  const { logout } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const change = useMutation({
    mutationFn: () => request("post", "/api/v1/auth/change-password", { body: { current_password: current, new_password: next } }),
    onSuccess: (r) => {
      // The server re-issues this session (other sessions are signed out).
      setAccessToken(r.access_token);
      setCurrent("");
      setNext("");
    },
  });
  const signOutAll = useMutation({
    mutationFn: () => request("post", "/api/v1/auth/logout-all", { }),
    onSettled: () => logout(),
  });
  return (
    <section className="card p-4">
      <h2 className="mb-3 text-sm font-semibold">Change password</h2>
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Current password">
          <input className="input" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
        </Field>
        <Field label="New password" hint="At least 12 characters. Other sessions are signed out.">
          <input className="input" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
        </Field>
      </div>
      <div className="mt-3 flex items-center gap-3">
        <button className="btn-secondary" disabled={!current || next.length < 12 || change.isPending} onClick={() => change.mutate()}>
          Update password
        </button>
        {change.isSuccess && <span className="text-sm text-good">Password updated</span>}
      </div>
      <div className="mt-3">
        <ErrorBox error={change.error} />
      </div>
      <div className="mt-4 flex flex-wrap items-center justify-between gap-2 border-t border-line pt-3">
        <p className="text-xs text-muted">Lost a device? Revoke every session of your account, including this one.</p>
        <button className="btn-secondary" disabled={signOutAll.isPending} onClick={() => signOutAll.mutate()}>
          Sign out everywhere
        </button>
      </div>
    </section>
  );
}

export default function Settings() {
  const [params, setParams] = useSearchParams();
  const sections = [{ key: "account", label: "Account & API tokens" }, { key: "policies", label: "Policies" }, { key: "catalog", label: "Products & teams" }, { key: "integrations", label: "Integrations & schedules" }];
  const section = sections.some((item) => item.key === params.get("section")) ? params.get("section")! : "account";
  const meta = useMeta();
  const { user, can } = useAuth();
  const qc = useQueryClient();
  const [showAll, setShowAll] = useState(false);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<ApiToken["scopes"]>(["ingest"]);
  const [expires, setExpires] = useState("90");
  const [created, setCreated] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<ApiToken | null>(null);
  const toast = useToast();

  const tokens = useQuery({
    queryKey: ["tokens", showAll],
    enabled: section === "account",
    queryFn: ({ signal }) => request("get", "/api/v1/tokens", { signal, query: { all: showAll || undefined } }),
  });
  const create = useMutation({
    mutationFn: () =>
      request("post", "/api/v1/tokens", {
        body: { name, scopes, expires_in_days: expires ? Number(expires) : null },
      }),
    onSuccess: (t) => {
      setCreated(t.token);
      setName("");
      qc.invalidateQueries({ queryKey: ["tokens"] });
    },
  });
  const revoke = useMutation({
    mutationFn: (id: number) => request("delete", "/api/v1/tokens/{token_id}", { params: { token_id: Number(id) } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["tokens"] });
      toast(`Revoked token “${revoking?.name}”`);
      setRevoking(null);
    },
  });

  const origin = window.location.origin;
  const curl = `curl -fsS -X POST ${origin}/api/v1/scans \\
  -H "Authorization: Bearer $GUARDIANO_TOKEN" \\
  -F "file=@results.sarif" \\
  -F "asset_name=my-service" \\
  -F "branch=$CI_COMMIT_REF_NAME" \\
  -F "commit_sha=$CI_COMMIT_SHA" \\
  -F "close_missing=true"`;
  const gha = `- name: Upload SAST results to Guardiano
  if: always()
  run: |
    curl -fsS -X POST "\${{ vars.GUARDIANO_URL }}/api/v1/scans" \\
      -H "Authorization: Bearer \${{ secrets.GUARDIANO_TOKEN }}" \\
      -F "file=@semgrep.sarif" \\
      -F "asset_name=\${{ github.event.repository.name }}" \\
      -F "branch=\${{ github.ref_name }}" -F "commit_sha=\${{ github.sha }}"`;

  function toggleScope(s: ApiToken["scopes"][number]) {
    setScopes(scopes.includes(s) ? scopes.filter((x) => x !== s) : [...scopes, s]);
  }

  return (
    <>
      <PageHeader title="Settings" subtitle={`Signed in as ${user?.email}`} />
      <Tabs id="settings" label="Settings sections" tabs={sections} active={section} onChange={(next) => setParams({ section: next })} className="mb-4 flex-wrap" />
      <div {...tabPanel("settings", section)} className="space-y-4">
        {section === "policies" && <><SlaCard /><GatePolicyCard assetId={null} /><LicensePolicyCard /><TriageRules /></>}
        {section === "catalog" && <><Products />{can("admin") && <Teams />}</>}
        {section === "integrations" && <>{can("manager") && <ReportSchedules />}{can("admin") && <><Webhooks /><Integrations /></>}</>}
        {section === "account" && <>
        <PasswordCard />
        <MfaCard />
        <NotificationPrefs />
        <section className="card overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3">
            <div>
              <h2 className="text-sm font-semibold">API tokens</h2>
              <p className="text-xs text-muted">For CI/CD pipelines and integrations. Tokens act with your role, limited to their scopes.</p>
            </div>
            <div className="flex items-center gap-3">
              {can("admin") && (
                <label className="flex items-center gap-1.5 text-xs text-ink2">
                  <input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} /> All users
                </label>
              )}
              <button
                className="btn-primary"
                onClick={() => {
                  setCreated(null);
                  setScopes(can("analyst") ? ["ingest"] : ["read"]);
                  setCreating(true);
                }}
              >
                <Plus className="h-4 w-4" /> New token
              </button>
            </div>
          </div>
          <ErrorBox error={tokens.error} />
          {tokens.data?.length === 0 ? (
            <EmptyState icon={<KeyRound className="h-8 w-8" />} title="No API tokens yet" />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="border-y border-line bg-page/50">
                  <tr>
                    <th className="th">Name</th>
                    {showAll && <th className="th">Owner</th>}
                    <th className="th">Token</th>
                    <th className="th">Scopes</th>
                    <th className="th">Last used</th>
                    <th className="th">Expires</th>
                    <th className="th" />
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {tokens.data?.map((t) => {
                    const expired = t.expires_at && new Date(t.expires_at) < new Date();
                    return (
                      <tr key={t.id} className={t.revoked_at || expired ? "text-muted" : ""}>
                        <td className="td font-medium">{t.name}</td>
                        {showAll && <td className="td text-xs">{t.user.email}</td>}
                        <td className="td font-mono text-xs">{t.prefix}…</td>
                        <td className="td text-xs">{t.scopes.join(", ")}</td>
                        <td className="td text-xs">{relTime(t.last_used_at)}</td>
                        <td className="td text-xs">{t.expires_at ? fmtDate(t.expires_at) : "Never"}</td>
                        <td className="td text-right">
                          {t.revoked_at ? (
                            <span className="text-xs">Revoked</span>
                          ) : expired ? (
                            <span className="text-xs">Expired</span>
                          ) : (
                            <button
                              className="btn-danger py-1 text-xs"
                              onClick={() => {
                                revoke.reset();
                                setRevoking(t);
                              }}
                            >
                              Revoke
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="card space-y-3 p-4">
          <h2 className="text-sm font-semibold">Push results from CI</h2>
          <p className="text-sm text-ink2">
            Create a token with the <span className="font-mono">ingest</span> scope, store it as a CI secret and POST reports after each
            scan. Findings are deduplicated automatically; <span className="font-mono">close_missing=true</span> resolves issues that
            disappeared from full scans.
          </p>
          <Snippet code={curl} />
          <p className="text-xs text-muted">GitHub Actions step:</p>
          <Snippet code={gha} />
          {meta.data?.docs_enabled && <p className="text-xs text-muted">
            Full API reference:{" "}
            <a className="text-accent hover:underline" href="/api/docs" target="_blank" rel="noreferrer">
              /api/docs
            </a>
          </p>}
        </section>
        </>}
      </div>

      <ConfirmDialog
        open={!!revoking}
        title="Revoke API token"
        confirmLabel="Revoke token"
        pending={revoke.isPending}
        error={revoke.error}
        onConfirm={() => revoking && revoke.mutate(revoking.id)}
        onClose={() => setRevoking(null)}
      >
        Revoke <span className="font-medium">{revoking?.name}</span> ({revoking?.prefix}…)? Pipelines using it will get
        401 errors immediately.
      </ConfirmDialog>
      <Modal
        open={creating}
        onClose={() => setCreating(false)}
        title={created ? "Token created" : "New API token"}
        footer={
          created ? (
            <button className="btn-primary" onClick={() => setCreating(false)}>
              Done
            </button>
          ) : (
            <>
              <button className="btn-secondary" onClick={() => setCreating(false)}>
                Cancel
              </button>
              <button className="btn-primary" disabled={!name.trim() || !scopes.length || create.isPending} onClick={() => create.mutate()}>
                Create
              </button>
            </>
          )
        }
      >
        {created ? (
          <>
            <p className="text-sm">Copy this token now. It will not be shown again.</p>
            <Snippet code={created} />
          </>
        ) : (
          <>
            <Field label="Name">
              <input className="input" placeholder="e.g. github-actions-payments" value={name} onChange={(e) => setName(e.target.value)} />
            </Field>
            <fieldset>
              <legend className="label">Scopes</legend>
              <label className="flex items-start gap-2 text-sm">
                <input type="checkbox" className="mt-0.5" disabled={!can("analyst")} checked={scopes.includes("ingest")} onChange={() => toggleScope("ingest")} />
                <span>
                  ingest <span className="block text-xs text-muted">Upload scan results (requires Analyst role)</span>
                </span>
              </label>
              <label className="mt-2 flex items-start gap-2 text-sm">
                <input type="checkbox" className="mt-0.5" checked={scopes.includes("read")} onChange={() => toggleScope("read")} />
                <span>
                  read <span className="block text-xs text-muted">Read findings, assets, scans and analytics</span>
                </span>
              </label>
              <label className="mt-2 flex items-start gap-2 text-sm">
                <input type="checkbox" className="mt-0.5" disabled={!can("analyst")} checked={scopes.includes("triage")} onChange={() => toggleScope("triage")} />
                <span>
                  triage{" "}
                  <span className="block text-xs text-muted">
                    Change status, assignee, tags and comments, as you could (requires Analyst role)
                  </span>
                </span>
              </label>
            </fieldset>
            <Field label="Expires">
              <select className="input" value={expires} onChange={(e) => setExpires(e.target.value)}>
                <option value="30">30 days</option>
                <option value="90">90 days</option>
                <option value="365">1 year</option>
                <option value="">Never</option>
              </select>
            </Field>
            <ErrorBox error={create.error} />
          </>
        )}
      </Modal>
    </>
  );
}
