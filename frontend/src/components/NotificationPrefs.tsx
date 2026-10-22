import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMeta } from "../api/queries";
import { request } from "../api/typed";
import { useToast } from "./Toaster";
import { ErrorBox, Field, Spinner } from "./ui";

interface Prefs {
  digest_frequency: "off" | "daily" | "weekly";
  notify_on_assignment: boolean;
}

/** Per-user email preferences. Hidden unless the server can actually send email. */
export default function NotificationPrefs() {
  const qc = useQueryClient();
  const toast = useToast();
  const meta = useMeta();
  const prefs = useQuery({ queryKey: ["preferences"], queryFn: ({ signal }) => request("get", "/api/v1/auth/preferences", { signal }) });

  const save = useMutation({
    mutationFn: (patch: Partial<Prefs>) => request("patch", "/api/v1/auth/preferences", { body: patch }),
    onSuccess: (updated) => {
      qc.setQueryData(["preferences"], updated);
      toast("Notification preferences saved");
    },
  });

  if (!meta.data?.email_enabled) return null;

  return (
    <section className="card p-4">
      <h2 className="text-sm font-semibold">Email notifications</h2>
      <p className="mb-3 text-xs text-muted">Sent to your account address.</p>
      <ErrorBox error={prefs.error ?? save.error} />
      {!prefs.data ? (
        <Spinner />
      ) : (
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Summary email" hint="Your open findings, what is overdue and what is due within a week">
            <select
              className="input"
              value={prefs.data.digest_frequency}
              disabled={save.isPending}
              onChange={(e) => save.mutate({ digest_frequency: e.target.value as Prefs["digest_frequency"] })}
            >
              <option value="off">Never</option>
              <option value="daily">Every day</option>
              <option value="weekly">Every Monday</option>
            </select>
          </Field>
          <label className="flex items-start gap-2 self-end pb-2 text-sm">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={prefs.data.notify_on_assignment}
              disabled={save.isPending}
              onChange={(e) => save.mutate({ notify_on_assignment: e.target.checked })}
            />
            <span>
              When a finding is assigned to me
              <span className="block text-xs text-muted">Only when somebody else assigns it</span>
            </span>
          </label>
        </div>
      )}
    </section>
  );
}
