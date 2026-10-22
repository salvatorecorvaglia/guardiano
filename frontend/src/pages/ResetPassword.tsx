import { useMutation } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import { type FormEvent, useState } from "react";
import { request } from "../api/typed";
import { ErrorBox, Field } from "../components/ui";

/** Lands here from the reset link in the email; the token comes from the query string. */
export default function ResetPassword() {
  const token = new URLSearchParams(window.location.search).get("token") ?? "";
  const [password, setPassword] = useState("");
  const [done, setDone] = useState(false);

  const reset = useMutation({
    mutationFn: () => request("post", "/api/v1/auth/reset-password", { body: { token, new_password: password } }),
    onSuccess: () => {
      setDone(true);
      window.history.replaceState({}, "", "/reset-password");
    },
  });

  function submit(e: FormEvent) {
    e.preventDefault();
    if (token && password.length >= 12) reset.mutate();
  }

  return (
    <div className="flex min-h-full items-center justify-center p-6">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center justify-center gap-2">
          <ShieldCheck className="h-7 w-7 text-accent" />
          <span className="text-lg font-semibold tracking-tight">Guardiano</span>
        </div>
        <form onSubmit={submit} className="card space-y-4 p-6">
          <h1 className="text-base font-semibold">Choose a new password</h1>
          {done ? (<p className="text-sm">Password updated. Sign in with your new password and authenticator.</p>) : !token ? (
            <p className="text-sm text-danger">
              This link is missing its token. Request a new reset email from the sign-in page.
            </p>
          ) : (
            <>
              <Field label="New password" hint="At least 12 characters">
                <input
                  className="input"
                  type="password"
                  autoComplete="new-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </Field>
              <button className="btn-primary w-full" disabled={password.length < 12 || reset.isPending || done}>
                {reset.isPending ? "Saving…" : "Set password"}
              </button>
              <ErrorBox error={reset.error} />
            </>
          )}
          <a className="block text-center text-xs text-accent hover:underline" href="/">
            Back to sign in
          </a>
        </form>
      </div>
    </div>
  );
}
