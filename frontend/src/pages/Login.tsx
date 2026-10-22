import { useMutation } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import { type FormEvent, useState } from "react";
import { useMeta } from "../api/queries";
import { request as apiRequest } from "../api/typed";
import type { MfaChallenge } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { ErrorBox, Field, Modal } from "../components/ui";

/** Asks the server to email a reset link. The reply never says whether the address exists. */
function ForgotPassword({ onClose }: { onClose: () => void }) {
  const [email, setEmail] = useState("");
  const request = useMutation({
    mutationFn: () =>
      apiRequest("post", "/api/v1/auth/forgot-password", { body: { email: email.trim() } }),
  });
  return (
    <Modal
      open
      onClose={onClose}
      title="Reset your password"
      footer={
        request.isSuccess ? (
          <button className="btn-primary" onClick={onClose}>
            Done
          </button>
        ) : (
          <>
            <button className="btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button
              className="btn-primary"
              disabled={!email.trim() || request.isPending}
              onClick={() => request.mutate()}
            >
              {request.isPending ? "Sending…" : "Send reset link"}
            </button>
          </>
        )
      }
    >
      {request.isSuccess ? (
        <p className="text-sm">
          If <span className="font-medium">{email}</span> has an account, a
          reset link is on its way. It expires in an hour and works once.
        </p>
      ) : (
        <>
          <Field label="Email">
            <input
              className="input"
              type="email"
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </Field>
          <ErrorBox error={request.error} />
        </>
      )}
    </Modal>
  );
}

export default function Login() {
  const { login, verifyMfa } = useAuth();
  const [challenge, setChallenge] = useState<MfaChallenge | null>(null);
  const [code, setCode] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [forgot, setForgot] = useState(false);
  const meta = useMeta();
  // The SSO callback sends people back here with a reason when it could not sign them in.
  const ssoError = new URLSearchParams(window.location.search).get("sso_error");

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      setChallenge(await login(email, password));
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-full items-center justify-center px-4 py-12">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center text-center">
          <ShieldCheck className="h-10 w-10 text-accent" />
          <h1 className="mt-3 text-2xl font-semibold tracking-tight">
            Guardiano
          </h1>
          <p className="mt-1 text-sm text-ink2">
            Application vulnerability management
          </p>
        </div>
        {ssoError && (
          <div
            className="mb-4 rounded-lg border border-danger/40 bg-danger/10 px-3 py-2 text-sm text-danger"
            role="alert"
          >
            Single sign-on failed: {ssoError}
          </div>
        )}
        {meta.data?.oidc_enabled && (
          <a
            className="btn-primary mb-4 w-full justify-center"
            href={`/api/v1/auth/oidc/login${window.location.pathname !== "/" ? `?next=${encodeURIComponent(window.location.pathname + window.location.search)}` : ""}`}
          >
            {meta.data.oidc_label}
          </a>
        )}
        {challenge ? (
          <form
            className="card space-y-4 p-6"
            onSubmit={async (e) => {
              e.preventDefault();
              setBusy(true);
              setError(null);
              try {
                await verifyMfa(challenge.mfa_token, code);
              } catch (err) {
                setError(err);
              } finally {
                setBusy(false);
              }
            }}
          >
            <h1 className="text-base font-semibold">Enter your code</h1>
            <p className="text-sm text-ink2">
              Open your authenticator app, or use one of your recovery codes.
            </p>
            <Field label="Code">
              <input
                className="input font-mono"
                inputMode="numeric"
                autoComplete="one-time-code"
                autoFocus
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
            </Field>
            <ErrorBox error={error} />
            <button className="btn-primary w-full" disabled={busy || code.length < 6}>
              {busy ? "Checking…" : "Sign in"}
            </button>
            <button
              type="button"
              className="w-full text-center text-xs text-accent hover:underline"
              onClick={() => {
                setChallenge(null);
                setCode("");
                setError(null);
              }}
            >
              Back
            </button>
          </form>
        ) : meta.data && !meta.data.local_login ? (
          <p className="card p-6 text-center text-sm text-ink2">
            This server signs in through your identity provider.
          </p>
        ) : (
          <form onSubmit={submit} className="card space-y-4 p-6">
            <Field label="Email">
              <input
                className="input"
                type="email"
                autoComplete="username"
                required
                autoFocus
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </Field>
            <Field label="Password">
              <input
                className="input"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </Field>
            <ErrorBox error={error} />
            <button className="btn-primary w-full" disabled={busy}>
              {busy ? "Signing in…" : "Sign in"}
            </button>
            {meta.data?.email_enabled && (
              <button
                type="button"
                className="w-full text-center text-xs text-accent hover:underline"
                onClick={() => setForgot(true)}
              >
                Forgot your password?
              </button>
            )}
          </form>
        )}
        {forgot && <ForgotPassword onClose={() => setForgot(false)} />}
      </div>
    </div>
  );
}
