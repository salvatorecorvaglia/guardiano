import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import QRCode from "qrcode";
import { useEffect, useState } from "react";
import { request } from "../api/typed";

import { useAuth } from "../auth/AuthContext";
import { useToast } from "./Toaster";
import { ErrorBox, Field, Modal, Spinner } from "./ui";


function RecoveryCodes({ codes, onClose }: { codes: string[]; onClose: () => void }) {
  return (
    <Modal
      open
      onClose={onClose}
      title="Save your recovery codes"
      footer={
        <button className="btn-primary" onClick={onClose}>
          I have saved them
        </button>
      }
    >
      <p className="text-sm">
        Each code signs you in once if you lose your phone. Keep them somewhere safe; they are not shown
        again.
      </p>
      <pre className="grid grid-cols-2 gap-x-6 gap-y-1 rounded-lg border border-line bg-page p-3 font-mono text-sm">
        {codes.map((c) => (
          <span key={c}>{c}</span>
        ))}
      </pre>
    </Modal>
  );
}

/** Enrol, replace recovery codes, or turn two-factor authentication off. */
export default function MfaCard() {
  const qc = useQueryClient();
  const toast = useToast();
  const { applySession, logout } = useAuth();
  const status = useQuery({ queryKey: ["mfa"], queryFn: ({ signal }) => request("get", "/api/v1/auth/mfa", { signal }) });
  const [setup, setSetup] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [password, setPassword] = useState("");
  const [disabling, setDisabling] = useState(false);

  useEffect(() => {
    if (!setup) return setQr(null);
    // Rendering is asynchronous. Without this flag, cancelling and starting setup again quickly could
    // let the older render finish last and show the QR code of a secret that has been replaced -- one
    // that can never produce a code the server accepts.
    let current = true;
    QRCode.toDataURL(setup.otpauth_uri, { margin: 1, width: 220 })
      .then((url) => current && setQr(url))
      .catch(() => current && setQr(null));
    return () => {
      current = false;
    };
  }, [setup]);

  const refresh = () => qc.invalidateQueries({ queryKey: ["mfa"] });
  const begin = useMutation({
    mutationFn: () => request("post", "/api/v1/auth/mfa/setup", { }),
    onSuccess: (data) => {
      setCode("");
      setSetup(data);
    },
  });
  const enable = useMutation({
    mutationFn: () => request("post", "/api/v1/auth/mfa/enable", { body: { code } }),
    onSuccess: (data) => {
      applySession(data.session);
      setSetup(null);
      setCodes(data.recovery_codes);
      refresh();
      toast("Two-factor authentication is on");
    },
  });
  const regenerate = useMutation({
    mutationFn: () => request("post", "/api/v1/auth/mfa/recovery-codes", { body: { code } }),
    onSuccess: (data) => {
      setCode("");
      setCodes(data.recovery_codes);
      refresh();
    },
  });
  const disable = useMutation({
    mutationFn: () => request("post", "/api/v1/auth/mfa/disable", { body: { password, code } }),
    onSuccess: () => {
      setDisabling(false);
      setPassword("");
      refresh();
      toast("Two-factor authentication is off");
      void logout();
    },
  });

  const s = status.data;

  return (
    <section className="card p-4">
      <h2 className="text-sm font-semibold">Two-factor authentication</h2>
      <p className="mb-3 text-xs text-muted">
        An app on your phone generates a code you enter after your password.
        {s?.required && " Your role is required to use it."}
      </p>
      <ErrorBox error={status.error ?? begin.error ?? enable.error ?? regenerate.error ?? disable.error} />

      {!s ? (
        <Spinner />
      ) : s.enabled ? (
        <div className="space-y-3">
          <p className="text-sm text-good">
            <ShieldCheck className="mr-1 inline h-4 w-4" />
            On since {new Date(s.confirmed_at ?? "").toLocaleDateString()} · {s.recovery_codes_left} recovery
            code{s.recovery_codes_left === 1 ? "" : "s"} left
          </p>
          <div className="flex flex-wrap items-end gap-2">
            <Field label="Code from your app">
              <input className="input w-36 font-mono" inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value)} />
            </Field>
            <button className="btn-secondary" disabled={code.length < 6 || regenerate.isPending} onClick={() => regenerate.mutate()}>
              New recovery codes
            </button>
            <button className="btn-ghost ml-auto text-danger" onClick={() => setDisabling(true)}>
              Turn off
            </button>
          </div>
        </div>
      ) : setup ? (
        <div className="space-y-3">
          <p className="text-sm">Scan this with your authenticator app, then enter the code it shows.</p>
          <div className="flex flex-wrap items-start gap-4">
            {qr ? <img src={qr} alt="Setup QR code" className="rounded-lg border border-line bg-white p-2" /> : <Spinner />}
            <div className="space-y-2">
              <div className="text-xs text-muted">Or type the key in by hand:</div>
              <pre className="rounded border border-line bg-page px-2 py-1 font-mono text-xs">{setup.secret}</pre>
              <Field label="Code from your app">
                <input className="input w-36 font-mono" inputMode="numeric" maxLength={6} autoFocus value={code} onChange={(e) => setCode(e.target.value)} />
              </Field>
              <div className="flex gap-2">
                <button className="btn-primary" disabled={code.length < 6 || enable.isPending} onClick={() => enable.mutate()}>
                  Turn on
                </button>
                <button className="btn-secondary" onClick={() => setSetup(null)}>
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      ) : (
        <button className="btn-secondary" disabled={begin.isPending} onClick={() => begin.mutate()}>
          Set up two-factor authentication
        </button>
      )}

      {codes && <RecoveryCodes codes={codes} onClose={() => setCodes(null)} />}
      <Modal
        open={disabling}
        onClose={() => setDisabling(false)}
        title="Turn off two-factor authentication"
        footer={
          <>
            <button className="btn-secondary" onClick={() => setDisabling(false)}>
              Cancel
            </button>
            <button className="btn-danger" disabled={!password || code.length < 6 || disable.isPending} onClick={() => disable.mutate()}>
              Turn off
            </button>
          </>
        }
      >
        <p className="text-sm">Your account will be protected by its password alone.</p>
        <Field label="Current password">
          <input className="input" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </Field>
        <Field label="Authenticator or recovery code">
          <input className="input" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} />
        </Field>
        <ErrorBox error={disable.error} />
      </Modal>
    </section>
  );
}
