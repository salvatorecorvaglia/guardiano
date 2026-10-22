import { useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { endSession, refreshSession, setAccessToken, setSessionExpiredHandler, subscribeSession } from "../api/client";
import { post } from "../api/typed";
import type { LoginResponse, MfaChallenge, Role, User } from "../api/types";

const RANK: Record<Role, number> = { viewer: 0, analyst: 1, manager: 2, admin: 3 };

interface AuthState {
  user: User | null;
  ready: boolean;
  /** Resolves to a challenge when the account has a second factor, otherwise signs in. */
  login: (email: string, password: string) => Promise<MfaChallenge | null>;
  verifyMfa: (token: string, code: string) => Promise<void>;
  logout: () => Promise<void>;
  can: (min: Role) => boolean;
  applySession: (session: LoginResponse) => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [ready, setReady] = useState(false);
  const qc = useQueryClient();
  const identity = useRef<User | null>(null);

  const applySession = useCallback((session: LoginResponse) => {
    const previous = identity.current;
    if (previous && (previous.id !== session.user.id || previous.role !== session.user.role)) qc.clear();
    identity.current = session.user;
    setAccessToken(session.access_token);
    setUser(session.user);
  }, [qc]);

  const clear = useCallback(() => {
    setAccessToken(null);
    identity.current = null;
    setUser(null);
    qc.clear();
  }, [qc]);

  useEffect(() => {
    setSessionExpiredHandler(clear);
    const unsubscribe = subscribeSession(applySession);
    refreshSession()
      // Unreachable server on load: show the sign-in page, as for no session. Without this the
      // rejection went unhandled -- reported as an error in the console and by error trackers.
      .catch(() => undefined)
      .finally(() => setReady(true));
    return () => {
      unsubscribe();
      setSessionExpiredHandler(null);
    };
  }, [clear, applySession]);

  const login = useCallback(async (email: string, password: string) => {
    const r = await post("/api/v1/auth/login", { email, password });
    if ("mfa_required" in r) return r; // the password was right; a code is still needed
    applySession(r);
    return null;
  }, [applySession]);

  const verifyMfa = useCallback(async (mfa_token: string, code: string) => {
    const r = await post("/api/v1/auth/login/mfa", { mfa_token, code });
    applySession(r);
  }, [applySession]);

  const logout = useCallback(async () => {
    try {
      await endSession();
    } finally {
      clear();
    }
  }, [clear]);

  const can = useCallback((min: Role) => !!user && RANK[user.role] >= RANK[min], [user]);

  const value = useMemo(
    () => ({ user, ready, login, verifyMfa, logout, can, applySession }),
    [user, ready, login, verifyMfa, logout, can, applySession],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// biome-ignore lint/style/useComponentExportOnlyModules: This hook intentionally shares its provider module.
export function useAuth(): AuthState {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}
