import { type ComponentType, type ReactElement, lazy, useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import type { Role } from "./api/types";
import { useAuth } from "./auth/AuthContext";
import MfaCard from "./components/MfaCard";
import Layout from "./components/Layout";
import { Spinner } from "./components/ui";
import Login from "./pages/Login";
import ResetPassword from "./pages/ResetPassword";

const RELOADED = "guardiano-chunk-reload";

/**
 * A page loaded on first visit rather than in the initial bundle, so the sign-in page no longer
 * downloads the charting library and every other page with it.
 *
 * After a deploy, a tab that stayed open asks for chunk files the new build no longer has. Reloading
 * once fetches the new index; the flag stops a genuinely broken chunk from reloading forever.
 */
function page(load: () => Promise<{ default: ComponentType }>) {
  return lazy(() =>
    load().then(
      (module) => {
        try {
          sessionStorage.removeItem(RELOADED);
        } catch {
          /* storage unavailable: nothing to clear */
        }
        return module;
      },
      (error: unknown) => {
        try {
          if (!sessionStorage.getItem(RELOADED)) {
            sessionStorage.setItem(RELOADED, "1");
            window.location.reload();
            return new Promise<never>(() => {});
          }
        } catch {
          /* storage unavailable: fall through to the error boundary */
        }
        throw error;
      },
    ),
  );
}

const Admin = page(() => import("./pages/Admin"));
const AssetDetail = page(() => import("./pages/AssetDetail"));
const Assets = page(() => import("./pages/Assets"));
const Components = page(() => import("./pages/Components"));
const Dashboard = page(() => import("./pages/Dashboard"));
const FindingDetail = page(() => import("./pages/FindingDetail"));
const Findings = page(() => import("./pages/Findings"));
const Reports = page(() => import("./pages/Reports"));
const ScanDetail = page(() => import("./pages/ScanDetail"));
const Scans = page(() => import("./pages/Scans"));
const Settings = page(() => import("./pages/Settings"));
const Users = page(() => import("./pages/Users"));
const Vulnerability = page(() => import("./pages/Vulnerability"));

function RequireRole({ min, children }: { min: Role; children: ReactElement }) {
  const { can } = useAuth();
  return can(min) ? children : <Navigate to="/" replace />;
}

export default function App() {
  const { user, ready, logout } = useAuth();
  const [enrollingId, setEnrollingId] = useState<number | null>(null);
  useEffect(() => {
    if (user?.mfa_enrollment_required) setEnrollingId(user.id);
    else if (!user) setEnrollingId(null);
  }, [user]);
  if (!ready)
    return (
      <div className="flex h-full items-center justify-center">
        <Spinner />
      </div>
    );
  // The reset link is followed while signed out, so it is handled before the sign-in form.
  if (!user) return window.location.pathname === "/reset-password" ? <ResetPassword /> : <Login />;

  if (user.mfa_enrollment_required || enrollingId === user.id) return <div className="mx-auto max-w-xl p-6"><h1 className="mb-4 text-xl">Set up two-factor authentication</h1><MfaCard /><button className="btn-primary mt-4" disabled={user.mfa_enrollment_required} onClick={() => setEnrollingId(null)}>Continue after setup</button><button className="btn-ghost ml-2" onClick={() => void logout()}>Sign out</button></div>;

  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="findings" element={<Findings />} />
        <Route path="findings/:id" element={<FindingDetail />} />
        <Route path="assets" element={<Assets />} />
        <Route path="assets/:id" element={<AssetDetail />} />
        <Route path="components" element={<Components />} />
        <Route path="scans" element={<Scans />} />
        <Route path="reports" element={<Reports />} />
        <Route path="scans/:id" element={<ScanDetail />} />
        <Route path="vulnerabilities/:id" element={<Vulnerability />} />
        <Route
          path="users"
          element={
            <RequireRole min="admin">
              <Users />
            </RequireRole>
          }
        />
        <Route
          path="admin"
          element={
            <RequireRole min="admin">
              <Admin />
            </RequireRole>
          }
        />
        <Route path="settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
