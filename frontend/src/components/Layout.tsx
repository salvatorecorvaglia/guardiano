import clsx from "clsx";
import { Boxes, Bug, FileText, LayoutDashboard, LogOut, Menu, Monitor, Moon, Package, ScanLine, ScrollText, Settings as SettingsIcon, ShieldCheck, Sun, Upload, Users as UsersIcon } from "lucide-react";
import { Suspense, useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import ErrorBoundary from "./ErrorBoundary";
import NotificationBell from "./NotificationBell";
import SearchPalette from "./SearchPalette";
import UploadDialog from "./UploadDialog";
import { Spinner } from "./ui";

type Theme = "system" | "light" | "dark";

function useTheme(): [Theme, (t: Theme) => void] {
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      const t = localStorage.getItem("guardiano-theme");
      return t === "light" || t === "dark" ? t : "system";
    } catch {
      return "system";
    }
  });
  useEffect(() => {
    // Always an explicit light or dark, as public/theme-init.js sets it; "system" resolves to what the
    // OS prefers now, and theme-init's listener follows it from there.
    const dark = theme === "dark" || (theme === "system" && window.matchMedia?.("(prefers-color-scheme: dark)").matches);
    document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
    try {
      if (theme === "system") localStorage.removeItem("guardiano-theme");
      else localStorage.setItem("guardiano-theme", theme);
    } catch {
      /* storage unavailable */
    }
  }, [theme]);
  return [theme, setTheme];
}

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/findings?status=open&status=in_progress", label: "Findings", icon: Bug },
  { to: "/assets", label: "Assets", icon: Boxes },
  { to: "/components", label: "Components", icon: Package },
  { to: "/scans", label: "Scans", icon: ScanLine },
  { to: "/reports", label: "Reports", icon: FileText },
] as const;

export default function Layout() {
  const { user, logout, can } = useAuth();
  const [theme, setTheme] = useTheme();
  const [menuOpen, setMenuOpen] = useState(false);
  const [uploadOpen, setUploadOpen] = useState(false);
  const location = useLocation();

  const contentRef = useRef<HTMLDivElement>(null);
  const drawerRef = useRef<HTMLElement>(null);

  // biome-ignore lint/correctness/useExhaustiveDependencies: Close the drawer after route navigation.
  useEffect(() => setMenuOpen(false), [location.pathname]);
  useEffect(() => {
    if (!menuOpen) return;
    const previous = document.activeElement as HTMLElement | null;
    const content = contentRef.current;
    const desktop = document.querySelector<HTMLElement>("aside.hidden");
    if (content) content.inert = true;
    if (desktop) desktop.inert = true;
    const focusable = () => [...(drawerRef.current?.querySelectorAll<HTMLElement>("a[href], button:not([disabled])") ?? [])].filter((el) => el.getClientRects().length > 0);
    focusable()[0]?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { e.preventDefault(); setMenuOpen(false); }
      if (e.key === "Tab") {
        const nodes = focusable();
        const first = nodes[0], last = nodes.at(-1);
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last?.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first?.focus(); }
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      if (content) content.inert = false;
      if (desktop) desktop.inert = false;
      previous?.focus();
    };
  }, [menuOpen]);

  const linkClass = ({ isActive }: { isActive: boolean }) =>
    clsx(
      "flex items-center gap-2.5 rounded-lg px-2.5 py-1.5 text-sm transition-colors",
      isActive ? "bg-accent/10 font-medium text-accent" : "text-ink2 hover:bg-ink/5 hover:text-ink",
    );

  const nextTheme: Record<Theme, Theme> = { system: "light", light: "dark", dark: "system" };
  const ThemeIcon = theme === "light" ? Sun : theme === "dark" ? Moon : Monitor;

  const sidebar = (
    <nav className="flex h-full flex-col gap-1 p-3">
      <div className="mb-4 flex items-center gap-2 px-2 pt-1">
        <ShieldCheck className="h-6 w-6 text-accent" />
        <span className="text-base font-semibold tracking-tight">Guardiano</span>
      </div>
      {NAV.map(({ to, label, icon: Icon, ...rest }) => (
        <NavLink key={to} to={to} className={linkClass} end={"end" in rest}>
          <Icon className="h-4 w-4" />
          {label}
        </NavLink>
      ))}
      <div className="mt-4 px-2.5 pb-1 text-[11px] font-medium uppercase tracking-wider text-muted">
        {can("admin") ? "Administration" : "Account"}
      </div>
      {can("admin") && (
        <NavLink to="/users" className={linkClass}>
          <UsersIcon className="h-4 w-4" />
          Users
        </NavLink>
      )}
      {can("admin") && (
        <NavLink to="/admin" className={linkClass}>
          <ScrollText className="h-4 w-4" />
          System
        </NavLink>
      )}
      <NavLink to="/settings" className={linkClass}>
        <SettingsIcon className="h-4 w-4" />
        Settings &amp; API tokens
      </NavLink>

      <div className="mt-auto border-t border-line pt-3">
        <div className="px-2.5">
          <div className="truncate text-sm font-medium">{user?.full_name || user?.email}</div>
          <div className="truncate text-xs text-muted">
            {user?.email} · <span className="capitalize">{user?.role}</span>
          </div>
        </div>
        <div className="mt-2 flex gap-1">
          <button
            className="btn-ghost flex-1 justify-start"
            onClick={() => setTheme(nextTheme[theme])}
            title="Toggle theme"
            aria-label={`Theme: ${theme}`}
          >
            <ThemeIcon className="h-4 w-4" />
            <span className="capitalize">{theme}</span>
          </button>
          <button className="btn-ghost" onClick={logout} title="Sign out" aria-label="Sign out">
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </nav>
  );

  return (
    <div className="flex h-full">
      <aside className="hidden w-60 shrink-0 border-r border-line bg-surface lg:block print:hidden">{sidebar}</aside>
      {menuOpen && (
        <div className="fixed inset-0 z-40 lg:hidden" onClick={() => setMenuOpen(false)}>
          <div className="absolute inset-0 bg-black/40" />
          <aside
            ref={drawerRef}
            role="dialog"
            aria-modal="true"
            aria-label="Navigation"
            className="absolute inset-y-0 left-0 w-64 border-r border-line bg-surface"
            onClick={(e) => e.stopPropagation()}
          >
            {sidebar}
          </aside>
        </div>
      )}
      <div ref={contentRef} className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center gap-3 border-b border-line bg-surface px-4 print:hidden">
          <button className="btn-ghost -ml-2 p-1.5 lg:hidden" onClick={() => setMenuOpen(true)} aria-label="Open menu">
            <Menu className="h-5 w-5" />
          </button>
          <SearchPalette />
          <div className="flex-1" />
          <NotificationBell />
          {can("analyst") && (
            <button className="btn-primary" onClick={() => setUploadOpen(true)}>
              <Upload className="h-4 w-4" />
              Upload scan
            </button>
          )}
        </header>
        <main className="flex-1 overflow-y-auto print:overflow-visible">
          <div className="mx-auto max-w-[1400px] px-4 py-6 sm:px-6">
            <ErrorBoundary resetKey={location.pathname}>
              <Suspense
                fallback={
                  <div className="flex justify-center py-16">
                    <Spinner />
                  </div>
                }
              >
                <Outlet />
              </Suspense>
            </ErrorBoundary>
          </div>
        </main>
      </div>
      <UploadDialog open={uploadOpen} onClose={() => setUploadOpen(false)} />
    </div>
  );
}
