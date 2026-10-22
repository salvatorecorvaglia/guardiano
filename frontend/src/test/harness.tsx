// biome-ignore-all lint/style/useComponentExportOnlyModules: Test helpers are never hot-reloaded.
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { vi } from "vitest";
import type { Finding, User } from "../api/types";
import { AuthProvider } from "../auth/AuthContext";
import { Toaster } from "../components/Toaster";

export const ANALYST: User = {
  id: 2,
  email: "analyst@test.io",
  full_name: "Ann Alyst",
  role: "analyst",
  is_active: true,
} as User;

type Handler = (url: URL, init: RequestInit) => unknown;

/**
 * Serves `fetch` from a table of "METHOD /path" -> response body (or a function of the request).
 * The session refresh the app makes on start is answered with `user`. Anything unlisted is a 404, so a
 * test fails loudly on a request it did not expect rather than hanging on an unresolved promise.
 */
export function serveApi(routes: Record<string, unknown | Handler>, user: User = ANALYST) {
  const calls: { method: string; path: string; url: URL; body: unknown }[] = [];
  const fetchMock = vi.fn(async (input: string, init: RequestInit = {}) => {
    const url = new URL(input, "http://localhost");
    const method = (init.method ?? "GET").toUpperCase();
    const path = url.pathname.replace(/^\/api\/v1/, "");
    calls.push({ method, path, url, body: typeof init.body === "string" ? JSON.parse(init.body) : init.body });
    if (path === "/auth/refresh") return json(200, { access_token: "t", expires_in: 1800, user });
    const route = routes[`${method} ${path}`] ?? routes[path];
    if (route === undefined) return json(404, { detail: `unexpected ${method} ${path}` });
    const body = typeof route === "function" ? (route as Handler)(url, init) : route;
    return json(200, body);
  });
  vi.stubGlobal("fetch", fetchMock);
  return calls;
}

function json(status: number, body: unknown) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

/** Where the router is now, for asserting on navigation. */
function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{location.pathname + location.search}</output>;
}

/** A page with the app's real providers, at `route`, matched by `path`. */
export function renderPage(page: ReactNode, { route = "/", path = "/" }: { route?: string; path?: string } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[route]}>
        <AuthProvider>
          <Toaster>
            <Routes>
              <Route path={path} element={page} />
              <Route path="*" element={null} />
            </Routes>
            <LocationProbe />
          </Toaster>
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

let nextId = 1;

export function finding(overrides: Partial<Finding> = {}): Finding {
  const id = overrides.id ?? nextId++;
  return {
    id,
    title: `Finding ${id}`,
    type: "sast",
    severity: "high",
    status: "open",
    cvss_score: null,
    cwe: ["CWE-89"],
    cve_id: null,
    vuln_id: null,
    rule_id: "r",
    file_path: "app/db.py",
    line_start: 42,
    package_name: null,
    package_version: null,
    fixed_version: null,
    tags: [],
    tools: ["Semgrep"],
    asset: { id: 1, name: "payments-api" },
    assignee: null,
    overdue: false,
    in_kev: false,
    priority: 5,
    kev_ransomware: false,
    first_seen_at: "2026-09-01T00:00:00Z",
    last_seen_at: "2026-09-20T00:00:00Z",
    closed_at: null,
    ...overrides,
  } as Finding;
}

export const page = <T,>(items: T[]) => ({ items, total: items.length, page: 1, page_size: 50 });
