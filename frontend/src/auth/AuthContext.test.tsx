import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Role, User } from "../api/types";
import { refreshSession } from "../api/client";
import { AuthProvider, useAuth } from "./AuthContext";

type Auth = ReturnType<typeof useAuth>;
const person = (role: Role): User => ({ id: 1, email: "a@test.io", full_name: "A", role, is_active: true }) as User;
const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

/** Mounts the provider and hands back the live context, re-read after every render. */
function mount(fetchMock: ReturnType<typeof vi.fn>) {
  vi.stubGlobal("fetch", fetchMock);
  const client = new QueryClient();
  const seen: { current: Auth | null } = { current: null };
  function Probe() {
    seen.current = useAuth();
    return <output data-testid="who">{seen.current.ready ? (seen.current.user?.email ?? "nobody") : "loading"}</output>;
  }
  render(
    <QueryClientProvider client={client}>
      <AuthProvider>
        <Probe />
      </AuthProvider>
    </QueryClientProvider>,
  );
  return { auth: () => seen.current!, client };
}

describe("AuthContext", () => {
  it("updates role controls and clears cached data after automatic refresh changes identity", async () => {
    const { auth, client } = mount(vi.fn()
      .mockResolvedValueOnce(json(200, { access_token: "old", user: person("admin") }))
      .mockResolvedValueOnce(json(200, { access_token: "new", user: person("viewer") })));
    await waitFor(() => expect(auth().can("admin")).toBe(true));
    client.setQueryData(["private"], { secret: true });
    await act(async () => { await refreshSession(); });
    expect(auth().user?.role).toBe("viewer");
    expect(auth().can("admin")).toBe(false);
    expect(client.getQueryData(["private"])).toBeUndefined();
  });
  it("restores the session on load from the refresh cookie", async () => {
    mount(vi.fn().mockResolvedValueOnce(json(200, { access_token: "t", user: person("analyst") })));
    await waitFor(() => expect(screen.getByTestId("who").textContent).toBe("a@test.io"));
  });

  it("is ready and signed out when there is no session, including when the network fails", async () => {
    mount(vi.fn().mockResolvedValueOnce(json(401, {})));
    await waitFor(() => expect(screen.getByTestId("who").textContent).toBe("nobody"));
    cleanup();
    mount(vi.fn().mockRejectedValueOnce(new TypeError("Failed to fetch")));
    await waitFor(() => expect(screen.getByTestId("who").textContent).toBe("nobody"));
  });

  it("signs in in two steps when the account has a second factor", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json(401, {})) // no session on load
      .mockResolvedValueOnce(json(200, { mfa_required: true, mfa_token: "challenge" }))
      .mockResolvedValueOnce(json(200, { access_token: "t", user: person("analyst") }));
    const { auth } = mount(fetchMock);
    await waitFor(() => expect(auth().ready).toBe(true));

    let challenge: Awaited<ReturnType<Auth["login"]>> = null;
    await act(async () => {
      challenge = await auth().login("a@test.io", "pw");
    });
    expect(challenge).toMatchObject({ mfa_token: "challenge" });
    expect(auth().user).toBeNull(); // the password alone is not a session

    await act(() => auth().verifyMfa("challenge", "123456"));
    expect(auth().user?.email).toBe("a@test.io");
    expect(JSON.parse(fetchMock.mock.calls[2][1].body)).toEqual({ mfa_token: "challenge", code: "123456" });
  });

  it("ranks roles, so a page asks for a minimum", async () => {
    const { auth } = mount(vi.fn().mockResolvedValueOnce(json(200, { access_token: "t", user: person("manager") })));
    await waitFor(() => expect(auth().user).not.toBeNull());
    expect([auth().can("viewer"), auth().can("analyst"), auth().can("manager"), auth().can("admin")]).toEqual([
      true,
      true,
      true,
      false,
    ]);
  });

  it("forgets the user and every cached query on sign-out, even if the server call fails", async () => {
    const { auth, client } = mount(
      vi
        .fn()
        .mockResolvedValueOnce(json(200, { access_token: "t", user: person("admin") }))
        .mockRejectedValueOnce(new TypeError("Failed to fetch")),
    );
    await waitFor(() => expect(auth().user).not.toBeNull());
    client.setQueryData(["findings"], { secret: true });

    await act(() => auth().logout().catch(() => {}));
    expect(auth().user).toBeNull();
    expect(client.getQueryData(["findings"])).toBeUndefined();
  });
});
