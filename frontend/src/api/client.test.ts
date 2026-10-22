import { afterEach, describe, expect, it, vi } from "vitest";
import { api, buildQuery, endSession, refreshSession, setAccessToken, setSessionExpiredHandler } from "./client";

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

afterEach(() => {
  vi.unstubAllGlobals();
  setAccessToken(null);
});

describe("buildQuery", () => {
  it("skips empty values and repeats array params", () => {
    expect(buildQuery({ a: "x", b: "", c: null, d: undefined, s: ["open", "in_progress"], n: 0 })).toBe(
      "?a=x&s=open&s=in_progress&n=0",
    );
    expect(buildQuery({})).toBe("");
  });
});

describe("api", () => {
  it("refreshes the session once on 401 and retries with the new token", async () => {
    setAccessToken("old");
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json(401, { detail: "expired" }))
      .mockResolvedValueOnce(json(200, { access_token: "new", user: {} }))
      .mockResolvedValueOnce(json(200, { ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(api("/findings")).resolves.toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls[1][0]).toBe("/api/v1/auth/refresh");
    expect(fetchMock.mock.calls[2][1].headers.Authorization).toBe("Bearer new");
  });

  it("signals session expiry when the refresh fails", async () => {
    const expired = vi.fn();
    setSessionExpiredHandler(expired);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValueOnce(json(401, { detail: "expired" })).mockResolvedValueOnce(json(401, {})),
    );
    await expect(api("/findings")).rejects.toMatchObject({ status: 401, message: "expired" });
    expect(expired).toHaveBeenCalledOnce();
  });

  it("refreshes for authenticated endpoints under /auth/ too", async () => {
    setAccessToken("old");
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json(401, { detail: "expired" }))
      .mockResolvedValueOnce(json(200, { access_token: "new", user: {} }))
      .mockResolvedValueOnce(json(200, { enabled: true }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(api("/auth/mfa")).resolves.toEqual({ enabled: true });
    expect(fetchMock.mock.calls[1][0]).toBe("/api/v1/auth/refresh");
  });

  it("does not try to refresh after a wrong password", async () => {
    const expired = vi.fn();
    setSessionExpiredHandler(expired);
    const fetchMock = vi.fn().mockResolvedValueOnce(json(401, { detail: "Invalid email or password" }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(api("/auth/login", { body: {} })).rejects.toMatchObject({ status: 401 });
    expect(fetchMock).toHaveBeenCalledOnce();
    expect(expired).not.toHaveBeenCalled();
  });

  it("ends the session when the refreshed token is refused as well", async () => {
    const expired = vi.fn();
    setSessionExpiredHandler(expired);
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(json(401, {}))
        .mockResolvedValueOnce(json(200, { access_token: "new", user: {} }))
        .mockResolvedValueOnce(json(401, { detail: "Session was revoked" })),
    );
    await expect(api("/findings")).rejects.toMatchObject({ status: 401 });
    expect(expired).toHaveBeenCalledOnce();
  });

  it("passes the abort signal to fetch, on the retry after a refresh as well", async () => {
    const controller = new AbortController();
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json(401, {}))
      .mockResolvedValueOnce(json(200, { access_token: "new", user: {} }))
      .mockResolvedValueOnce(json(200, { ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await api("/findings", { signal: controller.signal });
    expect(fetchMock.mock.calls[0][1].signal).toBe(controller.signal);
    expect(fetchMock.mock.calls[2][1].signal).toBe(controller.signal);
    // The refresh is shared by every waiting request, so one page going away must not cancel it.
    expect(fetchMock.mock.calls[1][1].signal).toBeUndefined();
  });

  it("formats FastAPI validation errors", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(json(422, { detail: [{ loc: ["body", "name"], msg: "field required" }] })),
    );
    await expect(api("/assets", { body: {} })).rejects.toMatchObject({ status: 422, message: "name: field required" });
  });
});


describe("refresh coordination", () => {
  it("shares concurrent refresh requests", async () => {
    const fetchMock = vi.fn().mockResolvedValue(json(200, { access_token: "new", user: {} }));
    vi.stubGlobal("fetch", fetchMock);
    const first = refreshSession();
    const second = refreshSession();
    expect(first).toBe(second);
    await Promise.all([first, second]);
    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it("does not restore access after logout starts during refresh", async () => {
    let release!: (response: Response) => void;
    const pending = new Promise<Response>((resolve) => { release = resolve; });
    const fetchMock = vi.fn().mockReturnValueOnce(pending).mockResolvedValueOnce(new Response(null, { status: 204 }))
      .mockResolvedValueOnce(json(200, {}));
    vi.stubGlobal("fetch", fetchMock);
    const refresh = refreshSession();
    const logout = endSession();
    release(json(200, { access_token: "too-late", user: {} }));
    expect(await refresh).toBeNull();
    await logout;
    await api("/findings");
    expect(fetchMock.mock.calls[1][0]).toBe("/api/v1/auth/logout");
    expect(fetchMock.mock.calls[2][1].headers.Authorization).toBeUndefined();
  });
});
