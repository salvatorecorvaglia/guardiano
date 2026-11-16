import { cleanup, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { afterEach, expect, it, vi } from "vitest";
import { renderPage, serveApi } from "../test/harness";
import AsyncPicker from "./AsyncPicker";
import UserMultiPicker from "./UserMultiPicker";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it("searches bounded pages and keeps a selected asset outside the current page", async () => {
  const calls = serveApi({ "/assets/options/search": (url: URL) => ({
    items: url.searchParams.get("q") ? [{ id: 3, name: "target" }] : [{ id: 1, name: "first" }],
    selected: { id: 99, name: "Selected asset" }, total: url.searchParams.get("q") ? 1 : 101,
    page: Number(url.searchParams.get("page")), page_size: 50,
  }) });
  renderPage(<AsyncPicker kind="assets" label="Asset" value="99" emptyLabel="All assets" onChange={() => {}} />);
  await screen.findByRole("option", { name: "Selected asset" });
  await waitFor(() => expect(screen.getByRole("combobox", { name: "Asset" })).toHaveProperty("disabled", false));
  expect(screen.getByRole("combobox", { name: "Asset" })).toHaveProperty("value", "99");
  await userEvent.click(screen.getByRole("button", { name: "Next asset results" }));
  await waitFor(() => expect(calls.some((call) => call.url.searchParams.get("page") === "2")).toBe(true));
  await new Promise((resolve) => setTimeout(resolve, 250));
  expect(screen.getByText("2 / 3")).toBeTruthy();
  await userEvent.type(screen.getByRole("searchbox", { name: "Search asset" }), "target");
  await screen.findByRole("option", { name: "target" });
  const searched = calls.find((call) => call.url.searchParams.get("q") === "target")!;
  expect(searched.url.searchParams.get("page")).toBe("1");
  expect(searched.url.searchParams.get("page_size")).toBe("50");
  expect(screen.getByRole("combobox", { name: "Asset" })).toHaveProperty("value", "99");
});

it("shows search errors, disables stale choices, and retries", async () => {
  serveApi({ "/assets/options/search": { items: [], selected: null, total: 0, page: 1, page_size: 50 } });
  const fallback = globalThis.fetch;
  let fail = true;
  vi.stubGlobal("fetch", vi.fn((input: string, init?: RequestInit) => input.includes("/options/search") && fail
    ? Promise.resolve(new Response(JSON.stringify({ detail: "Search unavailable" }), { status: 400 })) : fallback(input, init)));
  renderPage(<AsyncPicker kind="assets" label="Asset" value="" emptyLabel="All assets" onChange={() => {}} />);
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", "Search unavailable");
  expect(screen.getByRole("combobox")).toHaveProperty("disabled", true);
  fail = false;
  await userEvent.click(screen.getByRole("button", { name: "Retry asset" }));
  await waitFor(() => expect(screen.getByRole("combobox")).toHaveProperty("disabled", false));
  expect(screen.getByText("No matching assets.")).toBeTruthy();
});

function People() {
  const [ids, setIds] = useState([99]);
  return <UserMultiPicker label="Members" value={ids} onChange={setIds} />;
}

it("preserves selected people across searches and allows explicit removal", async () => {
  serveApi({ "/users/directory/search": { items: [{ id: 1, full_name: "New person", email: "new@test.io" }], selected: null, total: 1, page: 1, page_size: 50 },
    "/users/directory/lookup": [{ id: 99, full_name: "Existing person", email: "existing@test.io" }] });
  renderPage(<People />);
  await screen.findByText("Existing person");
  await waitFor(() => expect(screen.getByRole("combobox")).toHaveProperty("disabled", false));
  await userEvent.selectOptions(screen.getByRole("combobox"), "1");
  await screen.findByRole("button", { name: "Remove Existing person" });
  expect(screen.getAllByRole("listitem")).toHaveLength(2);
  await userEvent.click(screen.getByRole("button", { name: "Remove Existing person" }));
  expect(screen.getAllByRole("listitem")).toHaveLength(1);
});

it("cancels obsolete searches instead of showing their late results", async () => {
  serveApi({});
  const fallback = globalThis.fetch;
  const aborted = vi.fn();
  vi.stubGlobal("fetch", vi.fn((input: string, init?: RequestInit) => {
    if (!input.includes("/options/search")) return fallback(input, init);
    const url = new URL(input, "http://localhost");
    if (url.searchParams.get("q")) return Promise.resolve(new Response(JSON.stringify({
      items: [{ id: 2, name: "Current result" }], selected: null, total: 1, page: 1, page_size: 50,
    }), { status: 200 }));
    return new Promise<Response>((_resolve, reject) => init?.signal?.addEventListener("abort", () => {
      aborted(); reject(new DOMException("Aborted", "AbortError"));
    }));
  }));
  renderPage(<AsyncPicker kind="assets" label="Asset" value="" emptyLabel="All assets" onChange={() => {}} />);
  await userEvent.type(screen.getByRole("searchbox"), "current");
  await screen.findByRole("option", { name: "Current result" });
  expect(aborted).toHaveBeenCalledOnce();
});
