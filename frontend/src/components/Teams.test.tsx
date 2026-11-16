import { cleanup, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import type { User } from "../api/types";
import { ANALYST, renderPage, serveApi } from "../test/harness";
import Teams from "./Teams";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it("keeps deletion pending, shows errors inside the dialog, and allows retry", async () => {
  serveApi({ "/teams": [{ id: 1, name: "Payments", member_count: 0, asset_count: 2, members: [] }],
    "/users/directory": [] }, { ...ANALYST, role: "admin" } as User);
  const fallback = globalThis.fetch;
  let release!: (response: Response) => void;
  let deletes = 0;
  vi.stubGlobal("fetch", vi.fn((input: string, init?: RequestInit) => {
    if (input.endsWith("/teams/1") && init?.method === "DELETE") {
      deletes += 1;
      if (deletes === 1) return new Promise<Response>((resolve) => { release = resolve; });
      return Promise.resolve(new Response(null, { status: 204 }));
    }
    return fallback(input, init);
  }));
  renderPage(<Teams />);
  await userEvent.click(await screen.findByRole("button", { name: "Delete Payments" }));
  const dialog = screen.getByRole("dialog", { name: "Delete Payments?" });
  await userEvent.dblClick(within(dialog).getByRole("button", { name: "Delete" }));
  expect(within(dialog).getByRole("button", { name: "Working…" })).toHaveProperty("disabled", true);
  await userEvent.keyboard("{Escape}");
  expect(screen.getByRole("dialog")).toBe(dialog);
  expect(deletes).toBe(1);
  release(new Response(JSON.stringify({ detail: "Deletion failed" }), { status: 409 }));
  expect(await within(dialog).findByRole("alert")).toHaveProperty("textContent", "Deletion failed");
  expect(screen.getAllByRole("alert")).toHaveLength(1);
  await userEvent.click(within(dialog).getByRole("button", { name: "Delete" }));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  expect(deletes).toBe(2);
});
