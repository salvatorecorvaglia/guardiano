import { cleanup, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AcceptanceRequest, User } from "../api/types";
import { ANALYST, renderPage, serveApi } from "../test/harness";
import AcceptanceCard from "./AcceptanceCard";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const MANAGER = { ...ANALYST, id: 3, role: "manager", email: "manager@test.io" } as User;
const REQUEST = {
  id: 5,
  finding_id: 9,
  finding_title: "SQL injection",
  asset: { id: 1, name: "svc" },
  severity: "high",
  state: "pending",
  justification: "behind the WAF",
  until: "2026-12-31T22:59:59Z",
  requested_by: { id: ANALYST.id, email: ANALYST.email, full_name: ANALYST.full_name },
  decided_by: null,
  decided_at: null,
  decision_note: null,
  created_at: "2026-09-20T00:00:00Z",
} as unknown as AcceptanceRequest;

describe("AcceptanceCard", () => {
  it("lets an analyst request an acceptance", async () => {
    const calls = serveApi({ "/acceptance-requests": [], "POST /findings/9/acceptance-requests": REQUEST });
    renderPage(<AcceptanceCard findingId={9} status="open" />);
    await userEvent.click(await screen.findByRole("button", { name: /Request risk acceptance/ }));
    await userEvent.type(screen.getByRole("textbox"), "behind the WAF");
    await userEvent.type(screen.getByLabelText("Accepted until"), "2026-12-31");
    await userEvent.click(screen.getByRole("button", { name: "Send request" }));

    const asked = (c: (typeof calls)[number]) => c.path === "/findings/9/acceptance-requests";
    await waitFor(() => expect(calls.some(asked)).toBe(true));
    const body = calls.find(asked)!.body as { justification: string; until: string };
    expect(body.justification).toBe("behind the WAF");
    expect(body.until).toBe(new Date(2026, 11, 31, 23, 59, 59).toISOString());
  });

  it("offers a manager the decision, but not the person who asked", async () => {
    const calls = serveApi({ "/acceptance-requests": [REQUEST], "POST /acceptance-requests/5/approve": REQUEST }, MANAGER);
    renderPage(<AcceptanceCard findingId={9} status="open" />);
    expect(await screen.findByText("behind the WAF")).toBeTruthy();
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/acceptance-requests/5/approve")).toBe(true));
    cleanup();

    serveApi({ "/acceptance-requests": [REQUEST] }); // the analyst who asked
    renderPage(<AcceptanceCard findingId={9} status="open" />);
    expect(await screen.findByText("A manager other than you decides.")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
  });
});
