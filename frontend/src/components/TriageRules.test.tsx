import { cleanup, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { TriageRule, User } from "../api/types";
import { ANALYST, renderPage, serveApi } from "../test/harness";
import TriageRules from "./TriageRules";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const MANAGER = { ...ANALYST, id: 3, role: "manager" } as User;

const RULE = {
  id: 4,
  name: "Known exploited to the platform team",
  enabled: true,
  priority: 100,
  asset: null,
  match: { kev: true },
  action: { tags: ["urgent"] },
  expires_at: null,
  applied_count: 0,
  created_by: null,
  created_at: "2026-09-01T00:00:00Z",
  updated_at: "2026-09-01T00:00:00Z",
} as unknown as TriageRule;

describe("TriageRules", () => {
  it("describes the new conditions and applies a rule to existing findings after confirming", async () => {
    const calls = serveApi({ "/triage-rules": [RULE], "POST /triage-rules/4/apply": { job_id: 9 } }, MANAGER);
    renderPage(<TriageRules />);
    expect(await screen.findByText("known exploited (KEV)")).toBeTruthy();

    await userEvent.click(screen.getByRole("button", { name: `Apply ${RULE.name} to existing findings` }));
    expect(calls.some((c) => c.path === "/triage-rules/4/apply")).toBe(false); // nothing before confirming
    await userEvent.click(screen.getByRole("button", { name: "Apply rule" }));

    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/triage-rules/4/apply")).toBe(true));
    expect(await screen.findByText(/in the background/)).toBeTruthy();
  });

  it("lets a manager apply a rule for every asset, but not change it", async () => {
    serveApi({ "/triage-rules": [RULE] }, MANAGER); // RULE has no asset: it applies everywhere
    renderPage(<TriageRules />);
    await screen.findByText(RULE.name);
    expect(screen.getByRole("button", { name: `Apply ${RULE.name} to existing findings` })).toBeTruthy();
    expect(screen.queryByRole("button", { name: `Edit ${RULE.name}` })).toBeNull();
    expect(screen.queryByRole("button", { name: `Delete ${RULE.name}` })).toBeNull();
  });

  it("offers no actions to analysts", async () => {
    serveApi({ "/triage-rules": [RULE] });
    renderPage(<TriageRules />);
    await screen.findByText(RULE.name);
    expect(screen.queryByRole("button", { name: /Apply .* to existing findings/ })).toBeNull();
  });
});
