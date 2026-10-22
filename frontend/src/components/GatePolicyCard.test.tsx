import { cleanup, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { GatePolicy, User } from "../api/types";
import { ANALYST, renderPage, serveApi } from "../test/harness";
import GatePolicyCard from "./GatePolicyCard";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const ADMIN = { ...ANALYST, id: 1, role: "admin" } as User;

function policy(conditions: Partial<GatePolicy["conditions"]>): GatePolicy {
  return {
    id: 7,
    asset: null,
    enabled: true,
    conditions,
    created_at: "2026-09-01T00:00:00Z",
    updated_at: "2026-09-01T00:00:00Z",
  } as GatePolicy;
}

describe("GatePolicyCard", () => {
  it("keeps every condition it loaded when saving, EPSS as a fraction", async () => {
    // Saving sends the whole policy, so a condition the form did not know about would be erased.
    const calls = serveApi(
      {
        "/gate-policies": [
          policy({
            max_new: { critical: 0 },
            max_open_epss: 0.25,
            max_new_cvss: 8.9,
            fail_on_new_secrets: true,
            fail_on_denied_license: true,
          }),
        ],
        "PUT /gate-policies": policy({}),
      },
      ADMIN,
    );
    renderPage(<GatePolicyCard assetId={null} />);

    const epss = (await screen.findByRole("spinbutton", { name: "Open finding with EPSS above" })) as HTMLInputElement;
    expect(epss.value).toBe("25");
    expect((screen.getByRole("spinbutton", { name: "New finding with CVSS above" }) as HTMLInputElement).value).toBe("8.9");
    expect((screen.getByRole("checkbox", { name: /new secret/ }) as HTMLInputElement).checked).toBe(true);
    expect((screen.getByRole("checkbox", { name: /denied licence/ }) as HTMLInputElement).checked).toBe(true);

    // Change something unrelated, then save.
    await userEvent.click(screen.getByRole("checkbox", { name: /past their SLA/ }));
    await userEvent.click(screen.getByRole("button", { name: "Save gate" }));

    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    const sent = calls.find((c) => c.method === "PUT")!.body as { conditions: Record<string, unknown> };
    expect(sent.conditions).toMatchObject({
      max_new: { critical: 0 },
      max_open_epss: 0.25,
      max_new_cvss: 8.9,
      fail_on_new_secrets: true,
      fail_on_denied_license: true,
      fail_on_overdue: true,
    });
  });

  it("sends no score limit when the field is left empty", async () => {
    const calls = serveApi({ "/gate-policies": [], "PUT /gate-policies": policy({}) }, ADMIN);
    renderPage(<GatePolicyCard assetId={null} />);
    await userEvent.click(await screen.findByRole("checkbox", { name: /new secret/ }));
    await userEvent.click(screen.getByRole("button", { name: "Create gate" }));

    await waitFor(() => expect(calls.some((c) => c.method === "PUT")).toBe(true));
    const sent = calls.find((c) => c.method === "PUT")!.body as { conditions: Record<string, unknown> };
    expect(sent.conditions.max_open_epss).toBeNull();
    expect(sent.conditions.max_new_cvss).toBeNull();
    expect(sent.conditions.fail_on_new_secrets).toBe(true);
  });
});
