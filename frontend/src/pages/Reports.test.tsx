import { cleanup, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderPage, serveApi } from "../test/harness";
import Reports from "./Reports";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

// Only what these tests read. The report itself is left unserved: they are about which requests the
// filters produce, and the page shows its error box for the rest.
function serve() {
  return serveApi({ "/assets/options": [{ id: 3, name: "payments-api" }], "/analytics/top": [] });
}

describe("Reports", () => {
  it("takes its filters from the URL, so a report can be bookmarked or shared", async () => {
    const calls = serve();
    renderPage(<Reports />, { route: "/reports?asset=3&days=180", path: "/reports" });
    await waitFor(() => expect(calls.some((c) => c.path === "/analytics/compliance")).toBe(true));
    const compliance = calls.find((c) => c.path === "/analytics/compliance")!.url.searchParams;
    expect(compliance.get("asset_id")).toBe("3");
    expect(compliance.get("days")).toBe("180");
  });

  it("writes a changed filter back to the URL", async () => {
    serve();
    renderPage(<Reports />, { route: "/reports", path: "/reports" });
    const [asset, window] = await screen.findAllByRole("combobox");
    await screen.findByRole("option", { name: "payments-api" });
    await userEvent.selectOptions(asset, "3");
    await userEvent.selectOptions(window, "365");
    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("/reports?asset=3&days=365"));
  });

  it("ignores a window the page does not offer", async () => {
    const calls = serve();
    renderPage(<Reports />, { route: "/reports?days=7", path: "/reports" });
    await waitFor(() => expect(calls.some((c) => c.path === "/analytics/compliance")).toBe(true));
    expect(calls.find((c) => c.path === "/analytics/compliance")!.url.searchParams.get("days")).toBe("90");
  });
});
