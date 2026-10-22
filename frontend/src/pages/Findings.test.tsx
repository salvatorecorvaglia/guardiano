import { cleanup, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { finding, page, renderPage, serveApi } from "../test/harness";
import Findings from "./Findings";

// relTime runs once per rendered row, so counting its calls counts row renders.
const rows = vi.hoisted(() => ({ rendered: 0 }));
vi.mock("../lib/format", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../lib/format")>();
  return {
    ...actual,
    relTime: (...args: Parameters<typeof actual.relTime>) => {
      rows.rendered++;
      return actual.relTime(...args);
    },
  };
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function serve(items = [finding({ id: 1, tags: ["pci"] }), finding({ id: 2 }), finding({ id: 3 })]) {
  return serveApi({
    "/findings": page(items),
    "/assets/options": [],
    "/users/directory": [],
    "/views": [],
    "/findings/tags": [],
    "/meta": { version: "t", sla_days: {}, local_login: true, oidc_enabled: false, email_enabled: false },
    "POST /findings/bulk": { updated: 1 },
  });
}

describe("Findings", () => {
  it("lists findings and selects them one at a time", async () => {
    serve();
    renderPage(<Findings />, { route: "/findings", path: "/findings" });
    await screen.findByText("Finding 1");

    await userEvent.click(screen.getByRole("checkbox", { name: "Select finding 2" }));
    expect(screen.getByText("1 selected")).toBeTruthy();
    expect((screen.getByRole("checkbox", { name: "Select finding 2" }) as HTMLInputElement).checked).toBe(true);
    expect((screen.getByRole("checkbox", { name: "Select finding 1" }) as HTMLInputElement).checked).toBe(false);

    await userEvent.click(screen.getByRole("checkbox", { name: "Select finding 3" }));
    expect(screen.getByText("2 selected")).toBeTruthy();
    await userEvent.click(screen.getByRole("checkbox", { name: "Select finding 2" }));
    expect(screen.getByText("1 selected")).toBeTruthy();
  });

  it("sends the selected findings in a bulk action", async () => {
    const calls = serve();
    renderPage(<Findings />, { route: "/findings", path: "/findings" });
    await screen.findByText("Finding 1");
    await userEvent.click(screen.getByRole("checkbox", { name: "Select finding 1" }));
    await userEvent.click(screen.getByRole("checkbox", { name: "Select finding 3" }));
    await userEvent.type(screen.getByRole("textbox", { name: "Add tag to selected" }), "reviewed{Enter}");

    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === "/findings/bulk")).toBe(true));
    const bulk = calls.find((c) => c.path === "/findings/bulk")!.body as { ids: number[]; add_tags: string[] };
    expect(bulk.ids.sort()).toEqual([1, 3]);
    expect(bulk.add_tags).toEqual(["reviewed"]);
  });

  it("filters by a tag clicked in a row, once", async () => {
    serve();
    renderPage(<Findings />, { route: "/findings", path: "/findings" });
    const row = (await screen.findByText("Finding 1")).closest("tr")!;
    await userEvent.click(within(row).getByRole("button", { name: "pci" }));
    await waitFor(() => expect(screen.getByTestId("location").textContent).toContain("tag=pci"));
    await userEvent.click(within(row).getByRole("button", { name: "pci" }));
    expect(screen.getByTestId("location").textContent!.match(/tag=pci/g)).toHaveLength(1);
  });

  it("shows each finding's priority and sorts by it, highest first", async () => {
    const calls = serve([finding({ id: 1, priority: 20 }), finding({ id: 2, priority: 2.5 })]);
    renderPage(<Findings />, { route: "/findings", path: "/findings" });
    const row = (await screen.findByText("Finding 1")).closest("tr")!;
    expect(within(row).getByText("20.0")).toBeTruthy();

    await userEvent.click(screen.getByRole("button", { name: "Priority" }));
    await waitFor(() => expect(screen.getByTestId("location").textContent).toContain("sort=-priority"));
    await waitFor(() =>
      expect(calls.some((c) => c.path === "/findings" && c.url.searchParams.get("sort") === "-priority")).toBe(true),
    );
  });

  it("applies a bulk action to every finding the filters match", async () => {
    const items = [finding({ id: 1 }), finding({ id: 2 })];
    const calls = serveApi({
      "/findings": { ...page(items), total: 120 },
      "/assets/options": [],
      "/users/directory": [],
      "/views": [],
      "/findings/tags": [],
      "/meta": { version: "t", sla_days: {}, local_login: true, oidc_enabled: false, email_enabled: false },
      "POST /findings/bulk/matching": { updated: 120 },
    });
    renderPage(<Findings />, { route: "/findings?severity=high", path: "/findings" });
    await screen.findByText("Finding 1");

    await userEvent.click(screen.getByRole("checkbox", { name: "Select all on page" }));
    await userEvent.click(screen.getByRole("button", { name: "Select all 120 matching" }));
    expect(screen.getByText("All 120 matching selected")).toBeTruthy();
    await userEvent.type(screen.getByRole("textbox", { name: "Add tag to selected" }), "sprint-12{Enter}");

    await waitFor(() => expect(calls.some((c) => c.path === "/findings/bulk/matching")).toBe(true));
    const call = calls.find((c) => c.path === "/findings/bulk/matching")!;
    expect(call.url.searchParams.getAll("severity")).toEqual(["high"]);
    expect(call.body).toEqual({ add_tags: ["sprint-12"] });
  });

  it("goes back to the ticked rows when one is unticked after selecting all matching", async () => {
    const items = [finding({ id: 1 }), finding({ id: 2 })];
    const calls = serveApi({
      "/findings": { ...page(items), total: 120 },
      "/assets/options": [],
      "/users/directory": [],
      "/views": [],
      "/findings/tags": [],
      "/meta": { version: "t", sla_days: {}, local_login: true, oidc_enabled: false, email_enabled: false },
      "POST /findings/bulk": { updated: 1 },
    });
    renderPage(<Findings />, { route: "/findings", path: "/findings" });
    await screen.findByText("Finding 1");
    await userEvent.click(screen.getByRole("checkbox", { name: "Select all on page" }));
    await userEvent.click(screen.getByRole("button", { name: "Select all 120 matching" }));
    await userEvent.click(screen.getByRole("checkbox", { name: "Select finding 2" }));
    expect(screen.getByText("1 selected")).toBeTruthy();

    await userEvent.type(screen.getByRole("textbox", { name: "Add tag to selected" }), "x");
    await userEvent.click(screen.getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(calls.some((c) => c.path === "/findings/bulk")).toBe(true));
    expect(calls.find((c) => c.path === "/findings/bulk")!.body).toEqual({ ids: [1], remove_tags: ["x"] });
    expect(calls.some((c) => c.path === "/findings/bulk/matching")).toBe(false);
  });

  it("hides a column the viewer turns off, and remembers it", async () => {
    localStorage.removeItem("guardiano.findings.hidden-columns");
    serve();
    renderPage(<Findings />, { route: "/findings", path: "/findings" });
    await screen.findByText("Finding 1");
    expect(screen.getByRole("columnheader", { name: "Tools" })).toBeTruthy();

    await userEvent.click(screen.getByText("Columns"));
    await userEvent.click(screen.getByRole("checkbox", { name: "Tools" }));
    expect(screen.queryByRole("columnheader", { name: "Tools" })).toBeNull();
    expect(screen.queryByText("Semgrep")).toBeNull(); // the cells go with the header
    expect(JSON.parse(localStorage.getItem("guardiano.findings.hidden-columns")!)).toEqual(["tools"]);
    localStorage.removeItem("guardiano.findings.hidden-columns");
  });

  it("sends a first-seen range as whole local days, and the ticket filter", async () => {
    const calls = serve();
    renderPage(<Findings />, { route: "/findings?first_seen_from=2026-09-01&first_seen_to=2026-09-30&ticket_done=true", path: "/findings" });
    await screen.findByText("Finding 1");
    const url = calls.find((c) => c.path === "/findings")!.url;
    expect(url.searchParams.get("first_seen_from")).toBe(new Date(2026, 8, 1).toISOString());
    expect(url.searchParams.get("first_seen_to")).toBe(new Date(2026, 8, 30, 23, 59, 59).toISOString());
    expect(url.searchParams.get("ticket_done")).toBe("true");
    expect(screen.getByRole("button", { name: "Ticket closed" }).getAttribute("aria-pressed")).toBe("true");
  });

  it("opens a finding when its row is clicked", async () => {
    serve();
    renderPage(<Findings />, { route: "/findings", path: "/findings" });
    const row = (await screen.findByText("Finding 2")).closest("tr")!;
    await userEvent.click(within(row).getByText("payments-api"));
    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("/findings/2"));
  });

  it("re-renders only the row whose checkbox changed, and no row while typing a search", async () => {
    serve();
    renderPage(<Findings />, { route: "/findings", path: "/findings" });
    await screen.findByText("Finding 1");

    rows.rendered = 0;
    await userEvent.click(screen.getByRole("checkbox", { name: "Select finding 2" }));
    expect(rows.rendered).toBe(1); // was 3: every row, for one checkbox

    rows.rendered = 0;
    await userEvent.type(screen.getByLabelText("Search findings"), "sql");
    expect(rows.rendered).toBe(0); // was 3 per keystroke
  });
});
