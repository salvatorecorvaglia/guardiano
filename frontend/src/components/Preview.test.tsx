import { cleanup, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import type { Scan } from "../api/types";
import ScanDetail from "../pages/ScanDetail";
import { renderPage, serveApi } from "../test/harness";
import UploadDialog from "./UploadDialog";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

const PREVIEW: Scan = {
  id: 1, asset: { id: 1, name: "svc" }, scan_type: "sast", tool_name: "Semgrep", tool_version: null,
  format: "guardiano", branch: "pr-1", commit_sha: null, source: "preview", file_name: "report.json",
  uploaded_by: null, total_count: 1, new_count: 1, duplicate_count: 0, reopened_count: 1,
  auto_resolved_count: 0, gate: null, created_at: "2026-09-01T00:00:00Z",
  preview: { branch: "pr-1", default_branch: "main", would_resolve: 2, truncated: false,
    counts: { total: 1, new: 1, known: 0, new_by_severity: { low: 1 } },
    new: [{ title: "SQL injection", type: "sast", severity: "low", scanner_severity: "high", cvss_score: 8.5 }] },
};

it("shows projected changes and labels the scanner severity separately", async () => {
  serveApi({ "/scans/1": PREVIEW });
  renderPage(<ScanDetail />, { route: "/scans/1", path: "/scans/:id" });
  expect(await screen.findByText(/Scanner severity: high/)).toHaveProperty("textContent", "Scanner severity: high (CVSS 8.5) · adjusted by triage rules");
  expect(screen.getByText("Would resolve").parentElement?.textContent).toContain("2");
  expect(screen.getByText("Would reopen").parentElement?.textContent).toContain("1");
  expect(screen.queryByText("Auto-resolved")).toBeNull();
});

it("shows an unknown projection for older preview records", async () => {
  serveApi({ "/scans/1": { ...PREVIEW, preview: { ...PREVIEW.preview, would_resolve: null } } });
  renderPage(<ScanDetail />, { route: "/scans/1", path: "/scans/:id" });
  expect((await screen.findByText("Would resolve")).parentElement?.textContent).toContain("–");
});

it("allows missing-finding evaluation during preview and reports hypothetical counts", async () => {
  const calls = serveApi({ "/assets/options/search": { items: [{ id: 1, name: "svc" }], selected: { id: 1, name: "svc" }, total: 1, page: 1, page_size: 50 },
    "/meta": { max_upload_mb: 50, formats: ["guardiano"] }, "POST /scans": PREVIEW });
  renderPage(<UploadDialog open onClose={() => {}} defaultAssetId={1} />);
  await screen.findByRole("option", { name: "svc" });
  await userEvent.upload(document.querySelector<HTMLInputElement>('input[type="file"]')!,
    new File(['{"findings":[]}'], "report.json", { type: "application/json" }));
  await userEvent.click(screen.getByLabelText(/Preview only/));
  const closeMissing = screen.getByLabelText(/Resolve findings no longer reported/);
  expect(closeMissing).toHaveProperty("disabled", false);
  await userEvent.click(closeMissing);
  await userEvent.click(screen.getByRole("button", { name: /^Import$/ }));
  await screen.findByRole("dialog", { name: "Scan previewed" });
  const body = calls.find((call) => call.path === "/scans" && call.method === "POST")!.body as FormData;
  expect(body.get("preview")).toBe("true");
  expect(body.get("close_missing")).toBe("true");
  expect(screen.getByText("Would resolve").parentElement?.textContent).toContain("2");
  expect(screen.queryByText("Auto-resolved")).toBeNull();
});
