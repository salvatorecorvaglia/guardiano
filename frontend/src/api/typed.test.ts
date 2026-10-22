import { afterEach, expect, it, vi } from "vitest";
import { download, request } from "./typed";

const transport = vi.hoisted(() => ({ api: vi.fn().mockResolvedValue({ id: 1 }), download: vi.fn() }));
vi.mock("./client", () => transport);
afterEach(() => vi.clearAllMocks());

it("encodes path identifiers once and forwards cancellation and typed filters", async () => {
  const controller = new AbortController();
  await request("get", "/api/v1/vulnerabilities/{vuln_id}", { params: { vuln_id: "GHSA/a b" }, signal: controller.signal, query: { page: 2 } });
  expect(transport.api).toHaveBeenCalledWith("/vulnerabilities/GHSA%2Fa%20b", expect.objectContaining({ method: "GET", signal: controller.signal, query: { page: 2 } }));
});
it("serializes multipart values and leaves absent fields out", async () => {
  const file = new Blob(["{}"], { type: "application/json" });
  await request("post", "/api/v1/scans", { form: { file, asset_id: 12, preview: false, branch: undefined } });
  const options = transport.api.mock.calls[0][1];
  expect(options.form.get("file")).toBeInstanceOf(Blob);
  expect(options.form.get("asset_id")).toBe("12");
  expect(options.form.get("preview")).toBe("false");
  expect(options.form.has("branch")).toBe(false);
  expect(options.body).toBeUndefined();
});
it("uses generated export routes and query parameters for downloads", async () => {
  await download("/api/v1/assets/{asset_id}/sbom", { params: { asset_id: 5 }, query: { format: "spdx" } }, "inventory.json");
  expect(transport.download).toHaveBeenCalledWith("/assets/5/sbom", { format: "spdx" }, "inventory.json");
});
