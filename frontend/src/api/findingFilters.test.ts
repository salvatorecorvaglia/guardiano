import { expect, it } from "vitest";
import { findingFilters } from "./findingFilters";

it("converts URL filters to the generated API types without losing false values", () => {
  const query = findingFilters({ asset_id: ["12", "34"], severity: ["high"], status: ["open"], scan_id: "9", epss_min: "0.3", overdue: "false", kev: "true", tag: ["pci"], first_seen_from: "2026-10-01T00:00:00Z" });
  expect(query).toMatchObject({ asset_id: [12, 34], severity: ["high"], status: ["open"], scan_id: 9, epss_min: 0.3, overdue: false, kev: true, tag: ["pci"] });
  expect(findingFilters({ scan_id: "", overdue: "" }).scan_id).toBeUndefined();
});
it("reports malformed URL filters as actionable query errors", () => {
  for (const raw of [{ scan_id: "invalid" }, { overdue: "sometimes" }, { asset_id: ["bad"] }, { severity: ["urgent"] }, { status: ["done"] }]) {
    expect(() => findingFilters(raw)).toThrow();
  }
});
