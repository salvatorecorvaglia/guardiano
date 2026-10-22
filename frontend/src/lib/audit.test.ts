import { describe, expect, it } from "vitest";
import { describeChanges } from "./audit";

describe("describeChanges", () => {
  it("renders field diffs as from → to", () => {
    expect(describeChanges({ role: { from: "viewer", to: "analyst" }, tags: { from: [], to: ["pci", "gdpr"] } })).toEqual([
      "role: viewer → analyst",
      "tags: none → pci, gdpr",
    ]);
  });

  it("renders plain values, including two-item lists, as values", () => {
    expect(describeChanges({ scopes: ["ingest", "read"], expires_at: null, password: "changed" })).toEqual([
      "scopes: ingest, read",
      "expires_at: –",
      "password: changed",
    ]);
  });
});
