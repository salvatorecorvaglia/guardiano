import { QueryClient } from "@tanstack/react-query";
import { describe, expect, it } from "vitest";
import { analyticsKeys, invalidateAfterTriage } from "./queries";

function seeded(keys: (readonly unknown[])[]) {
  const qc = new QueryClient();
  for (const key of keys) qc.setQueryData(key, { seeded: true });
  return qc;
}

const stale = (qc: QueryClient, key: readonly unknown[]) => qc.getQueryState(key)?.isInvalidated;

describe("invalidateAfterTriage", () => {
  it("reaches every analytics figure, including the ones Reports and the OWASP panel show", () => {
    const keys = [
      analyticsKeys.summary(3),
      analyticsKeys.trends(90),
      analyticsKeys.top("assets", 10),
      analyticsKeys.compliance(3, 90),
      analyticsKeys.compliance(),
    ];
    const qc = seeded(keys);
    invalidateAfterTriage(qc);
    for (const key of keys) expect(stale(qc, key), JSON.stringify(key)).toBe(true);
  });

  it("refreshes the asset list, whose open counts come from findings", () => {
    const qc = seeded([["assets", { page: 1 }]]);
    invalidateAfterTriage(qc);
    expect(stale(qc, ["assets", { page: 1 }])).toBe(true);
  });

  it("leaves alone what triage cannot change, and the detail the caller has just filled", () => {
    const qc = seeded([["meta"], ["finding", "7"], ["finding", "8"]]);
    invalidateAfterTriage(qc, { fresh: ["finding", "7"] });
    expect(stale(qc, ["meta"])).toBe(false);
    expect(stale(qc, ["finding", "7"])).toBe(false);
    expect(stale(qc, ["finding", "8"])).toBe(true);
  });
});

describe("analyticsKeys", () => {
  it("gives one key to one request whether the asset id came from a URL or a route", () => {
    expect(analyticsKeys.summary("3")).toEqual(analyticsKeys.summary(3));
    expect(analyticsKeys.summary(undefined)).toEqual(analyticsKeys.summary(null));
  });
});
