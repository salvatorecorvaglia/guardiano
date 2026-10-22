import { describe, expect, it, vi } from "vitest";
import { compact, endOfLocalDay, findingLocation, relTime, toLocalDateInput } from "./format";

// Run under several TZ values (e.g. TZ=Pacific/Auckland pnpm test) to cover both sides of UTC.
describe("local due dates", () => {
  it("round-trips a picked day through the stored timestamp", () => {
    for (const day of ["2027-01-31", "2026-03-29", "2026-10-25", "2028-02-29"]) {
      expect(toLocalDateInput(endOfLocalDay(day))).toBe(day);
    }
  });

  it("ends the day at 23:59:59 local time", () => {
    const d = new Date(endOfLocalDay("2027-01-31"));
    expect([d.getDate(), d.getHours(), d.getMinutes(), d.getSeconds()]).toEqual([31, 23, 59, 59]);
  });

  it("maps empty values to an empty input", () => {
    expect(toLocalDateInput(null)).toBe("");
  });
});

describe("findingLocation", () => {
  const base = { file_path: null, line_start: null, package_name: null, package_version: null };
  it("is file:line for code, and package@version for a dependency", () => {
    expect(findingLocation({ ...base, type: "sast", file_path: "app/db.py", line_start: 42 })).toBe("app/db.py:42");
    expect(findingLocation({ ...base, type: "sast", file_path: "app/db.py" })).toBe("app/db.py");
    expect(findingLocation({ ...base, type: "sca", package_name: "lodash", package_version: "4.17.15" })).toBe("lodash@4.17.15");
  });
  it("is the resource for infrastructure, and the request for a running application", () => {
    const iac = { ...base, type: "iac" as const, file_path: "infra/s3.tf", line_start: 3, resource: "aws_s3_bucket.logs" };
    expect(findingLocation(iac)).toBe("aws_s3_bucket.logs · infra/s3.tf:3");
    expect(findingLocation({ ...iac, file_path: null })).toBe("aws_s3_bucket.logs");
    const dast = { ...base, type: "dast" as const, url: "https://x.test/api?id=1", http_method: "GET", parameter: "id" };
    expect(findingLocation(dast)).toBe("GET https://x.test/api?id=1 (id)");
    expect(findingLocation({ ...dast, http_method: null, parameter: null })).toBe("https://x.test/api?id=1");
  });
  it("says what it does not know rather than inventing it", () => {
    expect(findingLocation({ ...base, type: "sca", package_name: "lodash" })).toBe("lodash@?");
    expect(findingLocation({ ...base, type: "sast" })).toBe("");
    expect(findingLocation({ ...base, type: "sca" })).toBe("");
  });
});

describe("relTime", () => {
  it("picks the largest whole unit, and says never for nothing", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-09-21T12:00:00Z"));
    try {
      expect(relTime(null)).toBe("never");
      expect(relTime("2026-09-21T11:30:00Z")).toMatch(/30 minutes ago/);
      expect(relTime("2026-09-19T12:00:00Z")).toMatch(/2 days ago/);
      expect(relTime("2026-09-21T11:59:50Z")).toMatch(/now/);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("compact", () => {
  it("abbreviates only from a thousand", () => {
    expect(compact(999)).toBe(new Intl.NumberFormat().format(999));
    expect(compact(1500)).toMatch(/1\.5\s?K/i);
  });
});
