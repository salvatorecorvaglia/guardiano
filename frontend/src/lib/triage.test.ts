import { describe, expect, it } from "vitest";
import { describeAction, describeMatch } from "./triage";

describe("rule summaries", () => {
  it("lists every condition", () => {
    expect(describeMatch({ path_glob: "tests/*", cwe: "89", severity: ["high"], type: "sast" })).toBe(
      "type sast, severity high, CWE-89, path tests/*",
    );
    expect(describeMatch({ cwe: "CWE-79" })).toBe("CWE-79");
    expect(
      describeMatch({ cve: "cve-2021-44228", ecosystem: "maven", kev: true, epss_min: 0.5, asset_tags: ["pci"], asset_criticality: ["high", "critical"] }),
    ).toBe("CVE-2021-44228, ecosystem maven, known exploited (KEV), EPSS ≥ 50%, asset tagged pci, asset criticality high/critical");
    expect(describeMatch({ kev: false })).toBe("not in KEV");
  });

  it("says so when a rule would do nothing", () => {
    expect(describeMatch({})).toBe("nothing");
    expect(describeAction({})).toBe("nothing");
  });

  it("lists every effect", () => {
    expect(describeAction({ status: "false_positive", tags: ["noise"], severity: "low", assignee_id: 3 })).toBe(
      "mark false positive, set severity low, tag noise, assign",
    );
  });
});
