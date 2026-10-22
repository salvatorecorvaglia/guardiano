import type { RuleAction, RuleMatch } from "../api/types";

/** "path tests/*, CWE-89" — the conditions of a rule in one line. */
export function describeMatch(m: RuleMatch): string {
  const parts = [
    m.type && `type ${m.type}`,
    m.severity?.length && `severity ${m.severity.join("/")}`,
    m.tool && `tool ${m.tool}`,
    m.rule_id && `rule ${m.rule_id}`,
    m.cwe && (m.cwe.toUpperCase().startsWith("CWE-") ? m.cwe : `CWE-${m.cwe}`),
    m.package && `package ${m.package}`,
    m.path_glob && `path ${m.path_glob}`,
    m.title_contains && `title contains "${m.title_contains}"`,
    m.cve && m.cve.toUpperCase(),
    m.ecosystem && `ecosystem ${m.ecosystem}`,
    m.kev === true && "known exploited (KEV)",
    m.kev === false && "not in KEV",
    m.epss_min != null && `EPSS ≥ ${Math.round(m.epss_min * 100)}%`,
    m.asset_tags?.length && `asset tagged ${m.asset_tags.join(", ")}`,
    m.asset_criticality?.length && `asset criticality ${m.asset_criticality.join("/")}`,
  ].filter(Boolean);
  return parts.length ? parts.join(", ") : "nothing";
}

/** "mark false positive, tag noise" — what a rule does. */
export function describeAction(a: RuleAction): string {
  const parts = [
    a.status === "false_positive" && "mark false positive",
    a.severity && `set severity ${a.severity}`,
    a.tags?.length && `tag ${a.tags.join(", ")}`,
    a.assignee_id != null && "assign",
  ].filter(Boolean);
  return parts.length ? parts.join(", ") : "nothing";
}
