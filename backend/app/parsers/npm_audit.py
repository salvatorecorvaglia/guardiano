"""npm audit JSON (`npm audit --json`, npm 7 and later)."""

from typing import Any

from app.parsers.base import (
    NormalizedFinding,
    ParsedReport,
    ParseError,
    normalize_severity,
    to_float,
    truncate,
    unique_cwes,
)


def parse(data: dict[str, Any]) -> ParsedReport:
    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(vulnerabilities, dict):
        raise ParseError("npm audit report has no 'vulnerabilities' object (npm 7 or later required)")

    findings: list[NormalizedFinding] = []
    for package_name, entry in vulnerabilities.items():
        if not isinstance(entry, dict):
            continue
        severity = normalize_severity(entry.get("severity"))
        fix = entry.get("fixAvailable")
        fixed_version = fix.get("version") if isinstance(fix, dict) else None
        installed = entry.get("range")
        # "via" holds the advisories, or the names of packages that pull this one in.
        advisories = [v for v in entry.get("via") or [] if isinstance(v, dict)]
        if not advisories:
            # Only transitively affected: one finding for the package itself.
            advisories = [
                {"title": f"Vulnerable dependency {package_name}", "severity": entry.get("severity")}
            ]
        for advisory in advisories:
            cwes = advisory.get("cwe") or []
            url = advisory.get("url")
            title = advisory.get("title") or f"Advisory for {package_name}"
            findings.append(
                NormalizedFinding(
                    type="sca",
                    title=truncate(title, 500),
                    severity=normalize_severity(advisory.get("severity"), default=severity),
                    cvss_score=to_float((advisory.get("cvss") or {}).get("score")),
                    tool_name="npm audit",
                    description=f"Affected range: {advisory.get('range') or installed or 'unknown'}",
                    remediation=(
                        f"Upgrade {package_name} to {fixed_version}."
                        if fixed_version
                        else "No fixed version is available yet."
                    ),
                    cwe=unique_cwes(cwes if isinstance(cwes, list) else [cwes]),
                    rule_id=str(advisory.get("source")) if advisory.get("source") else None,
                    package_name=advisory.get("name") or package_name,
                    package_version=installed,
                    ecosystem="npm",
                    purl=f"pkg:npm/{advisory.get('name') or package_name}",
                    vuln_id=url.rsplit("/", 1)[-1] if isinstance(url, str) and "GHSA" in url else None,
                    fixed_version=fixed_version,
                    references=[{"url": url}] if url else [],
                )
            )
    return ParsedReport("npm-audit", "sca", "npm audit", None, findings)
