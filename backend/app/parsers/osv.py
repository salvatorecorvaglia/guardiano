"""OSV-Scanner JSON (`osv-scanner --format json`)."""

from typing import Any

from app.parsers.base import (
    NormalizedComponent,
    NormalizedFinding,
    ParsedReport,
    ParseError,
    normalize_severity,
    severity_from_score,
    to_float,
    truncate,
    unique_cwes,
)

# OSV ecosystems are capitalised ("PyPI", "npm", "Go"); purls are not.
_SEVERITY_KEYS = ("severity", "cvss_severity")


def _fixed_version(vuln: dict[str, Any], package: dict[str, Any]) -> str | None:
    fixes = set()
    affected_packages = vuln.get("affected") or []
    for affected in affected_packages:
        target = affected.get("package") or {}
        # Older scanner exports omit package only for a single affected entry.
        implicit_package = not target and len(affected_packages) == 1
        if not implicit_package and (target.get("name"), target.get("ecosystem")) != (
            package.get("name"),
            package.get("ecosystem"),
        ):
            continue
        for ranges in affected.get("ranges") or []:
            for event in ranges.get("events") or []:
                if event.get("fixed"):
                    fixes.add(str(event["fixed"]))
    return next(iter(fixes)) if len(fixes) == 1 else None


def _severity(vuln: dict[str, Any], group_score: float | None) -> tuple[str, float | None]:
    specific = vuln.get("database_specific") or {}
    for key in _SEVERITY_KEYS:
        if specific.get(key):
            return normalize_severity(specific[key]), group_score
    return severity_from_score(group_score) or "medium", group_score


def parse(data: dict[str, Any]) -> ParsedReport:
    results = data.get("results")
    if not isinstance(results, list):
        raise ParseError("OSV-Scanner report has no 'results' array")

    findings: list[NormalizedFinding] = []
    components: list[NormalizedComponent] = []
    for result in results:
        source = (result.get("source") or {}).get("path")
        for entry in result.get("packages") or []:
            package = entry.get("package") or {}
            name, version = package.get("name"), package.get("version")
            ecosystem = str(package.get("ecosystem") or "").lower() or None
            if name:
                components.append(
                    NormalizedComponent(
                        name=truncate(name, 300),
                        version=truncate(version, 100),
                        ecosystem=ecosystem,
                        purl=truncate(package.get("purl"), 1000),
                    )
                )
            # groups[].max_severity carries the CVSS score for the ids it covers.
            scores = {}
            for group in entry.get("groups") or []:
                score = to_float(group.get("max_severity"))
                for vid in group.get("ids") or []:
                    scores[vid] = score

            for vuln in entry.get("vulnerabilities") or []:
                vid = str(vuln.get("id") or "").strip()
                aliases = [str(a) for a in vuln.get("aliases") or []]
                cve = next((a for a in [vid, *aliases] if a.upper().startswith("CVE-")), None)
                severity, score = _severity(vuln, scores.get(vid))
                summary = (vuln.get("summary") or "").strip()
                details = (vuln.get("details") or "").strip()
                findings.append(
                    NormalizedFinding(
                        type="sca",
                        title=truncate(summary or f"{cve or vid} in {name}", 500) or vid,
                        severity=severity,
                        cvss_score=score,
                        tool_name="OSV-Scanner",
                        description=details or summary,
                        cwe=unique_cwes((vuln.get("database_specific") or {}).get("cwe_ids") or []),
                        rule_id=vid or None,
                        file_path=source,
                        package_name=name,
                        package_version=version,
                        ecosystem=ecosystem,
                        purl=package.get("purl"),
                        cve_id=cve.upper() if cve else None,
                        vuln_id=vid or None,
                        fixed_version=_fixed_version(vuln, package),
                        references=[
                            {"url": r["url"]}
                            for r in (vuln.get("references") or [])[:10]
                            if isinstance(r, dict) and r.get("url")
                        ],
                    )
                )
    return ParsedReport(
        "osv", "sca", "OSV-Scanner", None, findings, components=components, inventory_complete=False
    )
