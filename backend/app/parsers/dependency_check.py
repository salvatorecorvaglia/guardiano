"""OWASP Dependency-Check JSON (`--format JSON`)."""

from typing import Any

from app.parsers.base import (
    NormalizedComponent,
    NormalizedFinding,
    ParsedReport,
    ParseError,
    first_score,
    normalize_severity,
    purl_ecosystem,
    severity_from_score,
    truncate,
    unique_cwes,
)


def _package(dependency: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    """Name, version and purl, from the package ids Dependency-Check attaches."""
    for package in dependency.get("packages") or []:
        pid = str(package.get("id") or "")
        if not pid.startswith("pkg:"):
            continue
        body = pid[4:].split("?", 1)[0]
        namespace, _, name = body.partition("/")[2].rpartition("/")
        name = name or body.partition("/")[2]
        version = None
        if "@" in name:
            name, version = name.rsplit("@", 1)
        if namespace:
            # Same shape as the CycloneDX parser, so the same package from two tools is one finding
            # and one component: maven uses group:artifact, everything else namespace/name.
            separator = ":" if purl_ecosystem(pid) == "maven" else "/"
            name = f"{namespace}{separator}{name}"
        return name, version, pid
    # No purl: fall back to the evidence Dependency-Check gathered from the file itself.
    return dependency.get("fileName"), None, None


def _score(vuln: dict[str, Any]) -> float | None:
    for key in ("cvssv3", "cvssv4", "cvssv2"):
        block = vuln.get(key) or {}
        score = first_score(block.get("baseScore"), block.get("score"))
        if score is not None:
            return score
    return None


def parse(data: dict[str, Any]) -> ParsedReport:
    dependencies = data.get("dependencies")
    if not isinstance(dependencies, list):
        raise ParseError("Dependency-Check report has no 'dependencies' array")
    version = (data.get("scanInfo") or {}).get("engineVersion")

    findings: list[NormalizedFinding] = []
    components: list[NormalizedComponent] = []
    for dependency in dependencies:
        name, package_version, purl = _package(dependency)
        if name and purl:
            components.append(
                NormalizedComponent(
                    name=truncate(name, 300),
                    version=truncate(package_version, 100),
                    ecosystem=purl_ecosystem(purl),
                    purl=truncate(purl, 1000),
                    licenses=[truncate(dependency["license"], 100)] if dependency.get("license") else [],
                )
            )
        for vuln in dependency.get("vulnerabilities") or []:
            vid = str(vuln.get("name") or "").strip()
            score = _score(vuln)
            severity = normalize_severity(
                vuln.get("severity"), default=severity_from_score(score) or "medium"
            )
            cwes = [c.get("id") if isinstance(c, dict) else c for c in vuln.get("cwes") or []]
            findings.append(
                NormalizedFinding(
                    type="sca",
                    title=truncate(f"{vid} in {name or dependency.get('fileName')}", 500) or vid,
                    severity=severity,
                    cvss_score=score,
                    tool_name="OWASP Dependency-Check",
                    description=(vuln.get("description") or "").strip(),
                    cwe=unique_cwes(cwes),
                    rule_id=vid or None,
                    file_path=dependency.get("filePath"),
                    package_name=name,
                    package_version=package_version,
                    ecosystem=purl_ecosystem(purl),
                    purl=purl,
                    cve_id=vid.upper() if vid.upper().startswith("CVE-") else None,
                    vuln_id=vid or None,
                    references=[
                        {"url": r["url"], "title": r.get("name")}
                        for r in (vuln.get("references") or [])[:10]
                        if isinstance(r, dict) and r.get("url")
                    ],
                )
            )
    return ParsedReport(
        "dependency-check",
        "sca",
        "OWASP Dependency-Check",
        version,
        findings,
        components=components,
        inventory_complete=True,
    )
