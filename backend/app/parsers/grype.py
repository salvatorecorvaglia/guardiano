"""Anchore Grype JSON (`grype -o json`)."""

from typing import Any

from app.parsers.base import (
    NormalizedFinding,
    ParsedReport,
    ParseError,
    first_score,
    normalize_severity,
    purl_ecosystem,
    severity_from_score,
    to_float,
    truncate,
    unique_cwes,
)


def _score(vuln: dict[str, Any]) -> float | None:
    for entry in vuln.get("cvss") or []:
        score = to_float((entry.get("metrics") or {}).get("baseScore"))
        if score is not None:
            return score
    return None


def parse(data: dict[str, Any]) -> ParsedReport:
    matches = data.get("matches")
    if not isinstance(matches, list):
        raise ParseError("Grype report has no 'matches' array")
    descriptor = data.get("descriptor") or {}
    version = descriptor.get("version")

    findings: list[NormalizedFinding] = []
    for match in matches:
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        related = match.get("relatedVulnerabilities") or []
        vid = str(vuln.get("id") or "").strip()
        # Grype reports the GHSA and lists the CVE alongside it, or the other way round.
        cve = vid if vid.upper().startswith("CVE-") else None
        if not cve:
            cve = next(
                (str(r.get("id")) for r in related if str(r.get("id", "")).upper().startswith("CVE-")), None
            )
        score = first_score(_score(vuln), *(_score(r) for r in related))
        severity = normalize_severity(vuln.get("severity"), default=severity_from_score(score) or "medium")
        fix = vuln.get("fix") or {}
        purl = artifact.get("purl")
        locations = artifact.get("locations") or []
        description = (vuln.get("description") or "").strip()
        if not description and related:
            description = (related[0].get("description") or "").strip()
        refs = [{"url": u} for u in (vuln.get("urls") or [])[:10] if isinstance(u, str)]
        if source := vuln.get("dataSource"):
            refs.insert(0, {"url": source})

        findings.append(
            NormalizedFinding(
                type="sca",
                title=truncate(f"{cve or vid} in {artifact.get('name') or 'unknown package'}", 500) or vid,
                severity=severity,
                cvss_score=score,
                tool_name="Grype",
                description=description,
                cwe=unique_cwes(vuln.get("cwes") or []),
                rule_id=vid or None,
                file_path=(locations[0] or {}).get("path") if locations else None,
                package_name=artifact.get("name"),
                package_version=artifact.get("version"),
                ecosystem=purl_ecosystem(purl) or artifact.get("type"),
                purl=purl,
                cve_id=cve.upper() if cve else None,
                vuln_id=vid or None,
                fixed_version=next(iter(fix.get("versions") or []), None),
                references=refs,
            )
        )
    return ParsedReport("grype", "sca", "Grype", version, findings)
