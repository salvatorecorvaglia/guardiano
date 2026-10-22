"""Guardiano native JSON format - a simple, tool-agnostic schema for any scanner.

The parser below defines the complete accepted schema.
"""

from typing import Any

from app.parsers.base import (
    NormalizedFinding,
    ParsedReport,
    ParseError,
    normalize_severity,
    severity_from_score,
    to_float,
    to_int,
    truncate,
    unique_cwes,
)

_TYPES = ("sast", "sca", "iac", "dast")


def parse(data: dict[str, Any]) -> ParsedReport:
    items = data.get("findings")
    if not isinstance(items, list):
        raise ParseError("Guardiano JSON requires a 'findings' array")
    tool = data.get("tool") or {}
    if isinstance(tool, str):
        tool = {"name": tool}
    tool_name = str(tool.get("name") or "custom")
    scan_type = str(data.get("scan_type") or data.get("type") or "").lower()

    findings: list[NormalizedFinding] = []
    for i, f in enumerate(items):
        if not isinstance(f, dict):
            raise ParseError(f"findings[{i}] must be an object")
        ftype = str(f.get("type") or scan_type or ("sca" if f.get("package_name") else "sast")).lower()
        if ftype not in _TYPES:
            raise ParseError(f"findings[{i}].type must be one of: {', '.join(_TYPES)}")
        score = to_float(f.get("cvss_score"))
        severity = (
            normalize_severity(f["severity"], default="medium")
            if f.get("severity")
            else (severity_from_score(score) or "medium")
        )
        cwe = f.get("cwe") or []
        if not isinstance(cwe, list):
            cwe = [cwe]
        cve = f.get("cve_id") or f.get("cve")
        title = f.get("title") or cve or f.get("rule_id")
        if not title:
            raise ParseError(f"findings[{i}] requires 'title' (or cve_id / rule_id)")
        refs = f.get("references") or []
        if not isinstance(refs, list):  # one reference given as a bare string, not 17 one-letter ones
            refs = [refs]
        findings.append(
            NormalizedFinding(
                type=ftype,
                title=truncate(str(title), 500) or "Finding",
                severity=severity,
                cvss_score=score,
                tool_name=str(f.get("tool") or tool_name),
                description=str(f.get("description") or ""),
                remediation=str(f.get("remediation") or ""),
                cwe=unique_cwes(cwe),
                rule_id=f.get("rule_id"),
                file_path=f.get("file_path"),
                line_start=to_int(f.get("line_start") or f.get("line")),
                line_end=to_int(f.get("line_end")),
                snippet=truncate(f.get("snippet"), 4000),
                package_name=f.get("package_name"),
                package_version=f.get("package_version"),
                ecosystem=f.get("ecosystem"),
                purl=f.get("purl"),
                cve_id=str(cve).upper() if cve else None,
                vuln_id=f.get("vuln_id"),
                fixed_version=f.get("fixed_version"),
                references=[r if isinstance(r, dict) else {"url": str(r)} for r in refs],
                resource=f.get("resource"),
                url=f.get("url"),
                http_method=f.get("http_method") or f.get("method"),
                parameter=f.get("parameter") or f.get("param"),
            )
        )
    if not scan_type:
        scan_type = findings[0].type if findings else "sast"
    return ParsedReport("guardiano", scan_type, tool_name, tool.get("version"), findings)
