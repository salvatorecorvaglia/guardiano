"""Nuclei results: `-jsonl` output (one JSON object per line) or `-json-export` (a JSON array).

Each result is one template matching one URL. Templates that name a CVE carry it, so KEV and EPSS
apply to them as they do to dependency findings.
"""

from typing import Any

from app.parsers.base import (
    NormalizedFinding,
    ParsedReport,
    ParseError,
    first_score,
    normalize_severity,
    truncate,
    unique_cwes,
)


def _method(result: dict[str, Any]) -> str | None:
    request = result.get("request")
    if isinstance(request, str) and " " in request:
        verb = request.split(" ", 1)[0].strip().upper()
        return verb if verb.isalpha() and len(verb) <= 10 else None
    return None


def parse(data: Any) -> ParsedReport:
    if isinstance(data, dict):
        data = [data]  # a single result
    if not isinstance(data, list):
        raise ParseError("Nuclei results are JSON Lines or a JSON array of results")
    findings: list[NormalizedFinding] = []
    for result in data:
        if not isinstance(result, dict):
            raise ParseError("Nuclei results must be objects")
        info = result.get("info") or {}
        cls = info.get("classification") or {}
        cves = [str(c).upper() for c in cls.get("cve-id") or [] if c]
        candidates = (result.get("matched-at"), result.get("url"), result.get("host"))
        where = next((v for v in candidates if isinstance(v, str) and v), None)
        if where and "://" not in where:  # a network template matches "host:port", not a URL
            where = f"tcp://{where}"
        refs = info.get("reference") or []
        refs = [refs] if isinstance(refs, str) else refs
        findings.append(
            NormalizedFinding(
                type="dast",
                title=truncate(info.get("name") or result.get("template-id") or "Nuclei match", 500)
                or "Nuclei match",
                severity=normalize_severity(info.get("severity")),
                cvss_score=first_score(cls.get("cvss-score")),
                tool_name="Nuclei",
                description=(info.get("description") or "").strip(),
                remediation=(info.get("remediation") or "").strip(),
                cwe=unique_cwes(cls.get("cwe-id") or []),
                # A template with several matchers reports which one fired; each is its own finding.
                rule_id=":".join(str(x) for x in (result.get("template-id"), result.get("matcher-name")) if x)
                or None,
                url=where,
                http_method=_method(result),
                cve_id=cves[0] if cves else None,
                references=[{"url": u} for u in refs if isinstance(u, str)][:10],
            )
        )
    return ParsedReport("nuclei", "dast", "Nuclei", None, findings)
