"""KICS JSON (`kics scan -p . --report-formats json`): failed infrastructure-as-code queries.

Each query lists the files it failed in. Every file entry becomes a finding on its resource.
"""

from typing import Any

from app.parsers.base import (
    NormalizedFinding,
    ParsedReport,
    ParseError,
    normalize_cwe,
    normalize_severity,
    to_int,
    truncate,
)


def parse(data: Any) -> ParsedReport:
    queries = data.get("queries") if isinstance(data, dict) else None
    if not isinstance(queries, list):
        raise ParseError("KICS report has no 'queries' array")
    findings: list[NormalizedFinding] = []
    for query in queries:
        if not isinstance(query, dict):
            continue
        url = query.get("query_url")
        cwe = normalize_cwe(query.get("cwe"))
        for f in query.get("files") or []:
            if not isinstance(f, dict):
                continue
            expected, actual = f.get("expected_value"), f.get("actual_value")
            detail = "\n".join(
                x
                for x in (
                    query.get("description"),
                    f"Expected: {expected}" if expected else None,
                    f"Actual: {actual}" if actual else None,
                )
                if x
            )
            findings.append(
                NormalizedFinding(
                    type="iac",
                    title=truncate(query.get("query_name") or "Failed query", 500) or "Failed query",
                    severity=normalize_severity(query.get("severity")),
                    tool_name="KICS",
                    description=detail,
                    cwe=[cwe] if cwe else [],
                    rule_id=query.get("query_id"),
                    file_path=f.get("file_name"),
                    line_start=to_int(f.get("line")),
                    resource=f.get("resource_name") or f.get("search_key"),
                    references=[{"url": url}] if isinstance(url, str) and url else [],
                )
            )
    return ParsedReport("kics", "iac", "KICS", data.get("kics_version"), findings)
